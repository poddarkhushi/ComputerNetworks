"""
Reference model (software, not switch code) of checkpoint-and-resume SNI extraction.

The parser reads a TLS ClientHello one TCP segment at a time, the way a switch sees packets.
At the end of each segment it stores a small fixed-layout record per flow (what a switch
would keep in a register slot) and, when the next segment arrives, resumes from that record.
No payload bytes are buffered except the part of the hostname already seen.

Compared against three baselines on the same captures:
  single_packet : parse each segment on its own (per-packet DPI as in P4Wall / DeeP4R)
  fixed_offset  : read the hostname at the offset most often seen ("predictable client" assumption)
  offset_only   : checkpoint that stores only the skip offset, no partial-hostname bytes
"""
import glob, random, collections, csv, sys

# ---------- ground truth: full parse of the reassembled ClientHello ----------
def truth(b):
    p = 5 + 4 + 2 + 32
    p += 1 + b[p]
    p += 2 + int.from_bytes(b[p:p+2], "big")
    p += 1 + b[p]
    end = p + 2 + int.from_bytes(b[p:p+2], "big"); p += 2
    while p < end:
        t = int.from_bytes(b[p:p+2], "big"); l = int.from_bytes(b[p+2:p+4], "big")
        if t == 0:
            nl = int.from_bytes(b[p+7:p+9], "big")
            return b[p+9:p+9+nl].decode(), p + 9        # hostname, offset of first hostname byte
        p += 4 + l
    return None, None

# ---------- the resumable parser ----------
# Phases: each one either READs n bytes into a small accumulator or SKIPs n bytes.
REC, HS, VR, SIDL, SID, CSL, CS, CML, CM, EXL, EXH, SNIH, NAME, SKIPX, DONE, FAIL = range(16)

class Flow:
    """Per-flow checkpoint. Every field is fixed width except name_buf (partial hostname)."""
    __slots__ = ("phase", "need", "acc", "ext_left", "name_len", "name_buf", "next_seq")
    def __init__(self):
        self.phase, self.need, self.acc = REC, 5, b""
        self.ext_left = 0; self.name_len = 0; self.name_buf = b""; self.next_seq = 0
    def state_bytes(self):
        # phase 1 B + need 2 B + acc (<=5 B, length-prefixed 1 B) + ext_left 2 B + name_len 2 B
        # + next expected TCP seq 4 B + partial hostname bytes
        return 1 + 2 + 1 + len(self.acc) + 2 + 2 + 4 + len(self.name_buf)

def feed(f, seg, seq):
    """Process one TCP segment. Returns 'found', 'more', 'fallback' or 'fail'."""
    if seq != f.next_seq:                 # out-of-order or retransmission: hand to slow path
        f.phase = FAIL; return "fallback"
    f.next_seq = seq + len(seg)
    i = 0
    while i < len(seg) and f.phase not in (DONE, FAIL):
        reading = f.phase in (REC, HS, VR, SIDL, CSL, CML, EXL, EXH, SNIH)
        take = min(f.need, len(seg) - i)
        if reading: f.acc += seg[i:i+take]
        elif f.phase == NAME: f.name_buf += seg[i:i+take]   # only bytes ever kept across packets
        i += take; f.need -= take
        if f.need: break                  # segment ended mid-field: checkpoint holds the rest
        a = f.acc; f.acc = b""
        if   f.phase == REC:  f.phase, f.need = (HS, 4) if a[0] == 22 else (FAIL, 0)
        elif f.phase == HS:   f.phase, f.need = (VR, 34) if a[0] == 1 else (FAIL, 0)
        elif f.phase == VR:   f.phase, f.need = SIDL, 1
        elif f.phase == SIDL: f.phase, f.need = (SID, a[0]) if a[0] else (CSL, 2)
        elif f.phase == SID:  f.phase, f.need = CSL, 2
        elif f.phase == CSL:  f.phase, f.need = CS, int.from_bytes(a, "big")
        elif f.phase == CS:   f.phase, f.need = CML, 1
        elif f.phase == CML:  f.phase, f.need = CM, a[0]
        elif f.phase == CM:   f.phase, f.need = EXL, 2
        elif f.phase == EXL:  f.ext_left = int.from_bytes(a, "big"); f.phase, f.need = EXH, 4
        elif f.phase == EXH:
            t, l = int.from_bytes(a[:2], "big"), int.from_bytes(a[2:], "big")
            f.ext_left -= 4 + l
            if t == 0: f.phase, f.need = SNIH, 5               # list len 2, name type 1, name len 2
            else:      f.phase, f.need = SKIPX, l
        elif f.phase == SNIH:
            f.name_len = int.from_bytes(a[3:5], "big"); f.phase, f.need = NAME, f.name_len
        elif f.phase == NAME: f.phase = DONE
        elif f.phase == SKIPX:
            if f.ext_left <= 0: f.phase = FAIL                 # no SNI in this ClientHello
            else: f.phase, f.need = EXH, 4
    if f.phase == DONE: return "found"
    if f.phase == FAIL: return "fail"
    return "more"

def segments(b, mss):
    return [(b[i:i+mss], i) for i in range(0, len(b), mss)]

def run_resume(b, mss, order=None):
    """Returns (hostname or None, outcome, max checkpoint bytes, bytes still to skip at each boundary)."""
    f = Flow(); segs = segments(b, mss); max_state = 0; carried = []
    if order: segs = [segs[k] for k in order]
    for seg, seq in segs:
        r = feed(f, seg, seq)
        if r == "more":
            max_state = max(max_state, f.state_bytes())
            if f.phase in (SKIPX, CS, SID, CM): carried.append(f.need)
            continue
        if r == "found":
            name = f.name_buf.decode(errors="replace")
            return (name if len(f.name_buf) == f.name_len else None), r, max_state, carried
        return None, r, max_state, carried
    return None, "incomplete", max_state, carried

# ---------- baselines ----------
def single_packet(b, mss):
    """Per-packet parsing: only bytes of the first segment are visible to one parse."""
    name, off = truth(b)
    return name if off + len(name) <= mss else None

def fixed_offset(b, mss, off_learned, len_learned):
    name, off = truth(b)
    if off_learned + len_learned > mss: return None
    got = b[off_learned:off_learned+len_learned]
    return got.decode(errors="replace") if got.decode(errors="replace") == name else None

def offset_only(b, mss):
    """Checkpoint that keeps the parse position but drops hostname bytes already seen."""
    name, off = truth(b)
    straddles = off < mss < off + len(name)
    if straddles: return None
    return run_resume(b, mss)[0]

# ---------- experiment ----------
if __name__ == "__main__":
    files = sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else "caps/chromium_2000/*.bin"))
    data = [open(x, "rb").read() for x in files]
    n = len(data)
    gt = [truth(b) for b in data]
    assert all(g[0] for g in gt), "every capture should carry an SNI"
    # predictable-client baseline learns the modal hostname offset from the first 100 handshakes
    off_mode = collections.Counter(g[1] for g in gt[:100]).most_common(1)[0][0]
    len_mode = len(gt[0][0])
    print(f"captures: {n} | hostname: {gt[0][0]} | fixed-offset baseline uses offset {off_mode}\n")
    rows = []
    print(f"{'MSS':>5} {'segs':>5} | {'single-packet':>13} {'fixed-offset':>12} {'offset-only':>11} {'checkpoint':>10} | max state B | max skip carried")
    for mss in (1460, 1448, 1400, 1360, 1280, 536):
        ok = collections.Counter(); states = []; carried = []
        for b, (name, off) in zip(data, gt):
            ok["single"] += single_packet(b, mss) == name
            ok["fixed"]  += fixed_offset(b, mss, off_mode, len_mode) == name
            ok["offonly"] += offset_only(b, mss) == name
            got, res, st, car = run_resume(b, mss)
            ok["resume"] += got == name; states.append(st); carried += car
        segs = max(len(segments(b, mss)) for b in data)
        pct = lambda k: f"{100*ok[k]/n:.1f}%"
        print(f"{mss:>5} {segs:>5} | {pct('single'):>13} {pct('fixed'):>12} {pct('offonly'):>11} {pct('resume'):>10} | {max(states):>11} | {max(carried) if carried else 0}")
        rows.append([mss, segs, n, ok["single"], ok["fixed"], ok["offonly"], ok["resume"], max(states), max(carried) if carried else 0])
    # stress: random split points, every capture, 20 cut sizes each (covers cuts inside every field)
    random.seed(7); trials = bad = 0; worst = 0
    for b, (name, _) in zip(data, gt):
        for _ in range(20):
            mss = random.randint(40, len(b) - 1)
            got, res, st, _ = run_resume(b, mss); trials += 1; bad += got != name; worst = max(worst, st)
    print(f"\nrandom-cut stress test: {trials} runs, {trials-bad} correct, {bad} wrong, max state {worst} B")
    # out-of-order: segment 2 before segment 1 must go to the slow path, never return a wrong name
    wrong = sum(1 for b, (name, _) in zip(data, gt)
                if (r := run_resume(b, 1460, order=[1, 0]))[0] not in (None, name))
    flagged = sum(1 for b in data if run_resume(b, 1460, order=[1, 0])[1] == "fallback")
    print(f"out-of-order test (seg 2 first, MSS 1460): {flagged}/{n} sent to slow path, {wrong} wrong hostnames")
    with open("resume_results.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mss", "max_segments", "n", "single_packet_ok", "fixed_offset_ok", "offset_only_ok", "checkpoint_ok", "max_state_bytes", "max_skip_carried_bytes"])
        w.writerows(rows)
        w.writerow([]); w.writerow(["random_cut_runs", trials, "correct", trials - bad, "max_state_bytes", worst])
        w.writerow(["out_of_order_runs", n, "sent_to_slow_path", flagged, "wrong", wrong])
