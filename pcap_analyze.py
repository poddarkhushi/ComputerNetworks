"""
Analyse Wireshark captures of real browser TLS handshakes.

For every TCP connection to the server port (443 by default) it:
  - rebuilds the client's first TLS record (the ClientHello) from the real TCP segments,
  - records the real segment sizes, the MSS from the SYN / SYN-ACK, key-share groups, ECH,
  - finds where the SNI hostname sits relative to the real segment boundaries,
  - runs per-packet parsing and the checkpoint-resume model (sni_resume.py) on the real segments.

No extra packages: reads .pcap and .pcapng directly. Keep sni_resume.py in the same folder.
usage: python pcap_analyze.py capture1.pcapng [capture2.pcapng ...] [--port 443] [--out real_results.csv]
The browser label is taken from the file name before the first "_" (chrome_run1.pcapng -> chrome).
"""
import sys, struct, csv, os, collections
from sni_resume import truth, Flow, feed, DONE

GROUPS = {0x11ec: "X25519MLKEM768", 0x001d: "X25519", 0x0017: "P-256", 0x0018: "P-384",
          0x0201: "MLKEM768", 0x11eb: "SecP256r1MLKEM768", 0x6399: "X25519Kyber768Draft00"}

# ---------------- pcap / pcapng reading ----------------
def packets(path):
    """Yields (linktype, frame bytes) for every packet in a .pcap or .pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
        p = 24
        while p + 16 <= len(data):
            incl = struct.unpack(e + "I", data[p+8:p+12])[0]
            yield link, data[p+16:p+16+incl]
            p += 16 + incl
    elif magic == b"\x0a\x0d\x0d\x0a":
        p, e, links = 0, "<", []
        while p + 12 <= len(data):
            btype = struct.unpack(e + "I", data[p:p+4])[0]
            if btype == 0x0A0D0D0A:                      # section header: byte order
                e = "<" if data[p+8:p+12] == b"\x4d\x3c\x2b\x1a" else ">"
                links = []
            blen = struct.unpack(e + "I", data[p+4:p+8])[0]
            if blen < 12: break
            body = data[p+8:p+blen-4]
            if btype == 1:                               # interface description
                links.append(struct.unpack(e + "H", body[:2])[0])
            elif btype == 6:                             # enhanced packet
                iface, _, _, cap, _ = struct.unpack(e + "IIIII", body[:20])
                yield (links[iface] if iface < len(links) else 1), body[20:20+cap]
            elif btype == 3:                             # simple packet
                yield (links[0] if links else 1), body[4:]
            p += blen
    else:
        raise ValueError(f"{path}: not a pcap or pcapng file")

def ip_payload(link, fr):
    """Strips the link layer. Returns (version, ip packet) or None."""
    if link == 1:                                        # Ethernet
        t, off = struct.unpack(">H", fr[12:14])[0], 14
        while t in (0x8100, 0x88A8):                     # VLAN tags
            t, off = struct.unpack(">H", fr[off+2:off+4])[0], off + 4
        return {0x0800: (4, fr[off:]), 0x86DD: (6, fr[off:])}.get(t)
    if link == 113:                                      # Linux cooked (SLL)
        t = struct.unpack(">H", fr[14:16])[0]
        return {0x0800: (4, fr[16:]), 0x86DD: (6, fr[16:])}.get(t)
    if link == 276:                                      # Linux cooked v2
        t = struct.unpack(">H", fr[0:2])[0]
        return {0x0800: (4, fr[20:]), 0x86DD: (6, fr[20:])}.get(t)
    if link in (0, 108):                                 # BSD loopback / null
        fam = struct.unpack("<I", fr[:4])[0] if link == 0 else struct.unpack(">I", fr[:4])[0]
        return (4, fr[4:]) if fam == 2 else (6, fr[4:]) if fam in (24, 28, 30) else None
    if link in (101, 228, 229, 12, 14):                  # raw IP
        return (fr[0] >> 4, fr) if fr and fr[0] >> 4 in (4, 6) else None
    return None

def tcp_segment(ver, ip):
    """Returns (src, dst, sport, dport, seq, flags, mss, timestamps_option, payload) or None."""
    if ver == 4:
        if len(ip) < 20 or ip[9] != 6: return None
        if struct.unpack(">H", ip[6:8])[0] & 0x3FFF: return None   # IP fragment: skip
        ihl, tot = (ip[0] & 15) * 4, struct.unpack(">H", ip[2:4])[0]
        src, dst, t = ip[12:16], ip[16:20], ip[ihl:tot] if tot else ip[ihl:]
    else:
        if len(ip) < 40 or ip[6] != 6: return None                  # extension headers not handled
        plen = struct.unpack(">H", ip[4:6])[0]
        src, dst, t = ip[8:24], ip[24:40], ip[40:40+plen]
    if len(t) < 20: return None
    sport, dport, seq = struct.unpack(">HHI", t[:8])
    doff, flags = (t[12] >> 4) * 4, t[13]
    mss, ts, o = None, False, 20
    while o < doff:                                      # TCP options: look for MSS (kind 2)
        k = t[o]
        if k == 0: break
        if k == 1: o += 1; continue
        if o + 1 >= doff: break
        ln = t[o+1]
        if k == 2 and ln == 4: mss = struct.unpack(">H", t[o+2:o+4])[0]
        if k == 8: ts = True
        if ln < 2: break
        o += ln
    return src, dst, sport, dport, seq, flags, mss, ts, t[doff:]

# ---------------- per-connection reconstruction ----------------
def client_hellos(path, port):
    conns = {}
    for link, fr in packets(path):
        ipp = ip_payload(link, fr)
        if not ipp: continue
        seg = tcp_segment(*ipp)
        if not seg: continue
        src, dst, sp, dp, seq, flags, mss, ts, pay = seg
        if dp == port:                                   # client -> server
            c = conns.setdefault((src, sp, dst, dp), {"isn": None, "cmss": None, "smss": None, "cts": False, "sts": False, "segs": []})
            if flags & 0x02:                             # SYN
                c["isn"], c["cmss"], c["cts"], c["segs"] = seq, mss, ts, []
            elif pay and c["isn"] is not None:
                c["segs"].append(((seq - c["isn"] - 1) & 0xFFFFFFFF, pay))
        elif sp == port and flags & 0x12 == 0x12:        # SYN-ACK from server
            c = conns.get((dst, dp, src, sp))
            if c is not None: c["smss"], c["sts"] = mss, ts
    for key, c in conns.items():
        segs = c["segs"]
        if not segs: continue
        # rebuild the stream bytes by offset, then cut at the end of the first TLS record
        buf = bytearray(); have = set()
        for off, pay in segs:
            if off > 1_000_000: continue
            if len(buf) < off + len(pay): buf.extend(b"\0" * (off + len(pay) - len(buf)))
            buf[off:off+len(pay)] = pay; have.update(range(off, off + len(pay)))
        if len(buf) < 5 or buf[0] != 0x16 or 0 not in have: continue
        rec_end = 5 + struct.unpack(">H", bytes(buf[3:5]))[0]
        if not all(i in have for i in range(min(rec_end, len(buf)))) or len(buf) < rec_end: continue
        ch = bytes(buf[:rec_end])
        # segments that carry ClientHello bytes, in arrival order, trimmed at the record end
        used = [(off, pay[:max(0, rec_end - off)]) for off, pay in segs if off < rec_end]
        yield key, c, ch, used

def groups_and_ech(ch):
    p = 5 + 4 + 2 + 32; p += 1 + ch[p]; p += 2 + int.from_bytes(ch[p:p+2], "big"); p += 1 + ch[p]
    end = p + 2 + int.from_bytes(ch[p:p+2], "big"); p += 2
    ks, ech, grease = [], False, False
    is_grease = lambda v: (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)
    while p < end:
        t, l = int.from_bytes(ch[p:p+2], "big"), int.from_bytes(ch[p+2:p+4], "big")
        if is_grease(t): grease = True
        if t == 0xfe0d: ech = True
        if t == 51:
            q = p + 6
            while q < p + 4 + l:
                g, kl = int.from_bytes(ch[q:q+2], "big"), int.from_bytes(ch[q+2:q+4], "big")
                if is_grease(g): grease = True
                else: ks.append(GROUPS.get(g, hex(g)))
                q += 4 + kl
        p += 4 + l
    return ks, ech, grease

def evaluate(ch, used):
    name, off = truth(ch)
    if name is None: return None
    first = next((pay for o, pay in used if o == 0), b"")
    end = off + len(name)
    where = "segment 1" if end <= len(first) else ("split" if off < len(first) else "later segment")
    per_packet = end <= len(first)
    f = Flow(); outcome = "incomplete"; rec_max = 0
    for o, pay in used:                                  # real arrival order, real sequence offsets
        r = feed(f, pay, o)
        if r == "more": rec_max = max(rec_max, f.state_bytes()); continue
        outcome = r; break
    got = f.name_buf.decode(errors="replace") if f.phase == DONE else None
    return dict(sni=name, sni_len=len(name), sni_start=off, sni_end=end, where=where, per_packet_ok=per_packet,
                checkpoint=("ok" if got == name else outcome), record_bytes=rec_max)

def rebuilt(ch, size):
    """Cuts the ClientHello into full-size segments of `size` bytes, the way the sender's TCP
    emits them on the wire, and evaluates again. Used when offload hides the real cuts."""
    r = evaluate(ch, [(i, ch[i:i+size]) for i in range(0, len(ch), size)])
    return {"rebuilt_" + k: r[k] for k in ("where", "per_packet_ok", "checkpoint", "record_bytes")}

# ---------------- main ----------------
def main():
    args, port, out = [], 443, "real_results.csv"
    it = iter(sys.argv[1:])
    for a in it:
        if a == "--port": port = int(next(it))
        elif a == "--out": out = next(it)
        else: args.append(a)
    if not args: print(__doc__); return
    rows = []
    for path in args:
        label = os.path.basename(path).split("_")[0].split(".")[0].lower()
        for key, c, ch, used in client_hellos(path, port):
            ev = evaluate(ch, used)
            if not ev: continue
            ks, ech, grease = groups_and_ech(ch)
            sizes = [len(p) for _, p in used]
            mss = min([m for m in (c["cmss"], c["smss"]) if m] or [0])
            wire = (mss - 12 if c["cts"] and c["sts"] else mss) if mss else 1460   # payload per full segment
            rows.append(dict(file=os.path.basename(path), browser=label, grease=grease, clienthello_bytes=len(ch),
                             segments=len(used), segment_sizes="+".join(map(str, sizes)), mss=mss,
                             offload_suspected=bool(mss and max(sizes) > mss),
                             out_of_order=[o for o, _ in used] != sorted(o for o, _ in used),
                             key_shares="+".join(ks), pq=("X25519MLKEM768" in ks), ech=ech,
                             wire_segment_bytes=wire, **ev, **rebuilt(ch, wire)))
    if not rows: print("No complete ClientHellos found. Check the port and that the capture includes the SYN."); return
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    by = collections.defaultdict(list)
    for r in rows: by[r["browser"]].append(r)
    pct = lambda k, n: f"{k}/{n} ({100*k/n:.1f}%)"
    def report(title, rs):
        n = len(rs)
        if not n: print(f"\n== {title}: none"); return
        print(f"\n== {title}: {n} ClientHellos, {len(set(r['sni'] for r in rs))} hostnames")
        print("   offered X25519MLKEM768:    ", pct(sum(r["pq"] for r in rs), n))
        print("   ECH extension present:     ", pct(sum(r["ech"] for r in rs), n),
              "(may be a dummy 'GREASE' ECH; real ECH only if the SNI is a provider's public name)")
        print("   ClientHello size (bytes):  ", min(r["clienthello_bytes"] for r in rs), "to", max(r["clienthello_bytes"] for r in rs))
        print("   hostname length (chars):   ", min(r["sni_len"] for r in rs), "to", max(r["sni_len"] for r in rs))
        print("   MSS values seen:           ", dict(collections.Counter(r["mss"] for r in rs)))
        print("   wire payload per segment:  ", dict(collections.Counter(r["wire_segment_bytes"] for r in rs)),
              "(MSS minus 12 B when both sides use TCP timestamps)")
        off = sum(r["offload_suspected"] for r in rs)
        print("   A) AS CAPTURED" + (f"  -- unreliable: {off}/{n} have a segment larger than the MSS (offload)" if off else ""))
        print("      segment-size patterns:   ", collections.Counter(r["segment_sizes"] for r in rs).most_common(3))
        print("      hostname not in seg 1:   ", pct(sum(r["where"] != "segment 1" for r in rs), n), dict(collections.Counter(r["where"] for r in rs)))
        print("      per-packet correct:      ", pct(sum(r["per_packet_ok"] for r in rs), n))
        print("      checkpoint correct:      ", pct(sum(r["checkpoint"] == "ok" for r in rs), n), dict(collections.Counter(r["checkpoint"] for r in rs)))
        print("   B) REBUILT AT WIRE SEGMENT SIZE (real ClientHello bytes, cut where the sender's TCP cuts full segments)")
        print("      needed >1 segment:       ", pct(sum(r["clienthello_bytes"] > r["wire_segment_bytes"] for r in rs), n))
        print("      hostname not in seg 1:   ", pct(sum(r["rebuilt_where"] != "segment 1" for r in rs), n), dict(collections.Counter(r["rebuilt_where"] for r in rs)))
        print("      per-packet correct:      ", pct(sum(r["rebuilt_per_packet_ok"] for r in rs), n))
        print("      checkpoint correct:      ", pct(sum(r["rebuilt_checkpoint"] == "ok" for r in rs), n), dict(collections.Counter(r["rebuilt_checkpoint"] for r in rs)))
        print("      largest record (bytes):  ", max(r["rebuilt_record_bytes"] for r in rs))
    for b, rs in sorted(by.items()):
        report(f"{b} (all connections in the capture)", rs)
        report(f"{b} (GREASE present: Chrome/Edge-style ClientHellos)", [r for r in rs if r["grease"]])
        print(f"   note: {sum(not r['grease'] for r in rs)} {b} rows carry no GREASE; on a Chrome/Edge capture these are most likely other apps on the machine")
    print(f"\nPer-handshake rows written to {out}")

if __name__ == "__main__":
    main()
