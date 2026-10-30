"""
Live demo for the review (about 1 minute).
  1. Captures N fresh ClientHellos from headless Chromium (post-quantum key exchange on by default).
  2. Shows where the hostname lands relative to the TCP segment boundary.
  3. Runs per-packet parsing and the checkpoint-resume parser side by side.
  4. Prints the checkpoint record for one handshake whose hostname is in segment 2.
usage: python3 demo.py [N] [MSS]      (defaults: 20 handshakes, MSS 1460)
"""
import os, sys, subprocess, time, glob, shutil
from sni_resume import truth, run_resume, single_packet, Flow, feed, segments, NAME, SKIPX

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
MSS = int(sys.argv[2]) if len(sys.argv) > 2 else 1460
HOST, PORT, OUT = "www.example-bank.co.in", 8470, "caps/live_demo"
env = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy")}

shutil.rmtree(OUT, ignore_errors=True)
srv = subprocess.Popen([sys.executable, "capture_server.py", str(PORT), OUT, str(N)], env=env)
time.sleep(1)
print(f"[1] capturing {N} Chromium ClientHellos for {HOST} ...")
subprocess.run([sys.executable, "browser_client.py", "chromium", str(PORT), str(N), HOST],
               env=env, stdout=subprocess.DEVNULL)
srv.wait(timeout=30)
files = sorted(glob.glob(OUT + "/*.bin"))
print(f"    got {len(files)} ClientHellos\n")

print(f"[2] where the hostname sits (MSS {MSS})")
print(f"    {'#':>3} {'bytes':>6} {'segs':>4} {'hostname at':>12}  where")
sp_ok = cr_ok = 0; example = None
for i, x in enumerate(files):
    b = open(x, "rb").read(); name, off = truth(b); end = off + len(name)
    where = "segment 1" if end <= MSS else ("split across 1|2" if off < MSS else "segment 2")
    if where != "segment 1" and example is None: example = b
    sp = single_packet(b, MSS) == name; cr = run_resume(b, MSS)[0] == name
    sp_ok += sp; cr_ok += cr
    print(f"    {i:>3} {len(b):>6} {len(segments(b, MSS)):>4} {off:>5}-{end:<6}  {where:<17} per-packet {'OK  ' if sp else 'MISS'}  checkpoint {'OK' if cr else 'MISS'}")

print(f"\n[3] hostname recovered: per-packet {sp_ok}/{len(files)}, checkpoint-resume {cr_ok}/{len(files)}")

if example:
    print("\n[4] checkpoint record stored after segment 1 of one handshake whose hostname is not in segment 1:")
    f = Flow(); s1, s2 = segments(example, MSS)[:2]
    feed(f, s1[0], s1[1])
    phase = {SKIPX: "skipping an extension", NAME: "reading hostname"}.get(f.phase, f"phase {f.phase}")
    print(f"    state = {phase}; bytes still to skip/read = {f.need}; extension bytes left = {f.ext_left};")
    print(f"    partial hostname = {f.name_buf!r}; next TCP seq = {f.next_seq}; record size = {f.state_bytes()} B")
    r = feed(f, s2[0], s2[1])
    print(f"    segment 2 arrives -> {r}: {f.name_buf.decode()!r}")
