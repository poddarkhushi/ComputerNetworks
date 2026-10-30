# Accepts TCP connections on localhost, records the first bytes the client sends (the ClientHello), saves them.
import socket, sys, os
port = int(sys.argv[1]); outdir = sys.argv[2]; n = int(sys.argv[3])
os.makedirs(outdir, exist_ok=True)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(64)
for i in range(n):
    c, _ = s.accept(); c.settimeout(2)
    buf = b""
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
            if len(buf) >= 5:
                need = 5 + int.from_bytes(buf[3:5], "big")
                if len(buf) >= need: break
    except socket.timeout:
        pass
    open(f"{outdir}/ch_{i:03d}.bin", "wb").write(buf); c.close()
