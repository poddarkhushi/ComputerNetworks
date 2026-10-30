import socket, ssl, sys
port, n, host = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
for _ in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port)); s.settimeout(1)
        ctx.wrap_socket(s, server_hostname=host)
    except Exception: pass
