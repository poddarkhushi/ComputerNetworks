# PQ ClientHello measurement (pilot)
Captures the first TLS record each client sends to a local TCP listener and records where the SNI extension sits.
Run: python3 capture_server.py <port> caps/<name> <n> & then a client (client.go, client.js, client_py.py, chrome_client.py).
Analyse: python3 parse.py   (results.csv holds every handshake)
Limits: loopback only, headless Chromium, n=20-30 per client. "Segment" = byte offset vs an assumed MSS; real paths may differ.

## Scale run (25 Oct 2026): 2,000 Chromium handshakes
Run: python3 capture_server.py 8464 caps/chromium_2000 2000 & then python3 browser_client.py chromium 8464 2000 www.example-bank.co.in
Analyse: python3 analyze_scale.py  (summary in scale_summary.csv)
- Every ClientHello 1,732-1,828 B, X25519MLKEM768 key share 1,216 B, always exactly 2 segments at MSS 1280-1460.
- 2,000/2,000 distinct extension orders; 528 distinct SNI start offsets.
- MSS 1460: SNI fully in seg 1 1,099; straddles boundary 99 (5.0%); fully in seg 2 802. Not in seg 1: 45.0% (95% CI 42.9-47.2).
- MSS 1400: not in seg 1 50.4% (95% CI 48.2-52.5); straddles 23.
- When SNI is in seg 2, it starts up to 332 B into seg 2 (MSS 1460).
- The pilot's 17/30 (57%) overstated the rate; use the 2,000-run figures.
Limits: loopback, headless Chromium 141 only, one 22-char hostname, browser reused with a new context per handshake. Firefox not tested (not installed here).
