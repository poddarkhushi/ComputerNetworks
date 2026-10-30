# Review demo: run guide

## What you need on the demo laptop
- Python 3.10 or newer
- Playwright with Chromium: `pip install playwright` then `python -m playwright install chromium`
- No internet needed once installed; everything runs on 127.0.0.1

The Chromium that Playwright installs on your laptop may be a newer version than the 141 used for our results, so live numbers can differ slightly. Say so if asked.

## Before the review (5 minutes)
1. Unzip, open a terminal in the folder.
2. Dry-run: `python3 demo.py 20 1460`. It should end with "checkpoint-resume 20/20".
3. Dry-run the backup: `python3 sni_resume.py`. It takes about 3 seconds and prints the results table from the saved 2,000 captures.

## During the review
| Step | Command | What to point at |
|---|---|---|
| 1. Live capture and comparison | `python3 demo.py 20 1460` | Rows marked "segment 2" or "split": per-packet says MISS, checkpoint says OK |
| 2. The stored record | (part [4] of the same output) | Record is about a dozen bytes; segment 2 completes the hostname |
| 3. Full results | `python3 sni_resume.py` | The MSS table; random-cut and out-of-order lines |
| 4. Measurement only (optional) | `python3 analyze_scale.py` | 2,000/2,000 distinct orders; 45.0% not in segment 1 |

If Chromium fails to launch, skip step 1 and use step 3: it uses the saved captures in `caps/chromium_2000/`.

## Files
| File | Purpose |
|---|---|
| `capture_server.py` | Local TCP listener; saves each connection's first TLS record (the ClientHello) |
| `browser_client.py` | Opens N fresh Chromium contexts against the listener |
| `client.go`, `client.js`, `client_py.py`, `chrome_client.py` | Pilot clients (Go, Node.js, Python, Chromium) |
| `parse.py` | Pilot analysis: sizes, extension order, SNI position per client |
| `analyze_scale.py` | Analysis of the 2,000-handshake run, with 95% Wilson intervals |
| `sni_resume.py` | Reference model of checkpoint-resume parsing plus the three baselines, stress and out-of-order tests |
| `demo.py` | The live demo |
| `results.csv`, `scale_summary.csv`, `resume_results.csv` | Saved outputs |
| `caps/` | Raw captured ClientHellos |

## Honest limits to state if asked
- Software reference model only; no switch code yet (P4 on BMv2 is next).
- Loopback captures, headless Chromium, one 22-character hostname, assumed MSS values.
- Whether a Tofino parser can resume from saved per-flow state is not yet confirmed.
