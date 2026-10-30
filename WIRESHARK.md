# Real-browser capture with Wireshark: procedure

Goal: capture real Chrome, Edge and Firefox ClientHellos on a real network, then measure the real TCP segment sizes, where the hostname lands, and whether per-packet and checkpoint-resume parsing recover it.

Time: about 30 minutes of capture per browser (20 sites x 10 visits), plus 15 minutes of setup.

## 0. Setup (once)
1. Install Wireshark from wireshark.org. On Windows, accept the bundled Npcap install.
2. Install Python 3.10 or newer. No extra packages are needed.
3. Unzip the kit into one folder. The scripts used here: `visit_sites.py`, `sites.txt`, `pcap_analyze.py`, `sni_resume.py`.
4. Use your own laptop on a network you control: home Wi-Fi or your phone's hotspot. Close other apps, because Wireshark records all traffic from your machine.

## 1. Choose sites
Edit `sites.txt` if you want. Keep a mix of short and long hostnames. Twenty sites is enough.

## 2. Make sure you capture real segment sizes
Segmentation offload lets the operating system hand the network card one big chunk that the card splits later. Wireshark on the same laptop then shows packets larger than the MSS, which are not what went on the wire. `pcap_analyze.py` prints a WARNING when this happens.

Run one short test capture (steps 3 to 5 with one site and 1 repeat) and check for the warning. If it appears, turn offload off and capture again:
- Windows (PowerShell as Administrator): `Disable-NetAdapterLso -Name "Wi-Fi"`. Afterwards: `Enable-NetAdapterLso -Name "Wi-Fi"`. Use your adapter's name from `Get-NetAdapter`.
- Linux: `sudo ethtool -K <interface> tso off gso off gro off`. Afterwards set them back to `on`.
- macOS: `sudo sysctl -w net.inet.tcp.tso=0`. Afterwards set it back to `1`.

## 3. Start Wireshark
1. Open Wireshark and select your active interface (Wi-Fi, or Ethernet).
2. In the capture filter box type `tcp port 443` and press Enter. Capture starts.

## 4. Drive the browser
In a terminal in the kit folder:
```
python visit_sites.py chrome 10 6
```
- Each visit opens a new, empty browser profile, so no saved sessions shorten the handshake.
- QUIC (HTTP/3) is switched off, so the handshake goes over TCP where we can see it.
- Do not touch the browser windows while it runs.
- If your browser is installed somewhere else, add `--exe "full path to the browser"`.

## 5. Save the capture
When the script prints "done", stop Wireshark (red square) and use File > Save As in pcapng format. Name it `<browser>_<network>_<run>.pcapng`, for example `chrome_homewifi_1.pcapng`. The part before the first underscore becomes the label in the results.

## 6. Repeat for each browser
```
python visit_sites.py edge 10 6
python visit_sites.py firefox 10 6
```
Start a new Wireshark capture for each and save it as `edge_...` and `firefox_...`. If you have time, repeat Chrome on a second network (for example your phone hotspot), because the MSS can differ between networks.

## 7. Analyse
```
python pcap_analyze.py chrome_homewifi_1.pcapng edge_homewifi_1.pcapng firefox_homewifi_1.pcapng
```
It prints a summary per browser and writes every handshake to `real_results.csv`:
- whether X25519MLKEM768 was offered,
- ClientHello size, MSS, and real segment sizes,
- where the hostname fell (segment 1, split, later segment),
- per-packet result and checkpoint-resume result.

## 7b. Reading the output
For each browser the analyser prints two blocks, each twice: once for all connections in the capture, once for GREASE-carrying ClientHellos only.
- GREASE values are random placeholder codes that Chrome and Edge add to every ClientHello. Wireshark records every app on the machine, so on a Chrome or Edge capture, use the GREASE subset for browser claims.
- A) AS CAPTURED uses the segments Wireshark saw. If it says "unreliable (offload)", do not report its segment results.
- B) REBUILT AT WIRE SEGMENT SIZE cuts the real ClientHello bytes into full segments of the size the sender's TCP sends: the MSS from the handshake, minus 12 bytes when both sides use TCP timestamps. On an offload-free test capture of 100 Chromium handshakes, B matched A exactly (48/100 hostnames outside segment 1 in both). Report B, and say in the paper that segment boundaries were rebuilt from the negotiated MSS.

## 8. Check one handshake by hand in Wireshark (for the report)
1. Display filter: `tls.handshake.type == 1`.
2. Click a Client Hello. In the details pane, open Transport Layer Security. The line "[2 Reassembled TCP Segments ...]" lists the segment sizes.
3. Open Extension: key_share and check the group. Newer Wireshark shows X25519MLKEM768; older versions may show the code 4588 (0x11ec).
4. Open Extension: server_name to see the hostname.
A screenshot of this is good evidence for the paper.

## Things to note in the write-up
- Segment payload is often 1,448 bytes, not 1,460, when TCP timestamps are used (12 bytes per packet). Our loopback test with real kernel segmentation showed 1448+284 to 1448+380.
- Chrome sends a dummy ("GREASE") encrypted-client-hello extension, so "ECH present" does not mean the hostname is hidden. If the hostname shown is a provider's public name (for example a Cloudflare name) rather than the site you visited, real ECH was used and the true hostname is encrypted.
- Browsers also open background connections (updates, safe browsing). These are real ClientHellos and can stay in the data; the hostname column shows what they are.

## Privacy
The capture holds your own browsing metadata (IP addresses, hostnames). Do not share the .pcapng files publicly; the CSV is enough to share with your team or supervisor.
