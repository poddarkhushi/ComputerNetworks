"""
Opens each site in sites.txt in a real browser, with a brand-new profile every time, while Wireshark records.
A new profile means no saved session tickets, so every visit sends a full ClientHello.
QUIC (HTTP/3) is switched off so the ClientHello travels over TCP, where Wireshark and our parser see it.

usage: python visit_sites.py <chrome|edge|firefox> [repeats] [seconds_per_visit] [--exe PATH]
example: python visit_sites.py chrome 10 6
"""
import sys, os, time, shutil, subprocess, tempfile, platform

DEFAULT_EXE = {
    "Windows": {"chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "edge": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                "firefox": r"C:\Program Files\Mozilla Firefox\firefox.exe"},
    "Darwin": {"chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
               "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
               "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox"},
    "Linux": {"chrome": "google-chrome", "edge": "microsoft-edge", "firefox": "firefox"},
}
FIREFOX_PREFS = """user_pref("network.http.http3.enable", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
"""

def main():
    args = [a for a in sys.argv[1:]]
    exe = None
    if "--exe" in args:
        i = args.index("--exe"); exe = args[i + 1]; del args[i:i + 2]
    if not args or args[0] not in ("chrome", "edge", "firefox"): print(__doc__); return
    browser = args[0]
    repeats = int(args[1]) if len(args) > 1 else 10
    wait = float(args[2]) if len(args) > 2 else 6
    exe = exe or DEFAULT_EXE.get(platform.system(), {}).get(browser)
    here = os.path.dirname(os.path.abspath(__file__))
    sites = [l.strip() for l in open(os.path.join(here, "sites.txt")) if l.strip() and not l.startswith("#")]
    print(f"{browser}: {len(sites)} sites x {repeats} repeats, {wait}s each -> about {len(sites)*repeats*(wait+2)/60:.0f} min")
    for r in range(repeats):
        for url in sites:
            prof = tempfile.mkdtemp(prefix=f"pq_{browser}_")
            if browser == "firefox":
                open(os.path.join(prof, "user.js"), "w").write(FIREFOX_PREFS)
                cmd = [exe, "-no-remote", "-profile", prof, url]
            else:
                cmd = [exe, f"--user-data-dir={prof}", "--disable-quic", "--no-first-run",
                       "--no-default-browser-check", "--new-window", url]
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(wait)
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill()
            time.sleep(1.5)
            shutil.rmtree(prof, ignore_errors=True)
            print(f"  round {r+1}/{repeats}  {url}", flush=True)
    print("done - stop the Wireshark capture now")

if __name__ == "__main__":
    main()
