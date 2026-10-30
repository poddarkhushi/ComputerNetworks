# Opens N fresh browser contexts (new TLS connection each) against the capture server.
# usage: browser_client.py <chromium|firefox> <port> <n> <host> [fresh]
#   fresh = relaunch the whole browser every run (slower, matches the pilot method)
import sys, asyncio
from playwright.async_api import async_playwright
kind, port, n, host = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
fresh = len(sys.argv) > 5 and sys.argv[5] == "fresh"

async def launch(p):
    if kind == "chromium":
        return await p.chromium.launch(args=[f"--host-resolver-rules=MAP {host} 127.0.0.1",
                                             "--ignore-certificate-errors", "--no-proxy-server"])
    return await p.firefox.launch(firefox_user_prefs={
        "network.dns.localDomains": host, "network.proxy.type": 0})

async def main():
    async with async_playwright() as p:
        b = None if fresh else await launch(p)
        for i in range(n):
            if fresh: b = await launch(p)
            ctx = await b.new_context(ignore_https_errors=True)
            pg = await ctx.new_page()
            try: await pg.goto(f"https://{host}:{port}/", timeout=2500)
            except Exception: pass
            await ctx.close()
            if fresh: await b.close()
            if i % 100 == 0: print(kind, i, flush=True)
        if not fresh: await b.close()
asyncio.run(main())
