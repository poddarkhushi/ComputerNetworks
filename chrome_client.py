# Opens a fresh headless Chromium per run and points it at our capture server under a real-looking hostname.
import sys, asyncio
from playwright.async_api import async_playwright
port, n, host = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
async def main():
    async with async_playwright() as p:
        for i in range(n):
            b = await p.chromium.launch(args=[f"--host-resolver-rules=MAP {host} 127.0.0.1", "--ignore-certificate-errors","--no-proxy-server"])
            pg = await b.new_page()
            try: await pg.goto(f"https://{host}:{port}/", timeout=2500)
            except Exception as e: print(type(e).__name__, str(e)[:120])
            await b.close()
asyncio.run(main())
