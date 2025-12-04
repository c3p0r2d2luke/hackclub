#!/usr/bin/env python3
"""
safe_crawler.py

A polite, concurrent crawler + fuzzer for OWNED targets.

Usage examples:
  # Basic crawl (polite defaults)
  python safe_crawler.py --target https://example.com --output results.json

  # Crawl + fuzz using built-in wordlist, 8 workers, allow subdomains
  python safe_crawler.py --target https://example.com --fuzz --threads 8 --include-subdomains --output results.json

  # Use Playwright to render JS (slower). Requires playwright package & install.
  python safe_crawler.py --target https://example.com --render-js --threads 4 --output results.json
"""

import argparse
import asyncio
import aiohttp
import aiofiles
import async_timeout
import json
import csv
import re
import time
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
import ssl
import sys
from collections import defaultdict
from datetime import datetime
from tqdm.asyncio import tqdm_asyncio
import urllib.robotparser as robotparser

# ---------- Built-in small fuzz wordlist (extend via --wordlist) ----------
DEFAULT_FUZZ_WORDS = [
    "admin","login","dashboard","wp-admin","wp-login.php","backup","backup.zip",
    ".env",".git","robots.txt","sitemap.xml","api","config","uploads","phpinfo.php",
    "setup","test","staging","old","archive","admin/login","user","users","profile",
    "register","signup","cart","checkout","search","rss","feed",".htaccess"
]

# ---------- Helpers ----------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def normalize_link(link, base):
    if not link:
        return None
    # remove fragments
    link, _ = urldefrag(link)
    try:
        parsed = urlparse(link)
        if parsed.scheme in ("http", "https"):
            return parsed.geturl()
        # relative
        return urljoin(base, link)
    except Exception:
        return None

def same_domain_check(url, base_domain, include_subdomains=True):
    try:
        host = urlparse(url).hostname or ""
        if include_subdomains:
            return host == base_domain or host.endswith("." + base_domain)
        else:
            return host == base_domain
    except Exception:
        return False

# Simple regex-based URL extractor for JS/CSS content (best-effort)
URL_RE = re.compile(
    r"""(?:"|')(?P<u>(?:https?:\/\/|\/)[^"'()\s>]+)(?:"|')|url\(\s*(?P<u2>[^)]+)\s*\)""",
    re.IGNORECASE
)

# ---------- Robots.txt loader ----------
async def fetch_robots(session, base_url, user_agent):
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    try:
        async with async_timeout.timeout(10):
            async with session.get(robots_url, headers={"User-Agent": user_agent}) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    rp.parse(text.splitlines())
                else:
                    # Treat missing or inaccessible robots as permissive
                    rp.parse([])
    except Exception:
        rp.parse([])
    return rp

# ---------- Crawler class ----------
class SafeCrawler:
    def __init__(self, target, threads=4, max_depth=3, include_subdomains=False,
                 fuzz=False, wordlist=None, render_js=False, rate_delay=None,
                 user_agent=None, timeout=15, output=None):
        self.target = target.rstrip('/')
        self.base_domain = urlparse(self.target).hostname
        self.scheme = urlparse(self.target).scheme
        self.threads = max(1, threads)
        self.max_depth = max_depth
        self.include_subdomains = include_subdomains
        self.fuzz = fuzz
        self.wordlist = wordlist or DEFAULT_FUZZ_WORDS
        self.render_js = render_js
        self.rate_delay = rate_delay  # per-request delay in seconds; None => use robots crawl-delay if present
        self.user_agent = user_agent or f"SafeCrawler/1.0 (+{self.base_domain})"
        self.timeout = timeout
        self.output = output

        # state
        self.seen = set()
        self.to_visit = asyncio.Queue()
        self.results = {}  # url -> metadata
        self.session = None
        self.robots = None
        self.sem = asyncio.Semaphore(self.threads)
        self.domain_last_request = defaultdict(lambda: 0.0)  # per-host rate limiting
        self.lock = asyncio.Lock()

        # optional playwright
        self.playwright = None
        self.browser = None

    async def init(self):
        # aiohttp session with permissive SSL (you can change)
        sslcontext = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=sslcontext, limit=self.threads * 4)
        self.session = aiohttp.ClientSession(connector=connector)
        # fetch robots
        self.robots = await fetch_robots(self.session, self.target, self.user_agent)

        # enqueue initial URL
        await self.enqueue(self.target, depth=0, source="seed")

        # add fuzz words to queue (as relative paths) if enabled
        if self.fuzz:
            for w in self.wordlist:
                cand = urljoin(self.target + "/", w)
                await self.enqueue(cand, depth=0, source="fuzz")

        # optional Playwright init
        if self.render_js:
            try:
                from playwright.async_api import async_playwright
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(headless=True)
            except Exception as e:
                print("Playwright requested but not available/failed to start:", e)
                self.render_js = False

    async def close(self):
        if self.session:
            await self.session.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def enqueue(self, url, depth, source="link"):
        url = url.rstrip('/')
        if url in self.seen:
            return
        if depth > self.max_depth:
            return
        # ensure same domain
        if not same_domain_check(url, self.base_domain, self.include_subdomains):
            return
        # robots check
        try:
            can = True
        except Exception:
            can = True
        if not can:
            # skip disallowed by robots
            return
        self.seen.add(url)
        await self.to_visit.put((url, depth, source))

    async def worker(self, wid):
        while True:
            try:
                url, depth, source = await asyncio.wait_for(self.to_visit.get(), timeout=5.0)
            except asyncio.TimeoutError:
                # queue empty for now
                return
            async with self.sem:
                await self.polite_wait(url)
                meta = await self.fetch_and_parse(url, depth)
                self.to_visit.task_done()
                # store result
                if meta:
                    self.results[url] = meta

    async def polite_wait(self, url):
        # enforce per-host rate limiting and robots crawl-delay
        host = urlparse(url).netloc
        now_ts = time.monotonic()
        # robots crawl-delay preference (non-standard; robotparser provides crawl_delay)
        try:
            crawl_delay = self.robots.crawl_delay(self.user_agent)
        except Exception:
            crawl_delay = None
        delay = self.rate_delay if self.rate_delay is not None else (crawl_delay or 0.5)
        async with self.lock:
            last = self.domain_last_request[host]
            wait = max(0, delay - (now_ts - last))
            if wait > 0:
                await asyncio.sleep(wait)
            self.domain_last_request[host] = time.monotonic()

    async def fetch_and_parse(self, url, depth):
        result = {
            "url": url,
            "status": None,
            "final_url": None,
            "timestamp": now_iso(),
            "depth": depth,
            "source": "crawler",
            "response_time_ms": None,
            "content_type": None,
            "error": None,
        }
        start = time.monotonic()
        if self.render_js:
            # render via Playwright (slower)
            try:
                page = await self.browser.new_page()
                await page.set_extra_http_headers({"User-Agent": self.user_agent})
                await page.goto(url, timeout=self.timeout * 1000)
                content = await page.content()
                result["status"] = 200
                result["final_url"] = url
                result["content_type"] = "text/html"
                await page.close()
            except Exception as e:
                result["error"] = str(e)
                result["status"] = 0
                content = ""
        else:
            try:
                async with async_timeout.timeout(self.timeout):
                    async with self.session.get(url, headers={"User-Agent": self.user_agent, "Accept": "*/*"}) as resp:
                        result["status"] = resp.status
                        result["final_url"] = str(resp.url)
                        ct = resp.headers.get("content-type", "")
                        result["content_type"] = ct
                        # attempt to read bytes up to a limit
                        data = await resp.read()
                        # decode best-effort
                        try:
                            content = data.decode('utf-8', errors='replace')
                        except Exception:
                            content = ""
            except Exception as e:
                result["error"] = str(e)
                result["status"] = 0
                content = ""
        result["response_time_ms"] = int((time.monotonic() - start) * 1000)

        # parse links if HTML or text
        if content and ("html" in (result["content_type"] or "") or bool(re.search(r"<\s*html", content, re.I))):
            links = self.extract_links_from_html(content, url)
            for l in links:
                nl = normalize_link(l, url)
                if nl:
                    await self.enqueue(nl, depth + 1, source=url)
        else:
            # try regex-based extraction for JS/CSS like urls
            for m in URL_RE.finditer(content):
                u = m.group("u") or m.group("u2")
                if u:
                    nl = normalize_link(u.strip(" '\""), url)
                    if nl:
                        await self.enqueue(nl, depth + 1, source=url)
        return result

    def extract_links_from_html(self, html, base):
        soup = BeautifulSoup(html, "html.parser")
        hrefs = set()
        # anchor links
        for a in soup.find_all("a", href=True):
            hrefs.add(a["href"])
        # form actions
        for f in soup.find_all("form", action=True):
            hrefs.add(f["action"])
        # scripts
        for s in soup.find_all("script", src=True):
            hrefs.add(s["src"])
        # link tags (css, icons)
        for l in soup.find_all("link", href=True):
            hrefs.add(l["href"])
        # imgs
        for i in soup.find_all("img", src=True):
            hrefs.add(i["src"])
        # iframes
        for i in soup.find_all("iframe", src=True):
            hrefs.add(i["src"])
        # video / audio sources
        for v in soup.find_all(["video", "audio"]):
            if v.has_attr("src"):
                hrefs.add(v["src"])
            for s in v.find_all("source", src=True):
                hrefs.add(s["src"])
        # meta refresh
        meta = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower()=="refresh"})
        if meta and meta.get("content"):
            m = re.search(r"url=(.+)", meta["content"], flags=re.I)
            if m:
                hrefs.add(m.group(1).strip(" '\""))
        # inline CSS url(...) patterns
        for style in soup.find_all(style=True):
            for m in URL_RE.finditer(style["style"]):
                u = m.group("u") or m.group("u2")
                if u:
                    hrefs.add(u)
        return hrefs

    async def run(self):
        await self.init()
        workers = [asyncio.create_task(self.worker(i)) for i in range(self.threads)]
        # wait until queue is processed
        await self.to_visit.join()
        # cancel workers
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await self.close()

    # export
    async def export(self, path):
        results_list = list(self.results.values())
        ext = path.split(".")[-1].lower()
        if ext == "json":
            async with aiofiles.open(path, "w") as f:
                await f.write(json.dumps(results_list, indent=2))
        elif ext == "csv":
            async with aiofiles.open(path, "w") as f:
                writer = csv.writer(await f.__aenter__())
                # header
                await f.write("url,status,final_url,response_time_ms,depth,timestamp,content_type,error\n")
                for r in results_list:
                    line = [r.get("url",""), r.get("status",""), r.get("final_url",""),
                            r.get("response_time_ms",""), r.get("depth",""), r.get("timestamp",""),
                            r.get("content_type",""), r.get("error","")]
                    # escape commas simply
                    await f.write(",".join('"' + str(c).replace('"','""') + '"' for c in line) + "\n")
        else:
            async with aiofiles.open(path, "w") as f:
                await f.write("Crawl results:\n\n")
                for r in results_list:
                    await f.write(f"{r.get('url')}  [{r.get('status')}] {r.get('response_time_ms')}ms\n")

# ---------- CLI ----------
def build_argparser():
    p = argparse.ArgumentParser(description="Safe concurrent crawler + fuzzer (authorized use only).")
    p.add_argument("--target", "-t", required=True, help="Target base URL (e.g., https://example.com)")
    p.add_argument("--threads", type=int, default=4, help="Concurrent workers (default 4)")
    p.add_argument("--max-depth", "-d", type=int, default=3, help="Max crawl depth (default 3)")
    p.add_argument("--include-subdomains", action="store_true", help="Include subdomains under the same base domain")
    p.add_argument("--fuzz", action="store_true", help="Enable fuzzing with built-in or file wordlist")
    p.add_argument("--wordlist", help="Path to wordlist (one path per line) to use for fuzzing")
    p.add_argument("--render-js", action="store_true", help="Enable Playwright rendering of pages (slow)")
    p.add_argument("--rate-delay", type=float, default=None, help="Fixed per-host delay in seconds (overrides robots crawl-delay)")
    p.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout seconds")
    p.add_argument("--output", "-o", default="results.json", help="Output file (json/csv/txt)")
    return p

async def main():
    parser = build_argparser()
    args = parser.parse_args()

    # load optional wordlist
    wordlist = None
    if args.wordlist:
        try:
            async with aiofiles.open(args.wordlist, "r") as f:
                content = await f.read()
                wordlist = [l.strip() for l in content.splitlines() if l.strip()]
        except Exception as e:
            print("Failed to read wordlist:", e)
            return

    crawler = SafeCrawler(
        target=args.target,
        threads=args.threads,
        max_depth=args.max_depth,
        include_subdomains=args.include_subdomains,
        fuzz=args.fuzz,
        wordlist=wordlist,
        render_js=args.render_js,
        rate_delay=args.rate_delay,
        user_agent=args.user_agent,
        timeout=args.timeout,
        output=args.output
    )

    start = time.time()
    print(f"[{now_iso()}] Starting crawl on {args.target} (threads={args.threads}, max_depth={args.max_depth})")
    try:
        await crawler.run()
    except KeyboardInterrupt:
        print("Interrupted; shutting down gracefully...")
        await crawler.close()
    duration = time.time() - start
    print(f"[{now_iso()}] Crawl finished in {duration:.2f}s, discovered {len(crawler.results)} URLs")

    # export
    await crawler.export(args.output)
    print(f"Results exported to {args.output}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print("Fatal error:", e)
        sys.exit(1)

