import asyncio
import json
import os
import uuid
import subprocess
import requests
import shutil
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

CONCURRENCY_LIMIT = 5 
SCAN_TIMEOUT = 90 

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.processed_signatures = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
        self.dalfox_path = shutil.which("dalfox") or "/snap/bin/dalfox"

    async def fetch_links(self, url):
        if url in self.visited:
            return []
        self.visited.add(url)
        try:
            # Use a session for better performance during crawling
            res = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            soup = BeautifulSoup(res.text, 'html.parser')
            links = []
            for a in soup.find_all('a', href=True):
                full_url = urljoin(url, a['href']).split('#')[0].rstrip('/')
                if self.domain in urlparse(full_url).netloc:
                    links.append(full_url)
            return list(set(links))
        except Exception as e:
            return []

    def run_dalfox(self, target_url):
        output_file = f"result_{uuid.uuid4().hex}.json"
        # Only run if target has parameters or we want to force a crawl-based scan
        cmd = [self.dalfox_path, "url", target_url, "--silence", "--no-color", "--format", "json", "-o", output_file]
        
        try:
            if not os.path.exists(self.dalfox_path):
                print(f"[-] Error: dalfox binary not found. Please install it.")
                return []

            # Use subprocess.run for simpler timeout management
            subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT)
            
            results = []
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            line_data = json.loads(line.strip())
                            if isinstance(line_data, list):
                                results.extend(line_data)
                            else:
                                results.append(line_data)
                        except json.JSONDecodeError:
                            continue
            return results
        except Exception as e:
            return []
        finally:
            if os.path.exists(output_file): os.remove(output_file)

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Testing: {url}")
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            for r in results:
                finding = {"type": r.get('type'), "param": r.get('param'), "url": url}
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(f"[!] {r.get('type').upper()} FOUND: '{r.get('param')}' at {url}")

    async def run(self):
        if not self.dalfox_path:
            print("[-] Error: DalFox not found in PATH.")
            return

        print(f"[*] Starting Scan against {self.base_url}")
        to_crawl = [self.base_url]
        
        # Initial Discovery Phase
        while to_crawl:
            current = to_crawl.pop(0)
            links = await self.fetch_links(current)
            for link in links:
                parsed = urlparse(link)
                # Signature based on Path + Sorted Query Keys to avoid scanning identical logic
                sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                if sig not in self.processed_signatures:
                    self.processed_signatures.add(sig)
                    # Priority: only queue if it has parameters, or if it's the root
                    if parsed.query or link == self.base_url:
                        await self.queue.put(link)
                    to_crawl.append(link)
            if len(self.visited) > 100: break # Safety cap

        print(f"[*] Processing {self.queue.qsize()} targets...")
        tasks = []
        while not self.queue.empty():
            url = await self.queue.get()
            tasks.append(asyncio.create_task(self.worker(url)))
        
        if tasks:
            await asyncio.gather(*tasks)
        print(f"\n[✓] Finished. Total findings: {len(self.findings)}")

if __name__ == "__main__":
    target = input("Target URL: ").strip()
    if not target.startswith("http"): target = "http://" + target
    asyncio.run(XSSOrchestrator(target).run())