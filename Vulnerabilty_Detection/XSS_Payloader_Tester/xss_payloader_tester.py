import asyncio
import json
import os
import uuid
import subprocess
import httpx
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# --- Configuration & State ---
CONCURRENCY_LIMIT = 5 # Lowered for stability on vulnerable targets
SCAN_TIMEOUT = 120    # Increased timeout to allow Dalfox to finish its checks

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url, client):
        """Asynchronous crawler using httpx."""
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
            res = await client.get(url, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            links = [urljoin(url, a['href']).split('#')[0] for a in soup.find_all('a', href=True)]
            return [l for l in links if self.domain in urlparse(l).netloc]
        except Exception:
            return []

    def run_dalfox(self, target_url):
        """Executes Dalfox with improved discovery flags."""
        output_file = f"result_{uuid.uuid4().hex}.json"
        # Added --mining to find hidden params and --deep-domadrift for DOM XSS
        cmd = [
            "dalfox", "url", target_url, 
            "--mining", "--deep-domadrift",
            "--silence", "--no-color", "--format", "json", "-o", output_file
        ]
        
        try:
            # We use a timeout but allow more time for mining
            proc = subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    data = f.read().strip()
                    try:
                        # Dalfox can output a list or single objects per line
                        if data.startswith('['):
                            return json.loads(data)
                        return [json.loads(l) for l in data.splitlines() if l.strip()]
                    except: return []
        except (subprocess.TimeoutExpired, Exception):
            pass
        finally:
            if os.path.exists(output_file): os.remove(output_file)
        return []

    async def worker(self, url):
        """Orchestration logic for target analysis."""
        async with self.semaphore:
            print(f"[*] Analyzing: {url}")
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                # Dalfox JSON structure check
                ptype = r.get('type', 'XSS')
                param = r.get('param', 'unknown')
                finding = f"[!] {ptype} FOUND: {param} @ {url}"
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(finding)

    async def run(self):
        print(f"[*] Starting Rebuilt Orchestrator against {self.base_url}")
        
        async with httpx.AsyncClient(headers={'User-Agent': 'Mozilla/5.0'}, follow_redirects=True) as client:
            to_crawl = [self.base_url]
            unique_targets = set()
            
            # Map Phase
            while to_crawl:
                current = to_crawl.pop(0)
                new_links = await self.fetch_links(current, client)
                for link in new_links:
                    parsed = urlparse(link)
                    sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                    if sig not in unique_targets:
                        unique_targets.add(sig)
                        await self.queue.put(link)
                        to_crawl.append(link)

            print(f"[*] Queue built with {self.queue.qsize()} unique targets. Scanning...")

            # Scan Phase
            tasks = []
            while not self.queue.empty():
                url = await self.queue.get()
                tasks.append(asyncio.create_task(self.worker(url)))
            
            if tasks:
                await asyncio.gather(*tasks)
        
        print(f"\n[✓] Scan Complete. Total unique hits: {len(self.findings)}")

if __name__ == "__main__":
    target = input("Enter Target URL: ").strip()
    if target:
        asyncio.run(XSSOrchestrator(target).run())