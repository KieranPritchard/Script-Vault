import asyncio
import json
import os
import uuid
import subprocess
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# --- Configuration & State ---
CONCURRENCY_LIMIT = 10
SCAN_TIMEOUT = 60  # Aggressive 60s window per page

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url):
        """Standard crawler with an async wrapper."""
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
            # Using basic requests for the crawl phase
            res = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(res.text, 'html.parser')
            links = [urljoin(url, a['href']).split('#')[0] for a in soup.find_all('a', href=True)]
            return [l for l in links if self.domain in urlparse(l).netloc]
        except:
            return []

    def run_dalfox(self, target_url):
        """Worker function meant to run in a thread."""
        output_file = f"result_{uuid.uuid4().hex}.json"
        # Flags: --silence (clean output), --format json, -o (reliable file write)
        cmd = ["dalfox", "url", target_url, "--silence", "--no-color", "--format", "json", "-o", output_file]
        
        try:
            # start_new_session=True allows us to kill the whole process group if it hangs
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.wait(timeout=SCAN_TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), 15) # Force kill group
            
            # Parse findings from the persistence file
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    data = f.read().strip()
                    # Dalfox JSON can be a list or line-delimited
                    try:
                        results = json.loads(data) if data.startswith('[') else [json.loads(l) for l in data.splitlines()]
                        return results
                    except: return []
        finally:
            if os.path.exists(output_file): os.remove(output_file)
        return []

    async def worker(self, url):
        """The core orchestration logic for a single target."""
        async with self.semaphore:
            print(f"[*] Analyzing: {url}")
            # Run the heavy subprocess in the thread pool to keep the event loop free
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                finding = f"[!] {r.get('type')} FOUND: {r.get('param')} @ {url}"
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(finding)

    async def run(self):
        print(f"[*] Starting Rebuilt Orchestrator against {self.base_url}")
        
        # 1. Map Phase (Recursive Crawl)
        to_crawl = [self.base_url]
        unique_targets = set()
        
        while to_crawl:
            current = to_crawl.pop(0)
            new_links = await self.fetch_links(current)
            for link in new_links:
                # Basic deduplication by path and param keys
                parsed = urlparse(link)
                sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                if sig not in unique_targets:
                    unique_targets.add(sig)
                    await self.queue.put(link)
                    to_crawl.append(link)

        print(f"[*] Queue built with {self.queue.qsize()} unique structures. Launching workers...")

        # 2. Scan Phase
        tasks = []
        while not self.queue.empty():
            url = await self.queue.get()
            tasks.append(asyncio.create_task(self.worker(url)))
        
        await asyncio.gather(*tasks)
        print(f"\n[✓] Scan Complete. Total unique hits: {len(self.findings)}")

if __name__ == "__main__":
    target = input("Enter Target URL: ").strip()
    orchestrator = XSSOrchestrator(target)
    asyncio.run(orchestrator.run())