import asyncio
import json
import os
import uuid
import subprocess
import httpx
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# --- Configuration & State ---
CONCURRENCY_LIMIT = 5 
SCAN_TIMEOUT = 120    

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url, client):
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
            res = await client.get(url, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            return [urljoin(url, a['href']).split('#')[0] for a in soup.find_all('a', href=True) if self.domain in urlparse(urljoin(url, a['href'])).netloc]
        except: return []

    def run_dalfox(self, target_url):
        """Runs Dalfox using pipe mode for better stability and detailed discovery."""
        output_file = f"result_{uuid.uuid4().hex}.json"
        # We use 'pipe' mode and echo the URL into it; this is often more reliable in scripts
        cmd = f"echo {target_url} | dalfox pipe --mining --deep-domadrift --silence --format json -o {output_file}"
        
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=SCAN_TIMEOUT)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    raw_data = f.read().strip()
                    data = json.loads(raw_data)
                    # Dalfox JSON reports store findings in the 'pocs' key
                    return data.get('pocs', []) if isinstance(data, dict) else []
        except: pass
        finally:
            if os.path.exists(output_file): os.remove(output_file)
        return []

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Scanning: {url}")
            loop = asyncio.get_loop() if hasattr(asyncio, 'get_loop') else asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                finding = f"[!] {r.get('type')} FOUND in {r.get('param')} @ {url}"
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(finding)

    async def run(self):
        print(f"[*] Initializing scan for {self.base_url}")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            to_crawl = [self.base_url]
            unique_targets = set()
            while to_crawl:
                current = to_crawl.pop(0)
                for link in await self.fetch_links(current, client):
                    parsed = urlparse(link)
                    sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                    if sig not in unique_targets:
                        unique_targets.add(sig)
                        await self.queue.put(link)
                        to_crawl.append(link)

            print(f"[*] Starting scan on {self.queue.qsize()} targets...")
            tasks = [asyncio.create_task(self.worker(await self.queue.get())) for _ in range(self.queue.qsize())]
            await asyncio.gather(*tasks)
        print(f"\n[✓] Done. Total Findings: {len(self.findings)}")

if __name__ == "__main__":
    target = input("Target URL: ").strip()
    if target: asyncio.run(XSSOrchestrator(target).run())