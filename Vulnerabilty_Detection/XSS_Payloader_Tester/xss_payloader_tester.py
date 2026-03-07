import asyncio
import json
import os
import uuid
import subprocess
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# --- Configuration & State ---
CONCURRENCY_LIMIT = 5 
SCAN_TIMEOUT = 120  
MAX_DEPTH = 3

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url, depth):
        if depth > MAX_DEPTH or url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
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

    def run_tool(self, cmd, output_file):
        """Generic runner for CLI tools."""
        try:
            subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT)
            results = []
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            results.append(json.loads(line))
            return results
        except Exception:
            return []
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Scanning: {url}")
            loop = asyncio.get_event_loop()
            
            dalfox_out = f"df_{uuid.uuid4().hex}.json"
            nuclei_out = f"nc_{uuid.uuid4().hex}.json"

            # 1. DalFox: Best for reflected XSS in params
            df_cmd = ["dalfox", "url", url, "--silence", "--format", "json", "-o", dalfox_out]
            # 2. Nuclei: Best for template-based XSS/Common Vulns
            nc_cmd = ["nuclei", "-u", url, "-silent", "-jsonl", "-o", nuclei_out, "-tags", "xss"]

            # Run both tools in parallel for the current URL
            df_task = loop.run_in_executor(None, self.run_tool, df_cmd, dalfox_out)
            nc_task = loop.run_in_executor(None, self.run_tool, nc_cmd, nuclei_out)
            
            df_results, nc_results = await asyncio.gather(df_task, nc_task)

            for r in df_results:
                msg = f"[!] DALFOX: {r.get('type')} on {r.get('param')} -> {url}"
                if msg not in self.findings:
                    self.findings.append(msg); print(msg)

            for r in nc_results:
                msg = f"[!] NUCLEI: {r.get('info', {}).get('name')} -> {url}"
                if msg not in self.findings:
                    self.findings.append(msg); print(msg)

    async def run(self):
        print(f"[*] Launching Orchestrator: {self.base_url}")
        queue = [self.base_url]
        unique_targets = set()
        scan_tasks = []

        depth = 0
        while queue and depth <= MAX_DEPTH:
            current_batch = queue[:]
            queue.clear()
            for url in current_batch:
                # Deduplication by path and param keys
                p = urlparse(url)
                sig = (p.path, tuple(sorted(parse_qs(p.query).keys())))
                if sig not in unique_targets:
                    unique_targets.add(sig)
                    scan_tasks.append(asyncio.create_task(self.worker(url)))
                    
                    new_links = await self.fetch_links(url, depth)
                    queue.extend(new_links)
            depth += 1

        if scan_tasks:
            await asyncio.gather(*scan_tasks)
        print(f"\n[✓] Finished. Total Findings: {len(self.findings)}")

if __name__ == "__main__":
    target = input("Enter Target URL (with http/https): ").strip()
    if target:
        asyncio.run(XSSOrchestrator(target).run())