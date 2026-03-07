import asyncio
import json
import os
import uuid
import subprocess
import requests
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# --- Configuration & State ---
CONCURRENCY_LIMIT = 10
SCAN_TIMEOUT = 90  # Slightly increased to ensure thoroughness

TYPE_MAP = {
    "R": "Reflected XSS",
    "S": "Stored XSS",
    "V": "Verified (DOM) XSS",
    "G": "Grep/Potential XSS"
}

class XSSOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.findings = []
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_links(self, url):
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return []
        self.visited.add(url)
        try:
            res = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(res.text, 'html.parser')
            links = [urljoin(url, a['href']).split('#')[0] for a in soup.find_all('a', href=True)]
            return [l for l in links if self.domain in urlparse(l).netloc]
        except:
            return []

    def run_dalfox(self, target_url):
        output_file = f"result_{uuid.uuid4().hex}.json"
        dalfox_path = "/snap/bin/dalfox" 
        cmd = [dalfox_path, "url", target_url, "--silence", "--no-color", "--format", "json", "-o", output_file]
        
        results = []
        try:
            if not os.path.exists(dalfox_path):
                return []

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.wait(timeout=SCAN_TIMEOUT)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), 15)
                except: pass
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    data = f.read().strip()
                    try:
                        results = json.loads(data) if data.startswith('[') else [json.loads(l) for l in data.splitlines()]
                    except: pass
        except: pass
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
        return results

    async def worker(self, url):
        async with self.semaphore:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                raw_type = r.get('type', 'R')
                readable_type = TYPE_MAP.get(raw_type, f"Unknown ({raw_type})")
                
                finding = {
                    "type": readable_type, 
                    "param": r.get('param'), 
                    "url": url, 
                    "poc": r.get('poc', 'N/A')
                }
                
                # Deduplication logic
                if not any(f['type'] == finding['type'] and f['param'] == finding['param'] and f['url'] == finding['url'] for f in self.findings):
                    self.findings.append(finding)
                    print(f"[!] {readable_type} FOUND: Parameter '{finding['param']}' at {url}")

    async def run(self):
        start_time = time.perf_counter()
        print(f"[*] Mapping {self.base_url}...")
        
        to_crawl = [self.base_url]
        unique_targets = set()
        
        while to_crawl:
            current = to_crawl.pop(0)
            new_links = await self.fetch_links(current)
            for link in new_links:
                parsed = urlparse(link)
                sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                if sig not in unique_targets:
                    unique_targets.add(sig)
                    await self.queue.put(link)
                    to_crawl.append(link)

        print(f"[*] Starting scan on {self.queue.qsize()} targets...")

        tasks = []
        while not self.queue.empty():
            url = await self.queue.get()
            tasks.append(asyncio.create_task(self.worker(url)))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        elapsed = time.perf_counter() - start_time
        self.generate_report(elapsed)

    def generate_report(self, elapsed):
        if not self.findings:
            print(f"\n[-] Scan finished in {elapsed:.2f}s. No XSS found.")
            return

        print(f"\n[✓] Scan finished in {elapsed:.2f}s. Total Hits: {len(self.findings)}")
        
        # Summary Table for Console
        from collections import Counter
        counts = Counter(f['type'] for f in self.findings)
        print("\n" + "="*45)
        print(f"{'XSS TYPE':<30} | {'COUNT':>10}")
        print("-" * 45)
        for t, c in counts.items():
            print(f"{t:<30} | {c:>10}")
        print("="*45)

        # File Export
        filename = "xss_orchestrator_results.txt"
        with open(filename, "w") as f:
            f.write(f"XSS SCAN REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Duration: {elapsed:.2f} seconds\n")
            f.write("-" * 60 + "\n")
            for t, c in counts.items():
                f.write(f"{t}: {c}\n")
            f.write("-" * 60 + "\n\n")
            for res in self.findings:
                f.write(f"Type: {res['type']}\nURL: {res['url']}\nParam: {res['param']}\nPOC: {res['poc']}\n")
                f.write("." * 30 + "\n")
        
        print(f"[+] Detailed results saved to {filename}")

if __name__ == "__main__":
    target = input("Enter Target URL: ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    orchestrator = XSSOrchestrator(target)
    asyncio.run(orchestrator.run())