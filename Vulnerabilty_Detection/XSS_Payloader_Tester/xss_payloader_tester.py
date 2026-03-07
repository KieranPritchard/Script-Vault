import asyncio
import json
import os
import uuid
import subprocess
import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from collections import Counter

# --- Configuration & State ---
CONCURRENCY_LIMIT = 10
SCAN_TIMEOUT = 90  # Slightly increased for thoroughness

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
        if any(url.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf']):
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
        # Using -X POST for pages likely to have forms for better Stored coverage
        cmd = [dalfox_path, "url", target_url, "--silence", "--no-color", "--format", "json", "-o", output_file]
        
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
                        return json.loads(data) if data.startswith('[') else [json.loads(l) for l in data.splitlines()]
                    except: return []
        except:
            pass
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
        return []

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Analyzing: {url}")
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self.run_dalfox, url)
            
            for r in results:
                raw_type = r.get('type', 'R')
                readable_type = TYPE_MAP.get(raw_type, f"Unknown ({raw_type})")
                finding = {"type": readable_type, "param": r.get('param'), "url": url, "poc": r.get('poc')}
                
                # Deduplicate findings per parameter per page
                if not any(f['url'] == url and f['param'] == finding['param'] and f['type'] == readable_type for f in self.findings):
                    self.findings.append(finding)
                    print(f"[!] {readable_type} FOUND: Param '{finding['param']}' at {url}")

    async def run(self):
        start_time = time.perf_counter()
        print(f"[*] Starting Orchestrator against {self.base_url}")
        
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

        print(f"[*] Discovery complete. Processing {self.queue.qsize()} unique targets...")

        tasks = []
        while not self.queue.empty():
            url = await self.queue.get()
            tasks.append(asyncio.create_task(self.worker(url)))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        elapsed = time.perf_counter() - start_time
        self.print_summary(elapsed)

    def print_summary(self, elapsed):
        print(f"\n[✓] Scan Finished in {elapsed:.2f} seconds")
        if not self.findings:
            print("[-] No vulnerabilities detected.")
            return

        counts = Counter(f['type'] for f in self.findings)
        print("\n" + "="*50)
        print(f"{'XSS VULNERABILITY SUMMARY':^50}")
        print("="*50)
        for v_type, count in counts.items():
            print(f"{v_type:<40} | {count:>5}")
        print("="*50)

        save = input(f"\n[!] {len(self.findings)} hits found. Save to file? (y/n): ").lower()
        if save == 'y':
            with open("xss_scan_results.txt", "w") as f:
                f.write(f"XSS SCAN REPORT - {self.base_url}\n")
                f.write(f"Duration: {elapsed:.2f} seconds\n")
                f.write("-" * 50 + "\n")
                for fnd in self.findings:
                    f.write(f"Type: {fnd['type']} | Param: {fnd['param']} | URL: {fnd['url']}\n")
                    f.write(f"POC: {fnd['poc']}\n\n")
            print("[+] Results saved to xss_scan_results.txt")

if __name__ == "__main__":
    target = input("Enter Target URL: ").strip()
    if target:
        if not target.startswith("http"): target = "http://" + target
        asyncio.run(XSSOrchestrator(target).run())