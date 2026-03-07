import asyncio
import json
import os
import csv
import uuid
import subprocess
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

# --- Configuration ---
CONCURRENCY_LIMIT = 5
SCAN_TIMEOUT = 120 
URL_FILE = "discovered_urls.txt"
RESULTS_CSV = "results.csv"

class SecurityOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
        
        # Initialize files
        with open(URL_FILE, "w") as f: f.write("")
        with open(RESULTS_CSV, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Tool", "Type", "Severity", "Target", "Param/Info"])

    async def crawl(self, url):
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return
        self.visited.add(url)
        with open(URL_FILE, "a") as f: f.write(url + "\n")
        
        try:
            res = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            soup = BeautifulSoup(res.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href']).split('#')[0]
                if self.domain in urlparse(link).netloc:
                    await self.crawl(link)
        except Exception: pass

    def run_tool(self, cmd, tool_name):
        """Executes a CLI tool and returns the output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
            return result.stdout
        except Exception as e:
            return ""

    def log_to_csv(self, tool, v_type, severity, target, extra):
        with open(RESULTS_CSV, "a", newline='') as f:
            csv.writer(f).writerow([tool, v_type, severity, target, extra])

    async def worker(self, url):
        async with self.semaphore:
            print(f"[*] Scanning: {url}")
            loop = asyncio.get_event_loop()

            # 1. Run DalFox
            df_out = await loop.run_in_executor(None, self.run_tool, 
                ["dalfox", "url", url, "--format", "json", "--silence", "--no-color"], "DalFox")
            for line in df_out.splitlines():
                try:
                    data = json.loads(line)
                    self.log_to_csv("DalFox", data.get("type"), "Medium", url, data.get("param"))
                except: pass

            # 2. Run Nuclei (using specific XSS/Generic templates for speed)
            nu_out = await loop.run_in_executor(None, self.run_tool, 
                ["nuclei", "-u", url, "-jsonl", "-silent", "-nc"], "Nuclei")
            for line in nu_out.splitlines():
                try:
                    data = json.loads(line)
                    self.log_to_csv("Nuclei", data.get("info", {}).get("name"), 
                                   data.get("info", {}).get("severity"), url, data.get("template-id"))
                except: pass

    async def run(self):
        print(f"[*] Phase 1: Crawling {self.base_url}")
        await self.crawl(self.base_url)
        
        print(f"[*] Phase 2: Scanning {len(self.visited)} URLs with DalFox & Nuclei")
        tasks = [asyncio.create_task(self.worker(u)) for u in self.visited]
        await asyncio.gather(*tasks)
        print(f"\n[✓] Done. URLs saved to {URL_FILE}. Results saved to {RESULTS_CSV}")

if __name__ == "__main__":
    target = input("Enter Target URL (e.g., http://testphp.vulnweb.com): ").strip()
    orchestrator = SecurityOrchestrator(target)
    asyncio.run(orchestrator.run())