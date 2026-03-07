import asyncio
import json
import csv
import subprocess
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Define absolute paths for snap-based or local binaries
DALFOX_PATH = "/snap/bin/dalfox"
NUCLEI_PATH = "nuclei" # Ensure this is in your PATH or provide absolute path

class SecurityOrchestrator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.semaphore = asyncio.Semaphore(5)
        self.pages_file = "discovered_urls.txt"
        self.results_file = "results.csv"
        
        # Reset and prepare files
        with open(self.pages_file, "w") as f: f.write("")
        with open(self.results_file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Tool", "Target", "Vulnerability", "Severity", "Extra Info"])

    async def crawl(self, url):
        if url in self.visited or self.domain not in urlparse(url).netloc:
            return
        self.visited.add(url)
        with open(self.pages_file, "a") as f: f.write(url + "\n")
        
        try:
            # Basic crawl to find local links
            res = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            soup = BeautifulSoup(res.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href']).split('#')[0]
                if self.domain in urlparse(link).netloc:
                    await self.crawl(link)
        except Exception:
            pass

    def run_command(self, cmd):
        """Helper to run a shell command and capture output."""
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return proc.stdout
        except Exception as e:
            return f"Error: {str(e)}"

    async def scan_url(self, url):
        async with self.semaphore:
            print(f"[*] Scanning Target: {url}")
            loop = asyncio.get_event_loop()

            # 1. Run DalFox using the Snap path and mining enabled
            # --mining-dict forces DalFox to guess parameters if none are present
            df_cmd = [DALFOX_PATH, "url", url, "--format", "json", "--mining-dict", "--silence", "--no-color"]
            df_results = await loop.run_in_executor(None, self.run_command, df_cmd)
            for line in df_results.splitlines():
                try:
                    data = json.loads(line)
                    self.log_result("DalFox", url, data.get("type"), "Medium/High", f"Param: {data.get('param')}")
                except: continue

            # 2. Run Nuclei with JSONL output
            nu_cmd = [NUCLEI_PATH, "-u", url, "-jsonl", "-silent", "-nc"]
            nu_results = await loop.run_in_executor(None, self.run_command, nu_cmd)
            for line in nu_results.splitlines():
                try:
                    data = json.loads(line)
                    self.log_result("Nuclei", url, data.get("info", {}).get("name"), 
                                   data.get("info", {}).get("severity"), data.get("template-id"))
                except: continue

    def log_result(self, tool, target, vuln, sev, extra):
        with open(self.results_file, "a", newline='') as f:
            csv.writer(f).writerow([tool, target, vuln, sev, extra])

    async def run(self):
        print(f"[*] Step 1: Building site map for {self.base_url}...")
        await self.crawl(self.base_url)
        
        targets = list(self.visited)
        print(f"[*] Step 2: Firing Scanners at {len(targets)} discovered endpoints...")
        await asyncio.gather(*(self.scan_url(u) for u in targets))
        print(f"\n[✓] Done. Discovered pages: {self.pages_file} | Results: {self.results_file}")

if __name__ == "__main__":
    target = input("Enter Target URL: ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    orchestrator = SecurityOrchestrator(target)
    asyncio.run(orchestrator.run())