import requests
import time
import subprocess
import os
import json
import shutil
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from collections import Counter

print_lock = Lock()

class XSSPayloadTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        self.results_lock = Lock()
        self.target_domain = urlparse(target_url).netloc
        self.dalfox_path = shutil.which("dalfox")
        # Ensure it uses the Go-installed version in /home/user/go/bin
        if not self.dalfox_path:
            go_bin = os.path.expanduser("~/go/bin/dalfox")
            if os.path.exists(go_bin):
                self.dalfox_path = go_bin

    def get_headers(self):
        return {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        parsed = urlparse(url)
        if url in visited or self.target_domain not in parsed.netloc:
            return visited
        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.woff']):
            return visited

        with print_lock:
            print(f"[*] Crawling: {url}")
        visited.add(url)

        try:
            res = self.session.get(url, headers=self.get_headers(), timeout=10)
            if res.status_code == 200 and 'text/html' in res.headers.get('Content-Type', ''):
                soup = BeautifulSoup(res.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href']).split('#')[0]
                    self.crawl(full_url, visited)
        except: pass
        return visited

    def run_dalfox(self, target_url):
        if not self.dalfox_path:
            return
        
        # If the crawled URL has no params, add some for discovery
        scan_url = target_url
        if "?" not in scan_url:
            scan_url += "?id=1&q=test&search=query"

        with print_lock:
            print(f"[*] Testing: {scan_url}")

        command = [self.dalfox_path, "url", scan_url, "--worker", "5", "--waf-evasion", "--silence", "--no-color", "--format", "json"]
        
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = proc.communicate(timeout=60)
            for line in stdout.splitlines():
                line = line.strip().rstrip(',')
                if line.startswith('{'):
                    try:
                        data = json.loads(line)
                        self._log_result(f"Dalfox-{data.get('type')}", data.get("poc"), "Vulnerable", data.get("param"))
                    except: pass
        except: pass

    def _log_result(self, xtype, payload, status, param):
        sig = f"{xtype}-{param}-{payload}"
        with self.results_lock:
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == sig for r in self.results):
                self.results.append({"type": xtype, "payload": payload, "status": status, "parameter": param})
                with print_lock:
                    print(f"\n[!] VULNERABILITY FOUND: {xtype} on param '{param}'")
                    print(f"    PoC: {payload}\n")

def main():
    target = input("Enter Target URL: ").strip()
    if not target.startswith("http"):
        print("Invalid URL format.")
        return

    scanner = XSSPayloadTester(target)
    
    # PHASE 1: CRAWL FIRST
    print("\n--- PHASE 1: CRAWLING SITE ---")
    discovered_urls = scanner.crawl(target)
    
    # Deduplicate paths (ignoring slight param variations for efficiency)
    unique_paths = {}
    for url in discovered_urls:
        p = urlparse(url)
        if p.path not in unique_paths:
            unique_paths[p.path] = url
    
    scan_list = list(unique_paths.values())
    print(f"[✓] Crawl complete. Found {len(discovered_urls)} pages. Deduplicated to {len(scan_list)} unique paths.")

    # PHASE 2: TEST WITH DALFOX
    print("\n--- PHASE 2: TESTING WITH DALFOX ---")
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(scanner.run_dalfox, scan_list)

    print(f"\n[✓] All tests finished. Total Unique Hits: {len(scanner.results)}")

if __name__ == "__main__":
    main()