import requests
import time
import subprocess
import os
import json
import shutil
import csv
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

print_lock = Lock()

class XSSPayloadTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        self.results_lock = Lock()
        self.target_domain = urlparse(target_url).netloc
        # Ensure it uses the Go-installed version in /home/user/go/bin
        self.dalfox_path = shutil.which("dalfox")
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
        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.woff', '.svg']):
            return visited

        with print_lock:
            print(f"[*] Crawling: {url}")
        visited.add(url)

        try:
            res = self.session.get(url, headers=self.get_headers(), timeout=7)
            if res.status_code == 200 and 'text/html' in res.headers.get('Content-Type', ''):
                soup = BeautifulSoup(res.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href']).split('#')[0]
                    self.crawl(full_url, visited)
        except: pass
        return visited

    def run_dalfox(self, target_url):
        if not self.dalfox_path or not os.path.exists(self.dalfox_path):
            return

        scan_url = target_url if "?" in target_url else target_url + "?id=1&q=test"
        
        # Dalfox commands for Reflected/DOM and Stored XSS
        commands = [
            [self.dalfox_path, "url", scan_url, "--worker", "5", "--delay", "100", "--waf-evasion", "--silence", "--no-color", "--format", "json"],
            [self.dalfox_path, "sxss", scan_url, "--trigger", scan_url, "--worker", "5", "--delay", "100", "--silence", "--no-color", "--format", "json"]
        ]

        for cmd in commands:
            try:
                # We do not capture stdout=PIPE here so you see the live Dalfox output in the terminal
                # Instead, we run a second pass or use a temporary file to parse the JSON for the CSV
                proc = subprocess.Popen(cmd + ["--output", "temp_hit.txt"], stdout=None, stderr=None)
                proc.communicate(timeout=180)
                
                # If Dalfox found something, it will write to temp_hit.txt in JSON format
                if os.path.exists("temp_hit.txt"):
                    with open("temp_hit.txt", "r") as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                # FIX: Exhaustive search for the actual payload
                                poc_raw = data.get("poc") or data.get("evidence") or data.get("injection_point") or data.get("url")
                                poc = unquote(str(poc_raw)) if poc_raw else "Manual Verification Required"
                                
                                v_type = f"Dalfox-{data.get('type', 'Unknown')}"
                                if "sxss" in cmd: v_type = "Stored-XSS"
                                self._log_result(v_type, poc, "Vulnerable", data.get("param", "url-path"))
                            except: pass
                    os.remove("temp_hit.txt")
            except Exception as e:
                with print_lock: print(f"[-] Dalfox Error on {target_url}: {e}")

    def _log_result(self, xtype, payload, status, param):
        sig = f"{xtype}-{param}-{payload}"
        with self.results_lock:
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == sig for r in self.results):
                res_entry = {"type": xtype, "parameter": param, "payload": payload, "status": status}
                self.results.append(res_entry)
                with print_lock:
                    print(f"\n[!] {xtype} DETECTED!")
                    print(f"    Param: {param}")
                    print(f"    PoC: {payload}\n")

    def save_results_to_csv(self, filename="xss_results.csv"):
        if not self.results:
            print("[!] No vulnerabilities found to export.")
            return
        keys = ["type", "parameter", "payload", "status"]
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.results)
        print(f"[✓] Final report saved to {filename}")

def main():
    target = input("Enter Target URL: ").strip()
    if not target.startswith("http"):
        print("Invalid URL.")
        return
    
    start_time = time.perf_counter()
    scanner = XSSPayloadTester(target)
    
    print("\n--- PHASE 1: CRAWLING ---")
    discovered_urls = scanner.crawl(target)
    
    unique_paths = {}
    for url in discovered_urls:
        p = urlparse(url)
        if p.path not in unique_paths: unique_paths[p.path] = url
    
    scan_list = list(unique_paths.values())
    print(f"[✓] Found {len(scan_list)} unique targets.")

    print("\n--- PHASE 2: DALFOX SCAN (Reflected + Stored | 5 Threads) ---")
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scanner.run_dalfox, scan_list)

    scanner.save_results_to_csv()
    
    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Scan Complete in {elapsed:.2f} seconds.")
    print(f"[✓] Total unique vulnerabilities found: {len(scanner.results)}")

if __name__ == "__main__":
    main()