import requests
import time
import random
import subprocess
import os
import json
import uuid
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
        self.target_domain = urlparse(target_url).netloc

    def safe_request(self, method, url, **kwargs):
        try:
            kwargs['headers'] = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
            kwargs['timeout'] = 7
            return self.session.request(method, url, **kwargs)
        except:
            return None

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        if url in visited or self.target_domain not in urlparse(url).netloc:
            return visited
        if any(url.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf']):
            return visited
        with print_lock:
            print(f"[*] Crawling: {url}")
        visited.add(url)
        res = self.safe_request('GET', url)
        if not res: return visited
        try:
            soup = BeautifulSoup(res.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href']).split('#')[0]
                self.crawl(full_url, visited)
        except: pass
        return visited

    def run_nuclei_discovery(self, target):
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei against {target}")
        try:
            command = ["nuclei", "-u", target, "-tags", "xss", "-severity", "medium,high,critical", "-silent", "-jsonl"]
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, _ = proc.communicate(timeout=120)
                for line in stdout.splitlines():
                    try:
                        data = json.loads(line)
                        self._log_result(f"Nuclei-{data.get('info',{}).get('severity','').upper()}", data.get("matched-at"), "Vulnerable", data.get("matcher-name"))
                    except: continue
            except: proc.kill()
        except: pass

    def run_dalfox_mode(self, target_url, mode="url"):
        local_findings = []
        dalfox_path = "/snap/bin/dalfox"
        temp_file = f"tmp_{uuid.uuid4().hex}.json"
        
        # Removed --skip-mining-all to ensure parameters are actually tested
        if mode == "sxss":
            cmd = f"{dalfox_path} sxss \"{target_url}\" --trigger \"{target_url}\" -X POST --delay 50 --waf-evasion --silence --format json -o {temp_file}"
        else:
            cmd = f"{dalfox_path} url \"{target_url}\" --delay 50 --waf-evasion --silence --no-color --no-spinner --format json -o {temp_file}"
            
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                proc.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
            
            # Read results from the output file even if process was killed
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Dalfox sometimes writes a JSON array or multiple objects
                        if content.startswith('['):
                            data_list = json.loads(content)
                        else:
                            data_list = [json.loads(line) for line in content.splitlines() if line.strip()]
                        
                        for vuln in data_list:
                            v_type = "Stored" if mode == "sxss" else f"Dalfox-{vuln.get('type','R')}"
                            self._log_result(v_type, vuln.get("poc","N/A"), "Vulnerable", vuln.get("param","unknown"))
                os.remove(temp_file)
        except: pass
        return local_findings

    def _log_result(self, xss_type, payload, status, param=None):
        if payload and payload != "N/A":
            finding_sig = f"{xss_type}-{param}-{payload}"
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                self.results.append({"type": xss_type, "payload": payload, "parameter": param})
                with print_lock:
                    print(f"[!] {xss_type} FOUND: {param} at {payload[:50]}...")

    def scan_page_workflow(self, page):
        self.run_dalfox_mode(page, mode="url")
        self.run_dalfox_mode(page, mode="sxss")

def main():
    start_time = time.perf_counter() 
    url = input("Enter Target URL: ").strip()
    scanner = XSSPayloadTester(url)
    scanner.run_nuclei_discovery(url)
    
    print("[*] Phase 2: Mapping site structure...")
    raw_pages = scanner.crawl(url)
    
    unique_pages = {}
    for p in raw_pages:
        parsed = urlparse(p)
        params = tuple(sorted(parse_qs(parsed.query).keys()))
        sig = (parsed.path, params)
        if sig not in unique_pages: unique_pages[sig] = p
    
    scan_list = list(unique_pages.values())
    print(f"[*] Deduplicated to {len(scan_list)} targets. Scanning with 10 threads...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scanner.scan_page_workflow, scan_list)

    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds. Total unique hits: {len(scanner.results)}")

    if scanner.results:
        counts = Counter(r['type'] for r in scanner.results)
        print("\n" + "="*40)
        for v_type, count in counts.items():
            print(f"{v_type:<30} | {count:>5}")
        print("="*40)
        with open("xss_scan_results.txt", "w") as f:
            for r in scanner.results:
                f.write(f"Type: {r['type']} | Param: {r['parameter']} | POC: {r['payload']}\n")

if __name__ == "__main__":
    main()