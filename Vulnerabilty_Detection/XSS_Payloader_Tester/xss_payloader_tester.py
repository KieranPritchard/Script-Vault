import requests
import time
import random
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
    def __init__(self, target_url, payloads):
        self.target_url = target_url
        self.payloads = payloads
        self.session = requests.Session()
        self.results = []
        self.results_lock = Lock()
        self.target_domain = urlparse(target_url).netloc
        # Dynamically find tools in the new Go PATH
        self.dalfox_path = shutil.which("dalfox")
        self.nuclei_path = shutil.which("nuclei")

    def safe_request(self, method, url, **kwargs):
        try:
            kwargs['headers'] = get_random_agent()
            kwargs['timeout'] = 7
            return self.session.request(method, url, **kwargs)
        except:
            return None

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        if url in visited or self.target_domain not in urlparse(url).netloc:
            return visited
        if any(url.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.jpeg']):
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
        if not self.nuclei_path:
            print("[!] Nuclei not found. Skipping Phase 1.")
            return
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei against {target}")
        try:
            command = [self.nuclei_path, "-u", target, "-tags", "xss", "-severity", "medium,high,critical", "-silent", "-jsonl"]
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = proc.communicate(timeout=180)
            for line in stdout.splitlines():
                try:
                    vuln_data = json.loads(line)
                    self._log_result(f"Nuclei-{vuln_data.get('info',{}).get('severity','').upper()}", vuln_data.get("matched-at"), "Vulnerable", vuln_data.get("matcher-name"))
                except: continue
        except Exception as e:
            print(f"[-] Nuclei Error: {e}")

    def launch_dalfox(self, target_url):
        if not self.dalfox_path:
            return []
        
        # FIX: Dalfox needs parameters. If none exist, add common ones to trigger the scanner.
        if "?" not in target_url:
            target_url += "?q=test&id=1&search=query&name=user"

        local_findings = []
        command = [self.dalfox_path, "url", target_url, "--worker", "10", "--waf-evasion", "--silence", "--no-color", "--format", "json"]
        
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=60)
            
            if stderr and "error" in stderr.lower():
                with print_lock: print(f"[!] Dalfox Stderr: {stderr.strip()}")

            for line in stdout.splitlines():
                clean_line = line.strip().rstrip(',')
                if not clean_line or clean_line in ["[", "]"]: continue
                try:
                    vuln_data = json.loads(clean_line)
                    finding = {"type": "Dalfox-"+vuln_data.get("type","R"), "payload": vuln_data.get("poc","N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param","unknown")}
                    self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                    local_findings.append(finding)
                except: continue
        except Exception as e:
            with print_lock: print(f"[-] Dalfox Execution Error: {e}")
        return local_findings

    def _log_result(self, xss_type, payload, status, param=None):
        if status == "Vulnerable" and payload and payload != "N/A":
            finding_sig = f"{xss_type}-{param}-{payload}"
            with self.results_lock:
                if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                    result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
                    self.results.append(result)
                    with print_lock:
                        print(f"[!] {xss_type} FOUND: {param} | Payload: {payload}")

    def scan_page_workflow(self, page):
        return self.launch_dalfox(page)

def get_random_agent():
    return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}

def main():
    start_time = time.perf_counter() 
    url = input("Enter Target URL: ").strip()
    if not url.startswith("http"):
        print("Please include http:// or https://")
        return

    scanner = XSSPayloadTester(url, [])
    
    # Check tool availability
    if not scanner.dalfox_path:
        print("[!] Error: 'dalfox' command not found. Run 'export PATH=$PATH:$(go env GOPATH)/bin' first.")
        return

    scanner.run_nuclei_discovery(url)
    print("[*] Mapping site structure...")
    raw_pages = scanner.crawl(url)
    
    unique_pages = {}
    for p in raw_pages:
        parsed = urlparse(p)
        params = tuple(sorted(parse_qs(parsed.query).keys()))
        sig = (parsed.path, params)
        if sig not in unique_pages:
            unique_pages[sig] = p
    
    scan_list = list(unique_pages.values())
    print(f"[*] Deduplicated {len(raw_pages)} down to {len(scan_list)} unique targets.")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scanner.scan_page_workflow, scan_list)

    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds. Found {len(scanner.results)} unique hits.")

    if scanner.results:
        counts = Counter(v['type'] for v in scanner.results)
        print("\n" + "="*50)
        print(f"{'Vulnerability Type':<35} | {'Count':>5}")
        print("-" * 50)
        for v_type, count in counts.items():
            print(f"{v_type:<35} | {count:>5}")
        print("="*50)

if __name__ == "__main__":
    main()