import requests
import time
import random
import subprocess
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from collections import Counter # Added for the summary table

# A Lock prevents threads from printing over each other
print_lock = Lock()

class XSSPayloadTester:
    def __init__(self, target_url, payloads):
        self.target_url = target_url
        self.payloads = payloads
        self.session = requests.Session()
        self.results = []
        self.target_domain = urlparse(target_url).netloc

    # NEW: Robust request handler with exponential backoff
    def safe_request(self, method, url, **kwargs):
        retries = 3
        for i in range(retries):
            try:
                # Add a random user agent to every request
                kwargs['headers'] = get_random_agent()
                kwargs['timeout'] = 10
                response = self.session.request(method, url, **kwargs)
                return response
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if i < retries - 1:
                    wait = (i + 1) * 2 + random.uniform(0, 1)
                    with print_lock:
                        print(f"[-] Connection error on {url}. Retrying in {wait:.2f}s...")
                    time.sleep(wait)
                else:
                    return None
        return None

    def jitter(self):
        time.sleep(random.uniform(0.5, 2.0))

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        if url in visited or self.target_domain not in urlparse(url).netloc:
            return visited
        
        with print_lock:
            print(f"[*] Crawling: {url}")
        
        visited.add(url)
        res = self.safe_request('GET', url) # Using safe_request
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
            print(f"[*] Phase 1: Launching Nuclei templates against {target}")
        try:
            command = ["nuclei", "-u", target, "-tags", "xss", "-silent", "-jsonl"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line: continue
                try:
                    vuln_data = json.loads(line)
                    info = vuln_data.get("info", {})
                    severity = info.get("severity", "unknown").upper()
                    self._log_result(f"Nuclei {severity}", vuln_data.get("matched-at", "N/A"), "Vulnerable", vuln_data.get("matcher-name", "URL"))
                except: continue
            process.wait()
        except Exception as e:
            with print_lock: print(f"[-] Nuclei error: {e}")

    def launch_dalfox(self, target_url):
        local_findings = []
        with print_lock:
            print(f"[*] Phase 3: Sniper Mode - Dalfox analyzing {target_url}")
        dalfox_path = "/snap/bin/dalfox"
        command = f"{dalfox_path} url {target_url} --silence --no-color --no-spinner --format json"
        type_map = {"V": "Verified (DOM-based)", "R": "Reflected", "S": "Stored", "G": "Grep (Potential)"}
        
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line or line in ["[", "]"]: continue
                try:
                    vuln_data = json.loads(line.rstrip(','))
                    readable_type = type_map.get(vuln_data.get("type", "R"), "XSS")
                    finding = {"type": readable_type, "payload": vuln_data.get("poc", "N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param", "unknown")}
                    self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                    local_findings.append(finding)
                except: continue
            process.wait()
        except: pass
        return local_findings

    # Updated Stored mode using Dalfox sxss
    def scan_stored_dalfox(self, page_url):
        local_findings = []
        with print_lock:
            print(f"[*] Phase 4: Stored XSS Mode - Dalfox sxss on {page_url}")
        dalfox_path = "/snap/bin/dalfox"
        command = f"{dalfox_path} sxss {page_url} --trigger {page_url} -X POST --silence --no-color --format json"
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line or line in ["[", "]"]: continue
                try:
                    vuln_data = json.loads(line.rstrip(','))
                    finding = {"type": "Stored (Verified)", "payload": vuln_data.get("poc", "N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param", "unknown")}
                    self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                    local_findings.append(finding)
                except: continue
            process.wait()
        except: pass
        return local_findings

    def _log_result(self, xss_type, payload, status, param=None):
        if status == "Vulnerable" and payload and payload != "N/A":
            finding_sig = f"{xss_type}-{param}-{payload}"
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
                self.results.append(result)
                with print_lock:
                    print(f"[!] {xss_type} XSS FOUND: {payload} in parameter: {param}")

    def scan_page_workflow(self, page):
        findings = self.launch_dalfox(page)
        stored = self.scan_stored_dalfox(page)
        if stored: findings.extend(stored)
        return findings

def load_payloads():
    return ["<script>alert(1)</script>"] # Simplified for integration

def get_random_agent():
    user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"]
    return {"User-Agent": random.choice(user_agents)}

def main():
    start_time = time.perf_counter() 
    url = input("Enter Target URL: ").strip()
    scanner = XSSPayloadTester(url, load_payloads())

    scanner.run_nuclei_discovery(url)
    print("[*] Mapping site...")
    all_pages = scanner.crawl(url)
    
    vulnerability_log = []
    with ThreadPoolExecutor(max_workers=3) as executor: # Respecting your 3-thread limit
        futures = [executor.submit(scanner.scan_page_workflow, page) for page in all_pages]
        for future in futures:
            res = future.result()
            if res: vulnerability_log.extend(res)

    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds")

    # NEW: Generate Summary Table
    if vulnerability_log:
        counts = Counter(v['type'] for v in vulnerability_log)
        print("\n" + "="*30)
        print(f"{'VULNERABILITY SUMMARY':^30}")
        print("="*30)
        for v_type, count in counts.items():
            print(f"{v_type:<22} | {count:>5}")
        print("="*30)

        choice = input(f"\n[!] Save {len(vulnerability_log)} results? (y/n): ").strip().lower()
        if choice == 'y':
            with open("xss_scan_results.txt", "w") as f:
                f.write("--- SCAN SUMMARY ---\n")
                for v_type, count in counts.items():
                    f.write(f"{v_type}: {count}\n")
                f.write("\n--- DETAILED FINDINGS ---\n")
                for vuln in vulnerability_log:
                    f.write(f"Type: {vuln['type']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']}\n")
            print("[+] Results saved to xss_scan_results.txt")
    else:
        print("[-] No XSS vulnerabilities detected.")

if __name__ == "__main__":
    main()