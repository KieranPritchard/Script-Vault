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
from collections import Counter

# A Lock prevents threads from printing over each other
print_lock = Lock()

# Class to store XSS detection logic
class XSSPayloadTester:
    # initalises the class
    def __init__(self, target_url, payloads):
        self.target_url = target_url # Stores the target url
        self.payloads = payloads # Stores the payloads
        self.session = requests.Session() # Creates a new user session
        self.results = [] # Stores found vulnerabilities
        self.target_domain = urlparse(target_url).netloc # Stores the domain for crawling

    # Robust request handler to handle 'Connection Reset' at 5 threads
    def safe_request(self, method, url, **kwargs):
        retries = 3
        for i in range(retries):
            try:
                kwargs['headers'] = get_random_agent()
                kwargs['timeout'] = 10
                response = self.session.request(method, url, **kwargs)
                return response
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if i < retries - 1:
                    wait = (i + 1) * 2 + random.uniform(0, 1)
                    with print_lock:
                        print(f"[-] Connection error on {url}. Retrying in {wait:.2f}s...")
                    time.sleep(wait)
                else:
                    return None
        return None

    # Jitters the program to prevent detection from a WAF
    def jitter(self):
        # Sleeps for a random time
        time.sleep(random.uniform(0.5, 2.0))

    # Function to crawl the website
    def crawl(self, url, visited=None):
        # Checks if visited is none and sets it to a set
        if visited is None: visited = set()
        # Checks if the url is in the domain of the target
        if url in visited or self.target_domain not in urlparse(url).netloc:
            return visited
        
        with print_lock:
            print(f"[*] Crawling: {url}")
        
        visited.add(url)
        res = self.safe_request('GET', url) # Safe request for stability
        if not res: return visited

        try:
            # Creates soup object
            soup = BeautifulSoup(res.text, 'html.parser')
            # Loops over the link tags
            for link in soup.find_all('a', href=True):
                # Creates a full url
                full_url = urljoin(url, link['href']).split('#')[0]
                # Recursively call the crawl function
                self.crawl(full_url, visited)
        except: pass
        return visited

    # Method to run nuclei discovery
    def run_nuclei_discovery(self, target):
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei templates against {target}")
        try:
            # Captures vulnerabilities in real-time with JSONL
            command = ["nuclei", "-u", target, "-tags", "xss", "-severity", "medium,high,critical", "-silent", "-jsonl"]
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
            process.wait(timeout=300) # Ensure Nuclei doesn't hang forever
        except Exception as e:
            with print_lock: print(f"[-] Nuclei error: {e}")

    # Method to run dalfox reflected/dom scan with built-in WAF/Delay
    def launch_dalfox(self, target_url):
        local_findings = []
        with print_lock:
            print(f"[*] Phase 3: Sniper Mode - Dalfox analyzing {target_url}")
        dalfox_path = "/snap/bin/dalfox"
        # Optimized flags to prevent hanging
        command = f"{dalfox_path} url {target_url} --delay 100 --waf-evasion --skip-mining-all --silence --no-color --no-spinner --format json"
        type_map = {"V": "Verified (DOM-based)", "R": "Reflected", "S": "Stored", "G": "Grep (Potential)"}
        
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
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
                process.wait(timeout=60) # Kill process if it takes longer than 60s per page
            except subprocess.TimeoutExpired:
                process.kill()
        except: pass
        return local_findings

    # Method to scan stored xss using Dalfox's native sxss mode
    def scan_stored_dalfox(self, page_url):
        local_findings = []
        with print_lock:
            print(f"[*] Phase 4: Stored XSS Mode - Dalfox sxss on {page_url}")
        dalfox_path = "/snap/bin/dalfox"
        # Added --skip-mining-all to stop Dalfox from getting stuck in deep parameter analysis
        command = f"{dalfox_path} sxss {page_url} --trigger {page_url} -X POST --delay 100 --waf-evasion --skip-mining-all --silence --no-color --format json"
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                for line in iter(process.stdout.readline, ''):
                    line = line.strip()
                    if not line or line in ["[", "]"]: continue
                    try:
                        vuln_data = json.loads(line.rstrip(','))
                        finding = {"type": "Stored (Verified)", "payload": vuln_data.get("poc", "N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param", "unknown")}
                        self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                        local_findings.append(finding)
                    except: continue
                process.wait(timeout=90) # sxss takes longer, giving it 90s
            except subprocess.TimeoutExpired:
                process.kill()
        except: pass
        return local_findings

    # Method to log the result and prevent duplicates
    def _log_result(self, xss_type, payload, status, param=None):
        if status == "Vulnerable" and payload and payload != "N/A":
            finding_sig = f"{xss_type}-{param}-{payload}"
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
                self.results.append(result)
                with print_lock:
                    print(f"[!] {xss_type} XSS FOUND: {payload} in parameter: {param}")

    # Function to coordinate scanning for a specific page
    def scan_page_workflow(self, page):
        findings = self.launch_dalfox(page)
        stored = self.scan_stored_dalfox(page)
        if stored: findings.extend(stored)
        return findings

# Function to load the payloads
def load_payloads():
    payloads = ["<script>alert(1)</script>"]
    ua_path = "../../Resources/xss_payloads.txt"
    if os.path.exists(ua_path):
        with open(ua_path, "r") as f:
            payloads = [p.strip() for p in f if p.strip()]
    return payloads

# Function to get random user agent from folder
def get_random_agent():
    user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"]
    ua_path = "../../Resources/user_agent_strings.txt"
    if os.path.exists(ua_path):
        with open(ua_path, "r") as f:
            user_agents = [ua.strip() for ua in f if ua.strip()]
    return {"User-Agent": random.choice(user_agents)}

# Main entry point of the script
def main():
    start_time = time.perf_counter() 
    url = input("Enter Target URL: ").strip()
    all_payloads = load_payloads()
    scanner = XSSPayloadTester(url, all_payloads)

    # 1. Run Nuclei for quick wins
    scanner.run_nuclei_discovery(url)

    # 2. Map the site
    print("[*] Phase 2: Starting crawl to map the attack surface...")
    all_pages = scanner.crawl(url)
    print(f"[*] Discovery complete. Scanning {len(all_pages)} pages with 5 threads...")

    vulnerability_log = []
    # Using 5 threads
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scanner.scan_page_workflow, page) for page in all_pages]
        for future in futures:
            try:
                res = future.result()
                if res: vulnerability_log.extend(res)
            except: continue

    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds")

    # Generate Summary and Save Results
    if vulnerability_log:
        counts = Counter(v['type'] for v in vulnerability_log)
        print("\n" + "="*40)
        print(f"{'XSS VULNERABILITY SUMMARY':^40}")
        print("="*40)
        for v_type, count in counts.items():
            print(f"{v_type:<30} | {count:>5}")
        print("="*40)

        choice = input(f"\n[!] Total: {len(vulnerability_log)} findings. Save to file? (y/n): ").strip().lower()
        if choice == 'y':
            with open("xss_scan_results.txt", "w") as f:
                f.write(f"SCAN REPORT FOR {url}\n")
                f.write("-" * 40 + "\n")
                for v_type, count in counts.items():
                    f.write(f"{v_type}: {count}\n")
                f.write("-" * 40 + "\n\n")
                for vuln in vulnerability_log:
                    f.write(f"Type: {vuln['type']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']}\n")
            print("[+] Results saved to xss_scan_results.txt")
    else:
        print("[-] No XSS vulnerabilities detected.")

if __name__ == "__main__":
    main()