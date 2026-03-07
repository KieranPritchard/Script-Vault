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

def get_random_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
    ]
    return {"User-Agent": random.choice(agents)}

class XSSPayloadTester:
    def __init__(self, target_url, payloads):
        self.target_url = target_url
        self.payloads = payloads
        self.session = requests.Session()
        self.results = []
        self.results_lock = Lock()
        self.target_domain = urlparse(target_url).netloc
        self.dalfox_path = shutil.which("dalfox") or "/snap/bin/dalfox"

    def safe_request(self, method, url, **kwargs):
        try:
            kwargs['headers'] = get_random_agent()
            kwargs['timeout'] = 7
            return self.session.request(method, url, **kwargs)
        except Exception:
            return None

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        parsed_url = urlparse(url)
        if url in visited or self.target_domain not in parsed_url.netloc:
            return visited
        
        # Avoid static files
        if any(parsed_url.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.jpeg', '.woff', '.svg']):
            return visited

        with print_lock:
            print(f"[*] Crawling: {url}")
        
        visited.add(url)
        res = self.safe_request('GET', url)
        if not res or 'text/html' not in res.headers.get('Content-Type', ''): 
            return visited

        try:
            soup = BeautifulSoup(res.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href']).split('#')[0]
                self.crawl(full_url, visited)
        except Exception:
            pass
        return visited

    def run_nuclei_discovery(self, target):
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei against {target}")
        try:
            command = ["nuclei", "-u", target, "-tags", "xss", "-severity", "medium,high,critical", "-silent", "-jsonl"]
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, _ = proc.communicate(timeout=180)
                for line in stdout.splitlines():
                    try:
                        vuln_data = json.loads(line)
                        self._log_result(
                            f"Nuclei-{vuln_data.get('info', {}).get('severity', '').upper()}", 
                            vuln_data.get("matched-at"), 
                            "Vulnerable", 
                            vuln_data.get("matcher-name")
                        )
                    except Exception: continue
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception: pass

    def launch_dalfox(self, target_url):
        local_findings = []
        command = [self.dalfox_path, "url", target_url, "--delay", "50", "--waf-evasion", "--skip-mining-all", "--silence", "--no-color", "--no-spinner", "--format", "json"]
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, _ = proc.communicate(timeout=60)
                for line in stdout.splitlines():
                    clean_line = line.strip().rstrip(',')
                    if not clean_line or clean_line in ["[", "]"]: continue
                    try:
                        vuln_data = json.loads(clean_line)
                        finding = {"type": "Dalfox-"+vuln_data.get("type", "R"), "payload": vuln_data.get("poc", "N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param", "unknown")}
                        self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                        local_findings.append(finding)
                    except Exception: continue
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception: pass
        return local_findings

    def scan_stored_dalfox(self, page_url):
        local_findings = []
        command = [self.dalfox_path, "sxss", page_url, "--trigger", page_url, "-X", "POST", "--delay", "50", "--skip-mining-all", "--silence", "--no-color", "--format", "json"]
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, _ = proc.communicate(timeout=60)
                for line in stdout.splitlines():
                    clean_line = line.strip().rstrip(',')
                    if not clean_line or clean_line in ["[", "]"]: continue
                    try:
                        vuln_data = json.loads(clean_line)
                        finding = {"type": "Stored (Verified)", "payload": vuln_data.get("poc", "N/A"), "status": "Vulnerable", "parameter": vuln_data.get("param", "unknown")}
                        self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                        local_findings.append(finding)
                    except Exception: continue
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception: pass
        return local_findings

    def _log_result(self, xss_type, payload, status, param=None):
        if status == "Vulnerable" and payload and payload != "N/A":
            finding_sig = f"{xss_type}-{param}-{payload}"
            with self.results_lock:
                if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                    result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
                    self.results.append(result)
                    with print_lock:
                        print(f"[!] {xss_type} FOUND on param: {param}")

    def scan_page_workflow(self, page):
        findings = self.launch_dalfox(page)
        stored = self.scan_stored_dalfox(page)
        if stored: findings.extend(stored)
        return findings

def main():
    start_time = time.perf_counter() 
    url = input("Enter Target URL (e.g., http://testphp.vulnweb.com): ").strip()
    if not url.startswith("http"):
        print("Invalid URL format.")
        return

    scanner = XSSPayloadTester(url, [])
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
    print(f"[*] Deduplicated {len(raw_pages)} down to {len(scan_list)} unique target paths.")

    vulnerability_log = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scanner.scan_page_workflow, page): page for page in scan_list}
        for future in futures:
            try:
                res = future.result()
                if res: vulnerability_log.extend(res)
            except Exception as e:
                continue

    elapsed = time.perf_counter() - start_time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds. Total unique hits: {len(scanner.results)}")

    if scanner.results:
        counts = Counter(v['type'] for v in scanner.results)
        print("\n" + "="*45)
        print(f"{'Vulnerability Type':<30} | {'Count':>5}")
        print("-" * 45)
        for v_type, count in counts.items():
            print(f"{v_type:<30} | {count:>5}")
        print("="*45)

if __name__ == "__main__":
    main()