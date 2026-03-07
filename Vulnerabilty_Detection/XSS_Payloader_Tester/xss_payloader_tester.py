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
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ]
    return {"User-Agent": random.choice(agents)}

class XSSPayloadTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        self.results_lock = Lock()
        self.target_domain = urlparse(target_url).netloc
        # Auto-detect tool paths
        self.dalfox = shutil.which("dalfox")
        self.nuclei = shutil.which("nuclei")
        
        if not self.dalfox or not self.nuclei:
            print("[!] WARNING: dalfox or nuclei not found in PATH. Results will be limited.")

    def safe_request(self, method, url, **kwargs):
        try:
            kwargs.setdefault('headers', get_random_agent())
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('allow_redirects', True)
            return self.session.request(method, url, **kwargs)
        except Exception:
            return None

    def crawl(self, url, visited=None):
        if visited is None: visited = set()
        parsed = urlparse(url)
        if url in visited or self.target_domain not in parsed.netloc:
            return visited
        
        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.woff', '.svg']):
            return visited

        with print_lock: print(f"[*] Crawling: {url}")
        visited.add(url)
        
        res = self.safe_request('GET', url)
        if not res or 'text/html' not in res.headers.get('Content-Type', ''):
            return visited

        try:
            soup = BeautifulSoup(res.text, 'html.parser')
            # Follow links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href']).split('#')[0]
                self.crawl(full_url, visited)
            
            # Identify forms - crucial for "hits"
            forms = soup.find_all('form')
            if forms:
                with print_lock: print(f"    [+] Found {len(forms)} form(s) on {url}")
        except Exception: pass
        return visited

    def run_nuclei(self, target):
        if not self.nuclei: return
        with print_lock: print(f"[*] Launching Nuclei (Headless) against {target}...")
        try:
            # -headless is critical for modern XSS discovery
            cmd = [self.nuclei, "-u", target, "-tags", "xss", "-headless", "-severity", "medium,high,critical", "-silent", "-jsonl"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = proc.communicate(timeout=300)
            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    self._log_result(f"Nuclei-{data.get('info',{}).get('severity','').upper()}", data.get("matched-at"), "Vulnerable", data.get("matcher-name"))
                except: continue
        except Exception as e:
            with print_lock: print(f"[-] Nuclei Error: {e}")

    def run_dalfox(self, target):
        if not self.dalfox: return
        with print_lock: print(f"[*] Launching Dalfox against {target}...")
        try:
            # Added --mining-dict and --deep-dom for better coverage
            cmd = [self.dalfox, "url", target, "--delay", "100", "--waf-evasion", "--no-color", "--format", "json", "--silence"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = proc.communicate(timeout=120)
            for line in stdout.splitlines():
                line = line.strip().rstrip(',')
                if not line or line in ["[", "]"]: continue
                try:
                    data = json.loads(line)
                    self._log_result("Dalfox-"+data.get("type", "R"), data.get("poc"), "Vulnerable", data.get("param"))
                except: continue
        except Exception as e:
            with print_lock: print(f"[-] Dalfox Error: {e}")

    def _log_result(self, xtype, payload, status, param):
        sig = f"{xtype}-{param}-{payload}"
        with self.results_lock:
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == sig for r in self.results):
                self.results.append({"type": xtype, "payload": payload, "status": status, "parameter": param})
                with print_lock:
                    print(f"[!] {xtype} DETECTED! Parameter: {param}")

def main():
    target = input("Target URL (e.g. http://testphp.vulnweb.com): ").strip()
    if not target.startswith("http"): return print("Invalid URL.")

    scanner = XSSPayloadTester(target)
    
    # Pre-check tools
    if scanner.nuclei:
        subprocess.run([scanner.nuclei, "-ut"], capture_output=True) # Update templates
    
    print("[*] Phase 1: Global Discovery...")
    scanner.run_nuclei(target)
    
    print("[*] Phase 2: Crawling and Deep Scanning...")
    pages = scanner.crawl(target)
    
    # Filter unique paths for Dalfox to avoid redundant work
    unique_targets = {}
    for p in pages:
        parsed = urlparse(p)
        sig = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
        if sig not in unique_targets: unique_targets[sig] = p

    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(scanner.run_dalfox, unique_targets.values())

    print(f"\n[✓] Scan complete. Total unique hits: {len(scanner.results)}")
    if scanner.results:
        print("\nSummary of Findings:")
        for t, c in Counter(r['type'] for r in scanner.results).items():
            print(f" - {t}: {c}")

if __name__ == "__main__":
    main()