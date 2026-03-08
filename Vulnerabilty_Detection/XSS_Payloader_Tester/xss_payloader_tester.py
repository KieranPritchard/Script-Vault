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

# Creates the object for the print lock
print_lock = Lock()

# Global tuning knobs for performance and stealth
MAX_SCAN_TARGETS = 60          # Max URLs that will be sent to Dalfox (None = scan everything we find)
MAX_DALFOX_THREADS = 5         # How many Dalfox processes we run at the same time from Python
DALFOX_WORKERS = 10            # How many internal workers Dalfox itself uses per scan
DALFOX_DELAY = 2               # Delay in seconds Dalfox waits between its requests (higher = stealthier)
DALFOX_TIMEOUT = 8             # Per-request timeout Dalfox uses when talking to the target

# Class to store the detection logic
class XSSDetection:
    def __init__(self, target_url):
        self.target_url = target_url # Stores the target url
        self.session = requests.Session() # Stores the session
        self.results = [] # Stores the results
        self.results_lock = Lock() # Creates a lock for the results
        self.target_domain = urlparse(target_url).netloc # Sets the target domain
        
        # Locate binaries
        self.dalfox_path = shutil.which("dalfox") or os.path.expanduser("~/go/bin/dalfox")

    # Method to craft the headers
    def get_headers(self):
        # Returns a header
        return {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    # Method of crawl the website
    def crawl(self, url, visited=None):
        # Checks if visited is none and sets the visited to a set
        if visited is None: visited = set()
        # Parses the url
        parsed = urlparse(url)
        # Checks if the url is visited or the domain is not in parsed
        if url in visited or self.target_domain not in parsed.netloc:
            # Returns visited
            return visited
        # Checks for if any of the extentions are 
        if any(parsed.path.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.woff', '.svg']):
            # Returns visited
            return visited

        # Outputs the page being crawled
        with print_lock:
            print(f"[*] Crawling: {url}")
        # Adds the url to visited
        visited.add(url)

        try:
            # Gets the response to the url 
            res = self.session.get(url, headers=self.get_headers(), timeout=7)
            # Checks if the status code is 200 and is html page
            if res.status_code == 200 and 'text/html' in res.headers.get('Content-Type', ''):
                # Creates a soup object
                soup = BeautifulSoup(res.text, 'html.parser')
                # Loops over the link tags
                for link in soup.find_all('a', href=True):
                    # Creates a new url and crawls recursivley
                    full_url = urljoin(url, link['href']).split('#')[0]
                    self.crawl(full_url, visited)
        # Passs an exception
        except: pass
        # Returns visited
        return visited

    # Method to run dalfox
    def run_dalfox(self, target_url):
        # Checks if dalfox path exists
        if not os.path.exists(str(self.dalfox_path)): return

        # Creates the scan url if there is a parameter in it
        # If there are no params, we add some generic ones so Dalfox still has injection points
        scan_url = target_url if "?" in target_url else target_url + "?id=1&q=test"
        
        # Stores the commands for stored and reflected checks so we can loop over them
        commands = [
            # General URL Scan
            [
                self.dalfox_path, "url", scan_url, 
                "--worker", str(DALFOX_WORKERS),
                "--delay", str(DALFOX_DELAY),
                "--timeout", str(DALFOX_TIMEOUT),
                "--skip-bav",
                "--mining-dict",             # Thorough: search for hidden parameters
                "--mining-dom",              # Thorough: check DOM-based XSS
                "--waf-evasion",             # Evades the fireware
                "--silence", "--no-color", "--format", "json"
            ],
            # Stored XSS Scan
            [
                self.dalfox_path, "sxss", scan_url, 
                "--trigger", scan_url, 
                "--worker", str(DALFOX_WORKERS),
                "--delay", str(DALFOX_DELAY),
                "--timeout", str(DALFOX_TIMEOUT),
                "--skip-bav",
                "--silence", "--no-color", "--format", "json"
            ]
        ]

        # Loops over the commands in commands so every target URL gets both checks
        for cmd in commands:
            try:
                # Creates a new subprocess to pip the content into the script
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                # Sets the timeout to 180 seconds
                stdout, _ = proc.communicate(timeout=180)
                # Loops over the lines in the output
                for line in stdout.splitlines():
                    # Cleans the line
                    clean_line = line.strip().rstrip(',')
                    # Checks if the clean line as detected a hit
                    if clean_line.startswith('{'):
                        try:
                            # Converts the data to a json format
                            data = json.loads(clean_line)
                            # Searches for the raw proof of concept
                            poc_raw = data.get("poc") or data.get("evidence") or data.get("injection_point") or data.get("url")
                            # Extracts the proof of concept
                            poc = unquote(str(poc_raw)) if poc_raw else "Manual Verification Required"
                            
                            # Extracts the verification type
                            v_type = f"Dalfox-{data.get('type', 'Unknown')}"
                            # Checks if the stored xss was used
                            if "sxss" in cmd: v_type = "Stored-XSS"
                            # Logs the results
                            self._log_result(v_type, scan_url, poc, "Vulnerable", data.get("param", "url-path"))
                        # Passes the exception
                        except: pass
            # Passes the exception
            except: pass

    # Method to log result
    def _log_result(self, xtype, url, payload, status, param):
        # Logs the signature
        sig = f"{xtype}-{url}-{param}-{payload}"
        # Uses the results lock to log the data
        with self.results_lock:
            # Checks if the data is not incomplete
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == sig for r in self.results):
                # Stores the entry
                res_entry = {"type": xtype, "url": url, "parameter": param, "payload": payload, "status": status}
                # Adds the entry to 
                self.results.append(res_entry)
                # Outputs the found data
                with print_lock:
                    print(f"\n[!] {xtype} DETECTED!")
                    print(f"    Param: {param}")
                    print(f"    PoC: {payload}\n")

    # Method to save results to csv
    def save_results_to_csv(self, filename="xss_results.csv"):
        # Checks for results
        if not self.results:
            print("[!] No vulnerabilities found to export.")
            return
        # Creates the keys
        keys = ["type", "url", "parameter", "payload", "status"]
        # Opens the file to rewrite data
        with open(filename, 'w', newline='') as f:
            # Writes the data to the field names
            writer = csv.DictWriter(f, fieldnames=keys)
            # Writes the header
            writer.writeheader()
            # Writes the rows from results
            writer.writerows(self.results)
        # Outputs the result is saved
        print(f"[✓] Final report saved to {filename}")

def main():
    # ALlows the target to be inputted
    target = input("[+] Enter Target URL: ").strip()
    # Does some validation
    if not target.startswith("http"): return
    
    # Starts the timeer and loads the target into the scanner
    start_time = time.perf_counter()
    scanner = XSSDetection(target)
    

    print(f"\n[+] Crawling {target}")
    
    # Stores the discovered urls from the target
    discovered_urls = scanner.crawl(target)
    
    # Stores the unique paths found
    unique_paths = {}
    # Loops over the paths discovered
    for url in discovered_urls:
        # Normalises by path only so the same file with different params isn't crawled over and over
        p = urlparse(url)

        # Checks if the path is not in the unique variable
        if p.path not in unique_paths: 
            # Adds the path to the unquie paths path
            unique_paths[p.path] = url
    
    # Converts the paths values into a list
    all_targets = list(unique_paths.values())
    # Prioritise URLs that already have query parameters (higher XSS value, fewer total scans)
    param_urls = [url for url in all_targets if "?" in url] # Extracts the urls with parameters so they go first
    non_param_urls = [u for u in all_targets if "?" not in u] # Then gets the non parameter oens 
    # Creates an ordered list of urls
    ordered = param_urls + non_param_urls
    # Lowers the amount of urls if they are over the maxinum number of targets
    scan_list = ordered[:MAX_SCAN_TARGETS] if MAX_SCAN_TARGETS is not None else ordered
    # Prints the unique information
    print(f"[✓] Found {len(all_targets)} unique paths, selecting {len(scan_list)} for Dalfox scanning.")

    # Outputs the scan has started
    print("\n[+] Running Dalfox scan")
    # max_workers kept low to reduce noisy traffic patterns
    with ThreadPoolExecutor(max_workers=MAX_DALFOX_THREADS) as executor:
        # Runs the exceutor scan
        executor.map(scanner.run_dalfox, scan_list)

    # Saves the results to csv
    scanner.save_results_to_csv()
    
    # Calculates the elaspsed time
    elapsed = time.perf_counter() - start_time
    # Outputs the final infromation
    print(f"\n[✓] Scan Complete in {elapsed:.2f} seconds.")
    print(f"[✓] Total unique vulnerabilities found: {len(scanner.results)}")

# Starts the program
if __name__ == "__main__":
    main()