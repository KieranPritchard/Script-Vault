import requests
import time
import random
import subprocess
import os
import json
import uuid # Added to support unique canary generation for stored XSS
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

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
        
        # Logs the output for notifying 
        with print_lock:
            print(f"[*] Crawling: {url}")
        
        # Adds url to visited
        visited.add(url)

        try:
            # sends a get request to the url
            res = self.session.get(url, headers=get_random_agent(), timeout=5)
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
        # Outputs that Nuclei is starting
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei templates against {target}")
        
        try:
            # -jsonl allows us to parse each finding as a dictionary
            # -severity medium,high,critical filters out the 'info' noise
            command = ["nuclei", "-u", target, "-tags", "xss", "-silent", "-jsonl"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line: continue
                
                try:
                    vuln_data = json.loads(line)
                    info = vuln_data.get("info", {})
                    severity = info.get("severity", "unknown").upper()
                    template_id = vuln_data.get("template-id", "N/A")
                    
                    # Determine if it's Reflected or DOM based on template tags/id
                    xss_type = "Reflected"
                    if "dom" in template_id.lower() or "dom" in str(info.get("tags", "")).lower():
                        xss_type = "DOM-based"
                    
                    # Log to the internal result list
                    self._log_result(
                        xss_type=f"Nuclei {severity} ({xss_type})",
                        payload=vuln_data.get("matched-at", "N/A"),
                        status="Vulnerable",
                        param=vuln_data.get("matcher-name", "URL/Endpoint")
                    )
                except json.JSONDecodeError:
                    # Catch non-JSON status messages if any
                    continue
            
            process.wait()
        except FileNotFoundError:
            with print_lock:
                print("[-] Nuclei not found. Skipping Phase 1.")
        except Exception as e:
            with print_lock:
                print(f"[-] Nuclei execution error: {e}")

    def launch_dalfox(self, target_url):
        local_findings = []
        with print_lock:
            print(f"[*] Phase 3: Sniper Mode - Dalfox analyzing {target_url}")
        
        dalfox_path = "/snap/bin/dalfox"
        command = f"{dalfox_path} url {target_url} --silence --no-color --no-spinner --format json"
        
        # Mapping shorthand to readable types
        type_map = {
            "V": "Verified (DOM-based)",
            "R": "Reflected",
            "S": "Stored",
            "G": "Grep (Potential)"
        }
        
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line or line in ["[", "]"]: continue
                
                # Clean trailing commas and brackets that Dalfox adds in array mode
                clean_line = line.rstrip(',').rstrip(']')
                
                try:
                    vuln_data = json.loads(clean_line)
                    
                    # Extract the payload and determine type
                    raw_type = vuln_data.get("type", "R")
                    readable_type = type_map.get(raw_type, f"XSS ({raw_type})")
                    payload = vuln_data.get("poc") or vuln_data.get("data") or "N/A"
                    
                    if payload != "N/A":
                        finding = {
                            "type": readable_type,
                            "payload": payload,
                            "status": "Vulnerable",
                            "parameter": vuln_data.get("param", "unknown")
                        }
                        
                        # Log it globally and locally
                        self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                        local_findings.append(finding)
                except json.JSONDecodeError:
                    continue 
            
            process.wait()
            return local_findings
        except Exception as e:
            with print_lock:
                print(f"[-] Dalfox execution error: {e}")
            return []

    # Method to scan stored xss using a Canary-Mapping technique for speed and accuracy
    def scan_stored_custom(self, page_url, all_pages):
        # We use a unique Canary to identify where data submitted here appears on the rest of the site
        canary_id = f"STORED_CHECK_{uuid.uuid4().hex[:4]}"
        with print_lock:
            print(f"[*] Phase 4: Stored XSS Mode - Mapping {page_url} across site surface")
        
        local_stored_findings = []
        try:
            # First, we try to plant the Canary in any forms found on the page
            res = self.session.get(page_url, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = urljoin(page_url, form.get('action'))
                method = form.get('method', 'get').lower()
                # Fill every input and textarea with our unique Canary
                data = {i.get('name'): canary_id for i in form.find_all(['input', 'textarea']) if i.get('name')}
                
                if method == 'post':
                    self.session.post(action, data=data, timeout=5)
                else:
                    self.session.get(action, params=data, timeout=5)

            # Verification step: Check all previously crawled pages for our Canary
            for check_page in all_pages:
                verify_res = self.session.get(check_page, timeout=5)
                if canary_id in verify_res.text:
                    finding = {
                        "type": "Stored XSS (Verified)",
                        "payload": f"Canary found at {check_page}",
                        "status": "Vulnerable",
                        "parameter": "Form-Data"
                    }
                    # Log globally and locally
                    self._log_result(finding["type"], finding["payload"], "Vulnerable", finding["parameter"])
                    local_stored_findings.append(finding)
            
            return local_stored_findings
        except Exception as e:
            with print_lock:
                print(f"[-] Stored custom execution error: {e}")
            return []

    # Function to coordinate scanning for a specific page - FIXED to pass all_pages context
    def scan_page_workflow(self, page, all_pages):
        # Starts the sniper tools for Reflected/DOM
        findings = self.launch_dalfox(page)
        # Runs the native custom stored check and adds to the total findings for this page
        stored_findings = self.scan_stored_custom(page, all_pages)
        if stored_findings:
            findings.extend(stored_findings)
        return findings

    # Method to log the result
    def _log_result(self, xss_type, payload, status, param=None):
        # Only log confirmed vulnerabilities with valid payloads
        if status == "Vulnerable" and payload and payload != "N/A":
            # Check for duplicates to prevent the massive log spam
            finding_sig = f"{xss_type}-{param}-{payload}"
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == finding_sig for r in self.results):
                # Builds the result object
                result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
                # Adds the result to results
                self.results.append(result)
                # Uses the lock to prevent messy console output
                with print_lock:
                    # Outputs the found vulnerability
                    print(f"[!] {xss_type} XSS FOUND: {payload} in parameter: {param}")

# Function to load the payloads
def load_payloads():
    # Fallback if file missing
    payloads = ["<script>alert(1)</script>"]
    ua_path = "../../Resources/xss_payloads.txt"
    if os.path.exists(ua_path):
        # Opens the file
        with open(ua_path, "r") as f:
            # Reads in the payloads
            payloads = [p.strip() for p in f if p.strip()]
    # Returns the payloads
    return payloads

# Function to get random user agent from folder
def get_random_agent():
    # Fallback agents if file is missing
    user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"]
    # Path to the user agent file
    ua_path = "../../Resources/user_agent_strings.txt"
    
    if os.path.exists(ua_path):
        try:
            # Opens the file
            with open(ua_path, "r") as f:
                user_agents = [ua.strip() for ua in f if ua.strip()]
        except Exception as e:
            with print_lock:
                print(f"[-] Error reading user agents: {e}")

    # Returns the headers with a random agent
    return {"User-Agent": random.choice(user_agents)}

# Main entry point of the script
def main():
    # Logs the starting time
    start_time = time.perf_counter() 

    # Allows the user to enter in a url to scan
    url = input("Enter Target URL: ").strip()
    
    # Pre-loads payloads
    all_payloads = load_payloads()
    
    # Initialises the Automator class
    scanner = XSSPayloadTester(url, all_payloads)

    # 1. Run Nuclei for quick wins
    scanner.run_nuclei_discovery(url)

    # 2. Map the site
    print("[*] Starting crawl to map the attack surface...")
    # We convert the crawl results to a list to ensure stable iteration during scanning
    all_pages = list(scanner.crawl(url))
    
    # Outputs discovery is complete
    print(f"[*] Discovery complete. Scanning {len(all_pages)} pages with Sniper tools...")

    # Stores all vulnerabilities found across all threads
    vulnerability_log = []

    # Creates the thread pool executor
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Maps the workflow to the all_pages list, passing both page and the full all_pages list
        futures = [executor.submit(scanner.scan_page_workflow, page, all_pages) for page in all_pages]
        
        # Collects results as threads finish
        for future in futures:
            try:
                # Gets the list of findings
                result = future.result()
                # Checks if findings exist
                if result:
                    # Adds findings to the log
                    vulnerability_log.extend(result)
            except Exception as e:
                with print_lock:
                    print(f"[-] Thread execution error: {e}")

    # Calculates the elapsed time
    elapsed = time.perf_counter() - start_time

    # Outputs completion time
    print(f"\n[✓] Finished in {elapsed:.2f} seconds")

    # Checks if any vulnerabilities were found
    if vulnerability_log:
        # Prompts to save
        choice = input(f"\n[!] Found {len(vulnerability_log)} vulnerabilities. Save results? (y/n): ").strip().lower()
        # Checks if the choice is yes
        if choice == 'y':
            # Opens file to write
            with open("xss_scan_results.txt", "w") as f:
                # Loops over the vulnerability
                for vuln in vulnerability_log:
                    # Writes vulnerability details to file
                    f.write(f"Type: {vuln['type']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']}\n")
            # Outputs the file was saved
            print("[+] Results saved to xss_scan_results.txt")
    else:
        # Outputs no vulnerabilities found
        print("[-] No XSS vulnerabilities detected.")

# Starts the program
if __name__ == "__main__":
    main()