import requests
import time
import random
import subprocess
import os
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
            # Runs nuclei focusing on xss tags
            subprocess.run(["nuclei", "-u", target, "-tags", "xss", "-silent"], check=False)
        except FileNotFoundError:
            # Outputs nuclei not found
            print("[-] Nuclei not found.")

    def launch_dalfox(self, target_url):
        with print_lock:
            print(f"[*] Phase 3: Sniper Mode - Dalfox analyzing {target_url}")
        
        dalfox_path = "/snap/bin/dalfox"
        
        # We add --format json so we can read the results programmatically
        command = f"{dalfox_path} url {target_url} --silence --no-color --no-spinner --format json"
        
        try:
            # capture_output=True allows us to read what Dalfox found
            process = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
            
            # If Dalfox found something, it will be in the stdout
            if process.stdout:
                for line in process.stdout.splitlines():
                    try:
                        import json
                        vuln_data = json.loads(line)
                        # Log it into our main results list
                        self._log_result(
                            xss_type=vuln_data.get("type", "Reflected/DOM"),
                            payload=vuln_data.get("poc", "N/A"),
                            status="Vulnerable",
                            param=vuln_data.get("param", "N/A")
                        )
                    except:
                        continue # Skip non-json lines
        except Exception as e:
            with print_lock:
                print(f"[-] Dalfox execution error: {e}")

    # Method to scan the stored xss logic
    def scan_stored_custom(self, page_url):
        # Tries to find forms on the page
        try:
            res = self.session.get(page_url, headers=get_random_agent(), timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            # Loops over forms found
            for form in soup.find_all("form", method="post"):
                action = urljoin(page_url, form.get("action"))
                # Loops over inputs in the form
                for input_tag in form.find_all(["input", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        # Uses a simple payload for custom stored check
                        payload = self.payloads[0] if self.payloads else "<script>alert(1)</script>"
                        self.session.post(action, data={name: payload}, headers=get_random_agent())
                        # Re-visits the page to check for reflection
                        check_res = self.session.get(page_url, headers=get_random_agent())
                        if payload in check_res.text:
                            self._log_result("Stored", payload, "Vulnerable", name)
        except: pass

    # Method to log the result
    def _log_result(self, xss_type, payload, status, param=None):
        # Builds the result object
        result = {"type": xss_type, "payload": payload, "status": status, "parameter": param}
        # Adds the result to results
        self.results.append(result)
        # Checks if status is vulnerable
        if status == "Vulnerable":
            # Uses the lock to prevent messy console output
            with print_lock:
                # Outputs the found vulnerability
                print(f"[!] {xss_type} XSS FOUND: {payload} in parameter: {param}")

    # Function to coordinate scanning for a specific page
    def scan_page_workflow(self, page):
        # Starts the sniper tools
        self.launch_dalfox(page)
        self.scan_stored_custom(page)
        return self.results

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
        # Opens the file
        with open(ua_path, "r") as f:
            # Extracts the user agents as a list
            user_agents = [ua.strip() for ua in f if ua.strip()]

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
    all_pages = scanner.crawl(url)
    
    # Outputs discovery is complete
    print(f"[*] Discovery complete. Scanning {len(all_pages)} pages with Sniper tools...")

    # Stores all vulnerabilities found across all threads
    vulnerability_log = []

    # Creates the thread pool executor
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Maps the workflow to the all_pages list
        futures = [executor.submit(scanner.scan_page_workflow, page) for page in all_pages]
        
        # Collects results as threads finish
        for future in futures:
            # Gets the list of findings
            result = future.result()
            # Checks if findings exist
            if result:
                # Adds findings to the log
                vulnerability_log.extend(result)

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