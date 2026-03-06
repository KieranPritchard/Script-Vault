import requests
import time
import random
import subprocess
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
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
            res = self.session.get(url, timeout=5)
            # Creates soup object
            soup = BeautifulSoup(res.text, 'html.parser')
            # Loops over the link tags
            for link in soup.find_all('a', href=True):
                # Greates a full url
                full_url = urljoin(url, link['href']).split('#')[0]
                # Recursivly call the crawk function
                self.crawl(full_url, visited)
        except: pass
        return visited

    # Method to run nuclei discovery
    def run_nuclei_discovery(self):
        # Outputs that Nuclei is starting
        with print_lock:
            print(f"[*] Phase 1: Launching Nuclei templates against {self.target_url}")
        
        try:
            # Runs nuclei focusing on xss tags
            subprocess.run(["nuclei", "-u", self.target_url, "-tags", "xss", "-silent"], check=False)
        except FileNotFoundError:
            # Outputs nucli not found
            print("[-] Nuclei not found.")

    # Method to run dalfox discovery
    def launch_dalfox(self, target_url):
        # Outputs that Dalfox is starting
        with print_lock:
            print(f"[*] Phase 3: Sniper Mode - Dalfox analyzing {target_url}")
        
        # Runs dalfox with headless browser verification
        try:
            subprocess.run(["dalfox", "url", target_url, "--silence", "--skip-bmining-all"], check=False)
        except FileNotFoundError:
            # Outputs error message
            print("[-] Dalfox not found.")

    # Method to scan the stored xss
    def scan_stored(self, post_path, view_path, form_data_key):
        post_url = urljoin(self.target_url, post_path) # Stores the url to post to
        view_url = urljoin(self.target_url, view_path) # Stores the view url
        
        # Loops over the payload in payloads
        for payload in self.payloads:
            try:
                # Posts the data to the url
                self.session.post(post_url, data={form_data_key: payload}, headers=get_random_agent())
                # Gets the response from the viewing page
                res = self.session.get(view_url, headers=get_random_agent())
                # Checks if the payload in the response
                if payload in res.text:
                    # Logsts the result
                    self._log_result("Stored", payload, "Vulnerable", form_data_key)
            except: continue

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

    # Function to run the scanning logic for the page
    def run(self):
        # Gets all potential injection points
        target_inputs = self.get_all_inputs()
        
        # Filters inputs for reflected testing (GET and URL params)
        reflected_targets = [i for i in target_inputs if i['method'] == 'get']
        # Runs the reflected scan
        self.scan_reflected(reflected_targets)
        
        # Runs the DOM scan (optional fragment trigger)
        self.scan_dom()
        
        # Checks for POST forms to test stored XSS
        for item in target_inputs:
            if item['method'] == 'post':
                # Runs stored scan assuming post and view are on same url
                self.scan_stored(item['action'], self.target_url, item['name'])

        # Returns the list of findings
        return self.results

# Function to load the payloads
def load_payloads():
    # Opens the file
    with open("../../Resources/xss_payloads.txt", "r") as f:
        # Reads in the payloads
        payloads = f.readlines()

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

# Function to crawl a website and map all pages
def crawl_website(url, domain, visited=None):
    # Checks if visited is none
    if visited is None:
        # Creates a new set for visited
        visited = set()

    # Makes it stay within the same domain and avoid re-visiting pages
    if url in visited or domain not in urlparse(url).netloc:
        # Returns visited
        return visited

    # Outputs the url which is being visited
    with print_lock:
        print(f"[*] Crawling: {url}")
    
    # Adds the url to the set
    visited.add(url)

    try:
        # Gets a response from the page
        response = requests.get(url, headers=get_random_agent(), timeout=5)
        # Creates new beautiful soup object to parse the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Finds all 'a' tags with an 'href' attribute
        for link in soup.find_all('a', href=True):
            # Resolve relative URLs
            full_url = urljoin(url, link['href']).split('#')[0]
            # Recursive call to traverse the next page
            crawl_website(full_url, domain, visited)

    # Catches the error
    except: pass

    # Returns visited
    return visited

# Function to be executed by the threads
def scan_page(page, payloads):
    # Locks the print function to prevent jumbled text
    with print_lock:
        # Outputs the page being scanned
        print(f"--- Scanning Page: {page} ---")
    
    # Runs the XSS scanner
    scanner = XSSPayloadTester(page, payloads)
    # Returns the list of vulnerabilities found for this page
    return scanner.run()

# Main entry point of the script
def main():
    # Logs the starting time
    start_time = time.perf_counter() 

    # Allows the user to enter in a url to scan
    url = input("Enter Target URL: ").strip()
    # Extracts the domain name
    target_domain = urlparse(url).netloc
    
    # Outputs that crawling has started
    print("[*] Starting crawl to map the attack surface...")
    # Stores all of the pages found
    all_pages = crawl_website(url, target_domain)
    
    # Outputs discovery is complete
    print(f"[*] Discovery complete. Scanning {len(all_pages)} pages for XSS...")

    # Stores all vulnerabilities found across all threads
    vulnerability_log = []

    # Creates the thread pool executor
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Maps the scan_page function to the all_pages list
        futures = [executor.submit(scan_page, page, load_payloads()) for page in all_pages]
        
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
                # Loops over the vulnerabity
                for vuln in vulnerability_log:
                    # Writes vulnerability details to file
                    f.write(f"Type: {vuln['type']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']}\n")
            # Outputs the file was say
            print("[+] Results saved to xss_scan_results.txt")
    else:
        # Outputs no vulnerabilities found
        print("[-] No XSS vulnerabilities detected.")

# Starts the program
if __name__ == "__main__":
    main()