import requests
import time
import random
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
            # Gets the response from the page with the payload
            response = self.session.get(self.target_url + payload, headers=get_random_agent(), timeout=10)
            # Loops over the signatures in the errors list
            for signature in self.errors_sigatures:
                # Checks if the signature is in the response text
                if signature in response.text.lower():
                    return f"[!] VULNERABLE: Error-based found with payload: {payload}"
    
        # Returns none if nothing was found
        return None
    
    # Checks for boolean based injection
    def check_boolean_based(self):
        # Outputs testing for boolean based sqli
        print("[*] Testing for Boolean-based SQLi...")
        # Loops over the payloads in the boolean payloads
        for payload in self.payloads["boolean"]:
            # Stores the true and false response
            res_true = self.session.get(self.target_url + payload["true"])
            res_false = self.session.get(self.target_url + payload["false"])
            
            # If the "True" payload matches the baseline but "False" doesn't, it's vulnerable
            if len(res_true.content) != len(res_false.content):
                # Checks if the content is the same
                if len(res_true.content) == len(self.baseline_content):
                    # Returns the payload which was found
                    return f"[!] VULNERABLE: Boolean-based found with {payload['true']}"
        # Returns false
        return None

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