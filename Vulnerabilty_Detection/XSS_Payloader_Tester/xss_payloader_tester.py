import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

# Class to store payload tester logic
class XSSPayloadTester:
    # initalises the class
    def __init__(self, target_url, payloads):
        self.target_url = target_url # Stores the target url
        self.payloads = payloads # Stores the payloads
        self.session = requests.Session() # Creates a new user session
        self.results = []

    # Method to get all of the inputs on a page
    def get_all_inputs(self,):
        # Trys to get the inputs
        try:
            # gets the response of the targer url
            res = requests.get(self.target_url)

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
                inputs.append({"type": "url", "name": param, "method": "GET"})

            # Extract parameters from HTML Forms
            for form in soup.find_all("form"):
                action = form.get("action") # Gets the action from the form
                method = form.get("method", "get").lower() # Gets the methods from the form
                # Loops over the input tags
                for input_tag in form.find_all(["input", "textarea"]):
                    # Gets the name from the input tag
                    name = input_tag.get("name")
                    # Checks if there is a name
                    if name:
                        # Appends the gathered information to append
                        inputs.append({
                            "type": "form",
                            "name": name,
                            "method": method,
                            "action": action
                        })
            # Returns teh inputs
            return inputs
        # Catches the errors
        except Exception as e:
            # Prints a error message
            print(f"Error scraping {self.target_url}: {e}")
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
            # Outputs the found vulnerability
            print(f"[!] {xss_type} FOUND: {payload} in {param}")

    # Function to test parameters 
    def scan_reflected(self, params_to_test):
        # Loops over the parmeters in paremeters to test
        for param in params_to_test:
            # Loops over the payloads
            for payload in self.payloads:
                try:
                    # Gets the response from the parameters and payloads
                    res = requests.get(self.target_url, params={param: payload}, timeout=5)
                    # Checks for the payload
                    if payload in res.text:
                        # Logs the result
                        self._log_result("Reflected", payload, "Vulnerable", param)
                # Catches the errors
                except requests.RequestException as e:
                    # Outputs the error
                    print(f"Connection error: {e}")