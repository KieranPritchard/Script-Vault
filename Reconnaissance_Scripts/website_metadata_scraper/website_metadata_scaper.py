import random
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
import builtwith
import time

# Function to get random user agent from folder
def get_random_agent():
    # Opens the file
    with open("../../Resources/user_agent_strings.txt", "r") as f:
        # Extracts the user agents as a list
        user_agents = [ua.strip() for ua in f if ua.strip()]

    # Selects a random index
    user_agent = random.choice(user_agents)

    # Returns the headers
    return {"User-Agent": user_agent}

# Function to get http headers
def get_http_headers(url):
    # Gets random user agent for header
    header = get_random_agent()

    # gets the response from a get request to the url
    response = requests.get(url, headers=header,timeout=10)

    # Extracts the headers
    headers = response.headers

    # Returns headers
    return headers

# Function to get html comments
def get_html_comments(url):
    # Gets random user agent for header
    header = get_random_agent()

    # Makes get request with url arguement
    response = requests.get(url, headers=header,timeout=10)
    # Puts the text from the response into beautiful souo
    soup = BeautifulSoup(response.text, "lxml")

    # Stores any found comments in the comments variable
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    
    # Preps comments and returns them
    return [comment.strip() for comment in comments if comment.strip()]

# extracts the javascript comments
def get_js_comments(url):
    # Gets random user agent for header
    header = get_random_agent()
    # Makes a get request to the url
    response = requests.get(url,headers=header,timeout=10)
    # Extracts the page content
    soup = BeautifulSoup(response.text, "lxml")

    # List to store comments
    js_comments = []

    # Loops over all script elements in the website
    for script in soup.find_all("script"):
        # Checks if script is a string
        if script.string:
            # Extracts lines
            lines = script.string.splitlines()
            # Loops over the lines
            for line in lines:
                # Strips white space from the line
                line = line.strip()
                # Checks if the line is a script script comment
                if line.startswith("//") or line.startswith("/*"):
                    # Adds comments to lines
                    js_comments.append(line)

    # Returns the js comments
    return js_comments

# Function to get meta tags
def get_meta_tags(url):
    # Gets random user agent for header
    header = get_random_agent()
    # gets a respons from the get request to the url
    response = requests.get(url, headers=header, timeout=10)
    # Sets up beautiful soup
    soup = BeautifulSoup(response.text, "lxml")

    # Dictionary to store metadata
    metadata = {}

    # Loops over the metadata tags
    for tag in soup.find_all("meta"):
        key = tag.get("name")or tag.get("property") or tag.get("http-equiv")

        # Checks if there is a key
        if key:
            # Adds contents of metadata to metadata dictionary
            metadata[key] = tag.get("content")

    # Returns the metadata
    return metadata

# function to get cookie metadata
def get_cookie_metadata(url):
    # Gets random user agent for header
    header = get_random_agent()

    # Gets a response from the url
    response = requests.get(url, headers=header,timeout=10)

    # Empty list to store cookies
    cookies = []
    # Loops over the cookies
    for cookie in response.cookies:
        # Adds cookies to list
        cookies.append(
            {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in cookie._rest
            }
        )
    
    # Returns the cookies
    return cookies

def get_site_declarations(url):
    # Gets random user agent for header
    header = get_random_agent()

    # Specifies files 
    files = ["robots.txt", "sitemap.xml"]
    # Stores the declarations
    declarations = {}

    # Loops over the files
    for file in files:
        # Makes the url to test
        test_url = urljoin(url, file)
        # Make request to test url
        response = requests.get(test_url, headers=header,timeout=5)
        # Checks if the status code is within the ok range
        if response.status_code == 200:
            # Adds the reponse to the declarations
            declarations[file] = response.text
    
    # Returns the declarations
    return declarations

# Added detect technologies
def detect_technologies(url):
    # Trys to get the technologies
    try:
        # Reurns the resulrs from teh builtwith parse
        return builtwith.parse(url)
    except Exception as e:
        # Returns the error
        return {"error": str(e)}

def get_security_metadata(url):
    # Gets random user agent for header
    header = get_random_agent()

    # Makes request to url
    response = requests.get(url, headers=header, timeout=10)

    # Gets the headers from the response
    headers = response.headers

    # Gets the security headers
    security_headers = {
        "Content-Security-Policy": headers.get("Content-Security-Policy"),
        "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        "X-Frame-Options": headers.get("X-Frame-Options"),
        "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
        "Referrer-Policy": headers.get("Referrer-Policy"),
        "Permissions-Policy": headers.get("Permissions-Policy"),
    }

    # Returns the security headers
    return security_headers

# Main function
def main():
    # Logs the starting time
    start_time = time.perf_counter() 

    # Allows the user to enter the target
    target = input("Enter target URL (https://example.com): ")

    # Vaildates if there was a target entered
    if target:
        # Uses the functions to grab relevant metadata
        headers = get_http_headers(target) # Grabs http headers
        comments = get_html_comments(target) # Grabs html comments
        js_comments = get_js_comments(target) # Gets javascript comments
        metadata_tags = get_meta_tags(target) # Gets html metadata tags
        cookies = get_cookie_metadata(target) # Gets the metadata of cookies
        security_data = get_security_metadata(target) # Gets the security metadata
        declarations = get_site_declarations(target) # Gets declaration pages
        tech = detect_technologies(target) # Finds out the tech stack

        # Checks if headers were returned
        if headers:
            print("=" * 30)
            print("[+] HTTP Headers")
            print("=" * 30)
            # Loops over the headers
            for header, information in headers.items():
                # Outputs the headers and the information
                print(f"{header}: {information}")

        # Checks if comments were returned
        if comments:
            print("=" * 30)
            print("[+] HTML Comments")
            print("=" * 30)
            # Loops over the comments
            for comment in comments:
                # Outputs comments
                print(f"<!-- {comment} -->")

        # Checks if there are any javascript comments
        if js_comments:
            print("=" * 30)
            print("[+] JavaScript Comments")
            print("=" * 30)
            # Loops over the javascript comments
            for js_comment in js_comments:
                # Outputs the the javscript comments
                print(f"{js_comment}")
        
        # Checks if there are any metadata tags
        if metadata_tags:
            print("=" * 30)
            print("[+] <meta> tags")
            print("=" * 30)
            # Loops over metadata tags
            for tag in metadata_tags:
                # Outputs the tag name
                print(tag)
        
        # Checks if there are any cookies
        if cookies:
            print("=" * 30)
            print("[+] Cookie Metadata")
            print("=" * 30)
            # Loops over the cookies
            for cookie in cookies:
                # Outputs the cookie name and the metadata
                print(f"Cookie: {cookie.get("name")}")
                print(f"- Domain: {cookie.get("domain")}")
                print(f"- Path: {cookie.get("path")}")
                print(f"- Secure: {cookie.get("secure")}")
                print(f"- HTTPONLY: {cookie.get("httponly")}")

        # Checks if there was any security data
        if security_data:
            print("=" * 30)
            print("[+] Security metadata")
            print("=" * 30)
            # Loops over the security data
            for data in security_data:
                # Outputs the key-data pair
                print(f"{data}:{security_data.get(data)}")

        # Checks if there is any declarations
        if declarations:
            print("=" * 30)
            print("[+] Site Declarations")
            print("=" * 30)
            # Loops over the declarations
            for declaration in declarations:
                # Prints the declaration
                print(declaration)
        
        if tech:
            print("=" * 30)
            print("[+] Technologies Used")
            print("=" * 30)
            # loops over tech and extracts the technologys
            for category, items in tech.items():
                # Outputs the category
                print(f"{category}: {items}")
    else:
        print("[!] Please enter a target URL")

    # Gets end time and calculates the elasped time
    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # Outputs the time
    print(f"[✓] Finished in {elapsed:.2f} seconds")

# Starts the program
if __name__ == "__main__":
    main()