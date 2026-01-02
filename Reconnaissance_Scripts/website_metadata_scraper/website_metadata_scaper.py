import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
import builtwith

# Function to get http headers
def get_http_headers(url):
    # gets the response from a get request to the url
    response = requests.get(url, timeout=10)

    # Extracts the headers
    headers = response.headers

    # Returns headers
    return headers

# Function to get html comments
def get_html_comments(url):
    # Makes get request with url arguement
    response = requests.get(url, timeout=10)
    # Puts the text from the response into beautiful souo
    soup = BeautifulSoup(response.text, "lxml")

    # Stores any found comments in the comments variable
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    
    # Preps comments and returns them
    return [comment.strip() for comment in comments if comment.strip()]

# extracts the javascript comments
def get_js_comments(url):
    # Makes a get request to the url
    response = requests.get(url, timeout=10)
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

# function to get cookie metadata
def get_cookie_metadata(url):
    # Gets a response from the url
    response = requests.get(url, timeout=10)

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

# Added detect technologies
def detect_technologies(url):
    # Trys to get the technologies
    try:
        # Reurns the resulrs from teh builtwith parse
        return builtwith.parse(url)
    except Exception as e:
        # Returns the error
        return {"error": str(e)}

# Main function
def main():
    # Allows the user to enter the target
    target = input("Enter target URL (https://example.com): ")

    print("[+] HTTP Headers")
    # Gets the headers from the headers function
    headers = get_http_headers(target)
    # Loops over the headers
    for header, information in headers.items():
        # Outputs the headers and the information
        print(f"{header}: {information}")

    print("[+] HTML Comments")
    # Gets the comments from function
    comments = get_html_comments(target)
    # Loops over the comments
    for comment in comments:
        # Outputs comments
        print(f"<!-- {comment} -->")
    
    print("[+] Technologies Used")
    # Gets the tech stack from the function
    tech = detect_technologies(target)
    # loops over tech and extracts the technologys
    for category, items in tech.items():
        # Outputs the category
        print(f"{category}: {items}")

# Starts the program
if __name__ == "__main__":
    main()