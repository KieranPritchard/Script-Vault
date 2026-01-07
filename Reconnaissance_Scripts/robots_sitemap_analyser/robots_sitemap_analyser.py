import random
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import requests
import time

def load_wordlists():
    # Dictionary to store wordlist names and their file paths
    wordlist_paths = {
        "config": "/usr/share/seclists/Discovery/Web-Content/web-all-content-types.txt",
        "backup": "/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt",
        "git": "/usr/share/seclists/Discovery/Web-Content/versioning_metafiles.txt",
        "admin": "/usr/share/seclists/Discovery/Web-Content/CMS/admin-panels.txt",
        "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "dev": "/usr/share/seclists/Discovery/Web-Content/combined_words.txt",
        "staging": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "testing": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "raft": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    }

    # Dictionary to store the loaded wordlists
    wordlists = {}

    # Loops over each wordlist name and file path
    for name, path in wordlist_paths.items():
        try:
            # Opens the wordlist file
            with open(path, "r") as f:
                # Reads each line from the file
                # Strips newline characters and stores results in a list
                wordlists[name] = [line.strip() for line in f]
        except Exception as e:
            # Outputs error message if file cannot be read
            print(f"Error encountered while loading {path}: {e}")

            # Sets wordlist to empty list on error
            wordlists[name] = []

    # Returns all loaded wordlists
    return wordlists

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

def parse_robots(domain):
    # Lists to store disallowed and sitemaps
    disallowed = []
    sitemaps = []
    
    # Gets random user agent for header
    header = get_random_agent()

    # Creates robots url
    robots_url = urljoin(domain, "/robots.txt")

    # Gets response from the request to the robots
    reponse = requests.get(robots_url, headers=header, timeout=10)

    # Gets the page content
    contents = reponse.text

    # Checks for if there is no contents in response
    if not contents:
        return disallowed, sitemap

    # Loops over each line in contents after being split
    for line in contents.splitlines():
        # Strips the white space off of lines
        line = line.strip()
        
        # turns the line into lowercase and checks if it is disallowed
        if line.lower().startswith("disallow:"):
            # Splites the line in halve one at the : and strips any remaining white space
            path = line.split(":", 1)[1].strip()
            # Adds disallowed to the path
            disallowed.append(path)
        # turns the line into lowercase and checks if it is a sitemap
        elif line.lower().startswith("sitemap:"):
            # Splites the line in halve one at the : and strips any remaining white space
            sitemap = line.split(":", 1)[1].strip()
            # Adds disallowed to the path
            sitemaps.append(sitemap)
    
    # Returns the sitemap
    return disallowed, sitemaps

# Function to parse the sitemap
def parse_sitemap(domain):
    # Empty list to store paths
    urls = []

    # Gets random user agent for header
    header = get_random_agent()

    # Creates robots url
    robots_url = urljoin(domain, "/sitemap.xml")

    # Gets response from the request to the robots
    reponse = requests.get(robots_url, headers=header, timeout=10)

    # Gets the page content
    contents = reponse.text

    # Checks for if there is no contents in response
    if not contents:
        return urls
    
    try:
        # Gets the root of the xml tree
        root = ET.fromstring(contents)
        # Looks for the sitemap header
        ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        # Checks if the root tag ends with sitemap index value
        if root.tag.endswith("sitemapindex"):
            # loops over the sitemap entries
            for sm in root.findall("ns:sitemap", ns):
                # Finds locations in the sitemap
                loc = sm.find("ns:loc", ns)
                # Checks if there is a sitemap
                if loc is not None:
                    # Adds urls that are found using recursion
                    urls.extend(parse_sitemap(loc.text))
        else:
            # Checks for location
            for loc in root.findall(".//ns:loc", ns):
                # adds to list
                urls.append(loc.text)
    except ET.ParseError:
        pass
    
    # Reutns the urls
    return urls

def analyse_results(domain, results):
    # Gets the random user agent
    headers = get_random_agent()

    # Loads the wordlists (now returned as a dictionary)
    wordlists = load_wordlists()

    # Creates severity groupings from the loaded wordlists
    critical_wordlists = (
        wordlists["config"] +
        wordlists["backup"] +
        wordlists["git"]
    )

    high_wordlists = (
        wordlists["admin"] +
        wordlists["api"]
    )

    medium_wordlists = (
        wordlists["dev"] +
        wordlists["common"] +
        wordlists["staging"] +
        wordlists["testing"]
    )

    low_wordlists = wordlists["raft"]

    # Loops over the results
    for result in results:
        try:
            # Makes a request to the website
            response = requests.get(urljoin(domain, result), headers=headers, timeout=10)

            # Checks if the site is able to be accessed
            if response.status_code == 200:
                # Assesses the severity of the result
                if result in critical_wordlists:
                    print(f"[Critical] {urljoin(domain, result)}")
                elif result in high_wordlists:
                    print(f"[High] {urljoin(domain, result)}")
                elif result in medium_wordlists:
                    print(f"[Medium] {urljoin(domain, result)}")
                elif result in low_wordlists:
                    print(f"[Low] {urljoin(domain, result)}")
                else:
                    print(f"[Unknown] {urljoin(domain, result)}")
        except Exception as e:
            # Outputs error message if request fails
            print(f"Error encountered while requesting {result}: {e}")

            # Goes to next iteration
            continue

def main():
    # Logs the starting time
    start_time = time.perf_counter() 

    # Loop to interate while the input isnt a correct format
    while True:
        try: 
            # Lets the user enter a url
            domain = input("Please enter a URL: ")
            # Checks if there was a domain entered
            if domain:
                # Breaks out of the loop
                break
        except Exception as e:
            # Outputs error message
                print(f"Error encountered: {e}")

    # Outputs that robots is being parsed
    print("[+] Parsing robots.txt")
    # Stores the found disallowed and sitemps paths
    disallowed, sitemaps = parse_robots(domain)
    # Checks if there is dissallowed and sitemaps
    if disallowed and sitemaps:
        # Outputs header 
        print("[+] Found dissallowed and sitemap entries")
        
        # Outputs disallowed entries
        print("Dissallowed entries:")
        # Loops over the disallowed entries
        for i in disallowed:
            # Outputs the output
            print(f"- {i}")
        # Outputs sitemap entries
        print("sitemap entries")
        # Loops over the sitemaps entries
        for i in sitemaps:
            # Outputs the output
            print(f"- {i}")
    
    # Outputs the sitemaps are being parsed
    print("[+] Parsing sitemap.xml")
    # gets the paths from the sitemap
    sitemap_paths = parse_sitemap(domain)
    # Loops over the sitemap paths
    for i in sitemap_paths:
        # Outputs the path
        print(f"- {i}")

    # Outputs the dissallowed results are being analysed
    print("[+] Analysing disallowed results")
    # calls the function 
    analyse_results(domain, disallowed)
    
    print("[+] Analysing sitemap results")
    # calls the function 
    analyse_results(domain, sitemap_paths)

    # Gets end time and calculates the elasped time
    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # Outputs the time
    print(f"[✓] Finished in {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()