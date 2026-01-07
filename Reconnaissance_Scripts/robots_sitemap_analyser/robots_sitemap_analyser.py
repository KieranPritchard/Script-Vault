import random
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import requests
import time

def load_wordlists():
    # Variables to store contents of the wordlists
    config_wordlist = []
    backup_wordlist = []
    git_wordlist = []
    admin_wordlist = []
    api_wordlist = []
    dev_wordlist = []
    staging_wordlist = []
    testing_wordlist = []
    common_wordlist = []
    raft_wordlist = []

    # List to store wordlists paths
    wordlists = [
        "/usr/share/seclists/Discovery/Web-Content/Files/config-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/Files/backup-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/Files/git-config.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/admin-panels.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/Development/dev.txt",
        "/usr/share/seclists/Discovery/Web-Content/Development/staging.txt",
        "/usr/share/seclists/Discovery/Web-Content/Development/test.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    ]

    # Loops over each of the wordlists
    for wordlist in wordlists:
        # Checks the which wordlist is to be read
        if wordlist == "/usr/share/seclists/Discovery/Web-Content/Files/config-files.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        config_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/Files/backup-files.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        backup_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/Files/git-config.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        git_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/CMS/admin-panels.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        admin_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        api_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/Development/dev.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        dev_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/Development/staging.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        staging_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/Development/test.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        testing_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/common.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        common_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")
        elif wordlist == "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt":
            try:
                # Opens the file
                with open(wordlist, "r") as f:
                    # Loops over the contents of the file
                    for line in f:
                        # Adds line to the list
                        raft_wordlist.append(line)
            except Exception as e:
                # Outputs error message
                print(f"Error encountered: {e}")

    # Returns the wordlists
    return config_wordlist, backup_wordlist, git_wordlist, admin_wordlist, api_wordlist, dev_wordlist, staging_wordlist, testing_wordlist, common_wordlist, raft_wordlist

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

    # Loads the wordlists
    config_wordlist, backup_wordlist, git_wordlist, admin_wordlist, api_wordlist, dev_wordlist, staging_wordlist, testing_wordlist, common_wordlist, raft_wordlist = load_wordlists()

    # Loops over the results
    for result in results:
        # Makes a request to the websote
        response = requests.get(urljoin(domain, result), headers=headers, timeout=10)
        # Checks if the site is able to be accessed
        if response.status_code == 200:
            # Assesss the severity of the result
            if result in config_wordlist or result in backup_wordlist or result in git_wordlist:
                print(f"[Critical] {urljoin(domain, result)}")
            elif result in admin_wordlist or result in api_wordlist:
                print(f"[High] {urljoin(domain, result)}")
            elif result in dev_wordlist or result in common_wordlist or result in staging_wordlist or result in testing_wordlist:
                print(f"[Medium] {urljoin(domain, result)}")
            elif result in raft_wordlist:
                print(f"[Low] {urljoin(domain, result)}")
        else:
            # Gos to next iteration
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