import random
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import requests

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
        "Discovery/Web-Content/Files/config-files.txt",
        "Discovery/Web-Content/Files/backup-files.txt",
        "Discovery/Web-Content/Files/git-config.txt",
        "Discovery/Web-Content/CMS/admin-panels.txt",
        "Discovery/Web-Content/api/api-endpoints.txt",
        "Discovery/Web-Content/Development/dev.txt",
        "Discovery/Web-Content/Development/staging.txt",
        "Discovery/Web-Content/Development/test.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/raft-small-words.txt"
    ]

    # Loops over each of the wordlists
    for wordlist in wordlists:
        # Checks the which wordlist is to be read
        if wordlist == "Discovery/Web-Content/Files/config-files.txt":
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
        elif wordlist == "Discovery/Web-Content/Files/backup-files.txt":
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
        elif wordlist == "Discovery/Web-Content/Files/git-config.txt":
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
        elif wordlist == "Discovery/Web-Content/CMS/admin-panels.txt":
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
        elif wordlist == "Discovery/Web-Content/api/api-endpoints.txt":
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
        elif wordlist == "Discovery/Web-Content/Development/dev.txt":
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
        elif wordlist == "Discovery/Web-Content/Development/staging.txt":
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
        elif wordlist == "Discovery/Web-Content/Development/test.txt":
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
        elif wordlist == "Discovery/Web-Content/common.txt":
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
        elif wordlist == "Discovery/Web-Content/raft-small-words.txt":
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
    with open("Script-Vault/Resources/user_agent_strings.txt", "r") as f:
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
    robots_url = urljoin(domain, "/robots.txt")

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