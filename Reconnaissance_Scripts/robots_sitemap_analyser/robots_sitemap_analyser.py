import random
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import requests

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

def analyse_robots(domain):
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