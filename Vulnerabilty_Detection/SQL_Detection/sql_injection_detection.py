import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

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