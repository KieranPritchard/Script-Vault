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