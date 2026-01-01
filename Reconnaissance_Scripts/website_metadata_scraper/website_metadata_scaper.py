import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Function to get http headers
def get_http_headers(url):
    # gets the response from a get request to the url
    response = requests.get(url, timeout=10)

    # Extracts the headers
    headers = response.headers

    # Returns headers
    return headers