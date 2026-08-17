# Script: Website Metadata Scraper

## Project Description

### Objective

The goal of this project was to create a Python script that scrapes website metadata only, not page content. The idea was to pull as much useful passive information as possible without crawling pages or dumping full HTML.

This is intended for basic recon, analysis, and general OSINT-style use cases.

### Features

* Uses a randomized User-Agent for each request
* Pulls HTTP response headers
* Extracts HTML comments from the page
* Finds JavaScript comments inside <script> tags
* Parses HTML <meta> tags
* Collects cookie metadata (domain, path, secure, HttpOnly)
* Extracts common security-related HTTP headers, including:
    * Content-Security-Policy
    * Strict-Transport-Security
    * X-Frame-Options
    * X-Content-Type-Options
    * Referrer-Policy
    * Permissions-Policy
* Checks for common site declaration files:
    * robots.txt
    * sitemap.xml
* Detects technologies and frameworks used by the site using builtwith
* Handles missing data without crashing

### Technologies and Tools Used

* **Language:** Python
* * **Frameworks/Librarys:** random, requests, BeautifulSoup, urllib, builtwith

### Challenges Faced

I ran into an issue with the random User-Agent function. The problem was that I was referencing the Python script itself instead of the text file in the repo that actually contained the User-Agent strings.
Once I fixed the file path to point to the correct file, the function worked as expected.

### Outcome

The end result is a simple but effective metadata scraper that can quickly profile a website without doing anything invasive.
It pulls a decent amount of useful information in one run, organizes the output into readable sections, and doesn’t fall over when something isn’t present. It also leaves plenty of room to build on later if needed.


## How To Use Script

1. Set Up Your Environment
* Make sure Python 3 is installed
* Install the required libraries:
```
pip install dnspython python-whois
```
2. Save the Script
* Save the script to a file, for example:
```
domain_lookup.py
```
3. Run the Script
* Execute the script:
```
python3 domain_lookup.py
```
4. Script Behavior
* Prompts the user for a target URL
* Pulls and displays:
    * HTTP headers
    * HTML comments
    * JavaScript comments
    * Meta tags
    * Cookie metadata
    * Security headers
    * robots.txt and sitemap.xml (if present)
    * Detected technologies
* Handles missing records without crashing
5. Review Results
* All output is printed directly to the terminal
* Results are grouped into clearly labeled sections
* Output can be redirected to a file if needed:
```
python3 domain_lookup.py > results.txt
```