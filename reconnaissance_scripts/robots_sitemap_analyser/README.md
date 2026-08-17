# Script: Robots & Sitemap Analyser

## Project Description

### Objective

The goal of this project is to create an automation which can read and analyse the robots and the sitemap for sensitive paths which could be used by attackers using wordlists.

### Features

* Automatically retrieves and parses robots.txt
* Extracts Disallow entries
* Extracts any referenced sitemap URLs
* Retrieves and parses sitemap.xml
* Supports both standard sitemaps and sitemap index files
* Recursively processes nested sitemaps
* Uses random User-Agent strings to reduce request fingerprinting
* Compares discovered paths against multiple SecLists wordlists
* Categorises discovered paths by severity:
    * Critical
    * High
    * Medium
    * Low
    * Unknown
* Verifies discovered paths by making live HTTP requests
* Measures and reports total script execution time
* Handles errors gracefully without crashing

### Technologies and Tools Used

* **Language:** Python
* **Frameworks/Librarys:** random, xml, urllib, requests, time

### Challenges Faced

I had problems with the file paths, particularly when loading external wordlists and the User-Agent file. I resolved this by installing a VS Code extension that helped me visualise and copy correct paths within the repository. For files stored on my Kali Linux machine, I resolved the issue by manually specifying the full absolute file paths.

### Outcome

The final script successfully automates the analysis of robots.txt and sitemap.xml files and correlates discovered paths against known wordlists commonly used during web attacks. This provides a quick way to identify potentially sensitive or misconfigured endpoints before running more aggressive enumeration tools. The project improved my understanding of web reconnaissance, XML parsing, HTTP request handling, and structuring a modular Python security script.

## How To Use Script

1. Set Up Your Environment:
* Make sure Python 3 is installed
* Install the required libraries:
```
pip install requests
```
2. Save the Script
* Save the script to a file, for example:
```
robots_sitemap_analyser.py
```
3. Run the Script
* Execute the script:
```
python3 robots_sitemap_analyser.py
```
4. Script Behavior
* Prompts the user for a target URL
* Automatically:
    * Parses robots.txt
    * Extracts disallowed paths and sitemap references
    * Parses sitemap.xml (including nested sitemaps)
    * Checks discovered paths for accessibility
    * Matches paths against common attacker wordlists
    * Assigns a severity level to each valid path
* Handles missing files or invalid responses without crashing
5. Review Results
* All output is printed directly to the terminal
* Results are clearly labeled by severity
* Total runtime is displayed at the end
* Output can be redirected to a file if needed:
```
python3 robots_sitemap_analyser.py > results.txt
```