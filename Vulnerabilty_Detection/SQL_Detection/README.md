# Script: Deep SQL Injection Detection

## Project Description

### Objective

The goal was to create an automated security tool that maps a website's entire directory structure and tests every discovered page for SQL injection. By combining Recursive Crawling with Heuristic Analysis, the script provides a comprehensive view of how many pages on a site are vulnerable to data exfiltration.

### Features

* **Recursive Attack Surface Mapping:** Implements a crawler that follows internal <a> tags to discover every page within a domain, ensuring no hidden parameters are missed.

* **Intelligent Scope Control:** Automatically restricts the crawl to the target domain to prevent the scanner from "wandering" onto external websites like Google or Facebook.

* **Baseline-Adjusted Detection:** Establishes a mathematical "Noise Threshold" for the site to distinguish between server errors and dynamic page content.

* **Multi-Vector Scanning:** Simultaneously tests for Error-based, Boolean-based, Time-based, and Header-based SQLi.

* **Automated POST Discovery:** Parses HTML forms on every crawled page and tests them for injection vulnerabilities.

### Technologies and Tools Used

* **Language:** Python
* **Frameworks/Librarys:** requests, BeautifulSoup4 (Parsing & Crawling), difflib (Fuzzy Logic), urllib.parse.

### Challenges Faced

Crawling Depth & Redundancy: Initially, the crawler would get stuck in infinite loops or re-visit the same pages multiple times. I solved this by implementing a visited set to track processed URLs and using urljoin to normalize relative paths into absolute URLs.

Quantifying the Impact: A major problem was figuring out the scale of a vulnerability. I added a crawling phase specifically to quantify the total attack surface. This allowed the script to report not just if a site is vulnerable, but exactly how many pages are affected, giving a much better picture of the risk level.

Noise Thresholds: Dynamic pages (like those with changing timestamps) were triggering false positives. I implemented a baseline sampling method to calculate a similarity ratio, ensuring the Boolean-based scanner only triggers when a significant, logic-driven change occurs.

### Outcome

The tool is now a full-cycle security auditor. It begins with discovery, moves to vulnerability analysis, and ends with a detailed report on the domain's overall health. It successfully identifies the "Blast Radius" of a SQLi flaw by showing how many endpoints are susceptible to the same attack vector.


## How To Use Script

1. **Set Up Your Environment**

* Ensure Python 3 is installed.

* Install dependencies:

```Bash
pip install requests beautifulsoup4
```
2. Run the Suite

```Bash
python3 main_scanner.py
```
3. Script Behavior

* Discovery Phase: Enter a URL. The script will recursively visit every linked page it can find on that domain.

* Analysis Phase: Once discovery is complete, the script iterates through every found URL.

* Vulnerability Check: For each URL, it establishes a baseline and runs the full battery of SQLi tests.

* Final Reporting: The script outputs its findings in real-time, providing an sqlmap recommendation if vulnerabilities are confirmed.

4. Review Results

```Plaintext
[*] Discovery complete. Scanning 12 pages for SQLi...

--- Scanning: https://example.com/products.php?id=5 ---
[*] Testing for Error-based SQLi...
[!] VULNERABLE: Error-based found on https://example.com/products.php?id=5' (Matched: SQL syntax)

[✓] Finished in 42.15 seconds
```
