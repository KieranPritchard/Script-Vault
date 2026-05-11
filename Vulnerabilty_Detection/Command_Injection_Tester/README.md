# Script: Automated Command Injection Detection

## Project Description

### Objective

The objective of this tool is to automate the discovery and testing of command injection vulnerabilities across an entire web application's infrastructure. By integrating **Subdomain Discovery** (subfinder), **Deep Crawling** (katana), and **Automated Exploitation Testing** (commix), the script maps the attack surface and systematically tests every discovered endpoint for OS command injection vulnerabilities.

### Features

* **Subdomain Discovery:** Uses subfinder to identify all subdomains associated with the target, ensuring that forgotten or hidden staging environments are included in the audit.

* **Deep Endpoint Crawling:** Leverages katana to crawl discovered domains, extracting links, forms, and API endpoints, including those hidden within JavaScript.

* **Automated Injection Testing:** Uses commix to perform thorough command injection testing on all discovered parameters and headers.

* **Session Support:** Allows for authenticated scanning by passing session cookies, enabling the audit of internal or user-restricted areas of the application.

* **Structured Reporting:** Automatically generates a comprehensive CSV report (`command_injection_results.csv`) and a list of confirmed vulnerable targets (`vulnerable_targets.txt`).

* **Stealth and Performance:** Utilizes parallel processing and configurable timeouts to balance thoroughness with scan speed.

### Technologies and Tools Used

* **Language:** Python
* **External Tools:** commix (Command Injection testing), katana (endpoint crawling), subfinder (subdomain discovery)
* **Libraries:** subprocess, csv, urllib.parse, concurrent.futures (threading)

### Outcome

The tool provides a streamlined pipeline for command injection auditing: discovery → crawling → automated testing → reporting. It identifies vulnerable endpoints and provides the specific payloads needed to reproduce the findings.


## How To Use Script

1. **Set Up Your Environment**

   * Ensure Python 3 is installed.
   * Install the required external tools:

   ```Bash
   # commix
   git clone https://github.com/commixproject/commix.git commix
   cd commix
   python3 commix.py --help

   # katana
   go install github.com/projectdiscovery/katana/cmd/katana@latest

   # subfinder
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

2. **Run the Scanner**

   ```Bash
   python3 command_injection_detection.py
   ```

3. **Input Prompts**

   * **Target URL:** The domain or specific URL to begin the audit.
   * **Session Cookie:** (Optional) Provide a cookie for authenticated scanning.

4. **Review Results**

   Once complete, the following files are generated:
   * **`command_injection_results.csv`**: Detailed report of all tested targets and findings.
   * **`vulnerable_targets.txt`**: A simplified list of confirmed vulnerable URLs.

5. **Configuration**

   You can adjust the following constants at the top of the script:

   | Variable | Default | Description |
   |---|---|---|
   | `MAX_SCAN_TARGETS` | 30 | Maximum URLs sent to commix |
   | `MAX_COMMIX_THREADS` | 2 | Number of parallel commix processes |
   | `COMMIX_TIMEOUT` | 300 | Maximum time allowed per target (seconds) |
