# Script: Advanced XSS Detection & Auditing

## Project Description

### Objective

This tool is designed to automate the detection of Cross-Site Scripting (XSS) vulnerabilities across complex web applications. It streamlines the entire workflow from **Subdomain Discovery** (subfinder) and **Deep Crawling** (katana) to **Advanced XSS Probing** (dalfox). The goal is to provide a comprehensive, high-speed audit that identifies Reflected, Stored, and DOM-based XSS vulnerabilities.

### Features

* **Subdomain Discovery:** Integrates subfinder to map out the entire domain landscape, ensuring no subdomains are left untested.

* **Deep JavaScript-Aware Crawling:** Uses katana to find hidden endpoints and parameters, specifically targeting modern single-page applications (SPAs) and dynamic content.

* **Multi-Vector XSS Testing:** Leverages dalfox to perform advanced XSS testing, including:
    * **Reflected XSS:** Testing URL parameters and path segments.
    * **Stored XSS:** Systematically checking for payloads that persist across requests.
    * **DOM-based XSS:** Analyzing client-side scripts for dangerous sinks.

* **WAF Evasion:** Automatically employs dalfox's built-in WAF evasion techniques and parameter mining to bypass common security filters.

* **Optimized Performance:** Throttles scanning to maintain stealth and reduce target load while utilizing multi-threading for efficient processing of large endpoint lists.

* **Clear Reporting:** Exports findings to `xss_results.csv` with full details (type, parameter, payload) and saves confirmed vulnerable URLs to `vulnerable_targets.txt`.

### Technologies and Tools Used

* **Language:** Python
* **External Tools:** dalfox (XSS scanning), katana (endpoint crawling), subfinder (subdomain discovery)
* **Libraries:** subprocess, csv, json, urllib.parse, concurrent.futures

### Outcome

The scanner provides a robust, end-to-end XSS auditing solution. It successfully identifies complex XSS vectors, provides reproducible PoCs (Proof of Concepts), and classifies findings by type and affected parameter, allowing for rapid remediation.


## How To Use Script

1. **Set Up Your Environment**

   * Ensure Python 3 and Go are installed.
   * Install the required external tools:

   ```Bash
   # dalfox
   go install github.com/hahwul/dalfox/v2@latest

   # katana
   go install github.com/projectdiscovery/katana/cmd/katana@latest

   # subfinder
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

2. **Run the Scanner**

   ```Bash
   python3 xss_detection.py
   ```

3. **Input Prompts**

   * **Target URL:** Enter the base domain or a specific URL to scan.

4. **Review Results**

   Once complete, the following files are generated:
   * **`xss_results.csv`**: Comprehensive report including vulnerability type, affected parameter, and the successful payload.
   * **`vulnerable_targets.txt`**: A simplified list of URLs confirmed to be vulnerable to XSS.

5. **Configuration**

   The following tuning knobs are available at the top of the script:

   | Variable | Default | Description |
   |---|---|---|
   | `MAX_SCAN_TARGETS` | 60 | Maximum URLs processed per run |
   | `MAX_DALFOX_THREADS` | 5 | Parallel dalfox processes |
   | `DALFOX_WORKERS` | 10 | Internal workers per dalfox scan |
   | `DALFOX_DELAY` | 2 | Delay between requests (stealth) |
   | `DALFOX_TIMEOUT` | 8 | Request timeout (seconds) |
