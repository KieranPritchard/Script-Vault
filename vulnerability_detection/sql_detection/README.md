# Script: Deep SQL Injection Detection

## Project Description

### Objective

The goal was to create an automated security tool that maps a website's entire attack surface and tests every discovered endpoint for SQL injection. By combining **Subdomain Discovery** (subfinder), **Deep Crawling** (katana), and **Automated Exploitation Testing** (sqlmap), the script provides a comprehensive view of how many endpoints on a domain are vulnerable to SQL injection.

### Features

* **Subdomain Discovery:** Uses subfinder to enumerate all subdomains under the target domain, expanding the attack surface beyond the primary host.

* **Deep Endpoint Crawling:** Uses katana with JavaScript crawling to discover endpoints, hidden parameters, and dynamic paths across all discovered subdomains.

* **Safe Mode for Stealth:** Includes a dedicated "Safe Mode" that throttles requests (via --delay), lowers risk levels, and uses single-threading to avoid WAF detection and server overload.

* **Authenticated Scanning:** Supports passing session cookies to perform deep crawling and injection testing on authenticated areas of an application.

* **Structured Reporting:** Exports all findings to a structured CSV file (`sql_injection_results.csv`) and confirmed vulnerable URLs to a simple text file (`vulnerable_targets.txt`) for easy post-processing.

* **High-Performance Optimization:** Utilizes parallel process execution, internal `sqlmap` multi-threading (`--threads=10`), and optimized connection flags (`--null-connection`, `--no-cast`) to maximize scan speed without sacrificing thoroughness.

### Technologies and Tools Used

* **Language:** Python
* **External Tools:** sqlmap (SQL injection testing), katana (endpoint crawling), subfinder (subdomain discovery)
* **Libraries:** subprocess, csv, urllib.parse, concurrent.futures (threading)

### Challenges Faced

**Attack Surface Discovery:** A single-page crawl misses the vast majority of injectable endpoints. By integrating subfinder for subdomain enumeration and katana for deep JavaScript-aware crawling, the tool now discovers endpoints that a simple HTML scraper would never find.

**sqlmap Output Parsing:** sqlmap uses specific output strings like `"injectable"`, `"the back-end DBMS is"`, and `"sqlmap identified the following injection point"` to indicate confirmed vulnerabilities. Early versions checked for incorrect keywords and missed all detections. The fix involved researching sqlmap's actual output format and implementing dual-source detection (stdout + log files).

**Scan Performance:** sqlmap is inherently slow due to its thorough testing methodology. The solution caps concurrent processes at 2 and limits total targets to 30 (configurable), with per-process timeouts to prevent hangs.

### Outcome

The tool now operates as a full-pipeline SQL injection auditor: subdomain discovery → deep crawling → automated sqlmap testing → structured CSV reporting. It successfully identifies SQL injection vulnerabilities with injection type classification, DBMS fingerprinting, and payload proof-of-concept capture.


## How To Use Script

1. **Set Up Your Environment**

   * Ensure Python 3 is installed.

   * Install the required external tools:

   ```Bash
   # sqlmap
   brew install sqlmap

   # katana (Go required)
   go install github.com/projectdiscovery/katana/cmd/katana@latest

   # subfinder (Go required)
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

2. **Run the Scanner**

   ```Bash
   python3 sql_injection_detection.py
   ```

3. **Input Prompts**

   * **Target URL:** The root domain or specific page you want to audit.
   * **Session Cookie:** (Optional) Paste your browser session cookie to scan behind logins.
   * **Safe Mode:** (Y/n) Choose "Y" for stealthy, throttled scanning or "n" for aggressive, multi-threaded testing.

4. **Script Behavior**

   * **Discovery Phase:** The script discovers subdomains via subfinder and crawls all in-scope paths with katana.
   * **Prioritisation:** Deduplicates paths and prioritises URLs with query parameters.
   * **Analysis Phase:** Runs sqlmap with the selected safety profile. Advanced WAF evasion (`space2comment`, `between`, `randomcase`) is always enabled.
   * **Silent Output:** To maintain professional clarity, terminal output is minimized. The final source of truth is the CSV report.

5. **Review Results**

   Once complete, two files are generated:
   * **`sql_injection_results.csv`**: Full details including injection type, PoC, and DBMS.
   * **`vulnerable_targets.txt`**: A clean list of only the vulnerable URLs for use with other tools.

5. **Configuration**

   The following constants at the top of the script can be adjusted:

   | Variable | Default | Description |
   |---|---|---|
   | `MAX_SCAN_TARGETS` | 30 | Maximum URLs sent to sqlmap |
   | `MAX_SQLMAP_THREADS` | 2 | Parallel processes (Safe Mode) |
   | `SQLMAP_INTERNAL_THREADS` | 10 | Threads per sqlmap process |
   | `SQLMAP_TIMEOUT` | 300 | Per-process timeout (seconds) |
   | `DEFAULT_LEVEL` | 2 | sqlmap thoroughness in Safe Mode |
   | `DEFAULT_RISK` | 1 | sqlmap aggressiveness in Safe Mode |
   | `DEFAULT_DELAY` | 1 | Delay between requests in Safe Mode |
