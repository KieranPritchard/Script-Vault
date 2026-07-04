import os
import subprocess
import shutil
import csv
import time
import random
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# Creates the object for the print lock
print_lock = Lock()

# Global tuning knobs for performance and stealth
MAX_SCAN_TARGETS = 30           # Max URLs that will be sent to sqlmap (None = scan everything we find)
MAX_SQLMAP_THREADS = 2          # Parallel sqlmap processes (Safe: 1-2, Aggressive: 5+)
SQLMAP_INTERNAL_THREADS = 10    # sqlmap internal threads per process (--threads)
SQLMAP_TIMEOUT = 300            # Per-process timeout in seconds
DEFAULT_LEVEL = 3               # Safe default level
DEFAULT_RISK = 1                # Safe default risk
DEFAULT_DELAY = 1               # Delay in seconds between requests (0 for aggressive)


# Class to store the detection logic
class SQLInjectionDetection:
    def __init__(self, target_url, cookie="", safe_mode=True, output_dir="sql_reports"):
        self.target_url = target_url                    # Stores the target url
        self.cookie = cookie                            # Stores the session cookie
        self.safe_mode = safe_mode                      # Safety toggle
        self.target_domain = urlparse(target_url).netloc  # Sets the target domain
        self.output_dir = output_dir                    # Stores the output directory for sqlmap logs
        self.results = []                               # Stores the results
        self.results_lock = Lock()                      # Creates a lock for the results

        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    # Method to get a random user agent string
    def get_user_agent(self):
        """Function to get a random user agent string"""

        try:
            # Opens the file
            with open("../../Resources/user_agent_strings.txt", "r") as file:
                # Extracts the user agents as a list
                user_agents = [user_agent.strip() for user_agent in file if user_agent.strip()]

            # Selects a random user agent
            return random.choice(user_agents)
        except:
            # Returns a default user agent
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0"

    # Function to run subfinder
    def run_subfinder(self):
        """Subdomain discovery function using subfinder"""

        # Checks if subfinder is installed
        if not shutil.which("subfinder"):
            print("[!] subfinder not found, skipping subdomain discovery.")
            return [self.target_domain]

        # Outputs the program is discovering subdomains
        print(f"[*] Discovering subdomains for {self.target_domain}...")

        # Gets the result of the scan
        result = subprocess.run(
            ["subfinder", "-d", self.target_domain, "-silent"],
            capture_output=True, text=True
        )

        # Extracts the domains from the results
        domains = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        # Always include the original target domain
        if self.target_domain not in domains:
            domains.insert(0, self.target_domain)

        # Outputs the found domains
        print(f"[✓] Found {len(domains)} domains (including subdomains).")

        return domains

    # Function to run katana
    def run_katana(self, targets):
        """Crawl for hidden endpoints using katana"""

        # Checks if katana is installed
        if not shutil.which("katana"):
            print("[!] katana not found, skipping deep crawl.")
            return []

        # Empty list to store discovered urls
        discovered = []

        # Outputs katana is starting
        print(f"[*] Starting Katana deep crawl...")

        # Loops over the targets in targets
        for target in targets:

            # Formats the target
            formatted_target = target if "://" in target else f"http://{target}"

            try:
                # Optimized katana command for speed
                katana_cmd = ["katana", "-u", formatted_target, "-depth", "3", "-silent", "-nc", "-jc", "-concurrency", "25"]
                
                # Adds cookie to katana request if provided
                if self.cookie:
                    katana_cmd.extend(["-H", f"Cookie: {self.cookie}"])
                
                # Gets the result for the target
                result = subprocess.run(
                    katana_cmd,
                    capture_output=True, text=True
                )

                # Adds the results to the discovered list
                discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
            except:
                continue  # Continues if there isnt anything

        # Filter URLs to only keep those within the target domains
        in_scope_urls = []
        for url in discovered:
            try:
                netloc = urlparse(url).netloc
                # Ensure it belongs to one of our target domains
                if any(netloc == d or netloc.endswith("." + d) for d in targets):
                    in_scope_urls.append(url)
            except:
                pass

        # Returns a list without duplicates
        print(f"[✓] Katana discovered {len(set(in_scope_urls))} unique in-scope URLs.")
        return list(set(in_scope_urls))

    # Method to run sqlmap
    def run_sqlmap(self, target_url):
        """Runs sqlmap to detect SQL injection vulnerabilities"""

        # Set level and risk based on safe_mode
        level = DEFAULT_LEVEL if self.safe_mode else 5
        risk = DEFAULT_RISK if self.safe_mode else 2
        delay = DEFAULT_DELAY if self.safe_mode else 0

        # Constructs the sqlmap command
        command = [
            "sqlmap",
            "-u", target_url,
            "--batch",                              # No interactive prompts
            "--random-agent",                       # Rotates the user agent per request
            "--level", str(level),
            "--risk", str(risk),
            "--delay", str(delay),                  # Pause between requests for stealth
            "--threads", str(SQLMAP_INTERNAL_THREADS), # Internal sqlmap threading
            "--null-connection",                    # Faster blind SQLi detection
            "--no-cast",                            # Faster payload execution
            "--forms",                              # Test POST forms found on the page
            "--crawl=3",                            # Let sqlmap discover its own endpoints
            "--output-dir", self.output_dir,         # Save logs and payloads
            "--tamper=space2comment,between,randomcase", # Improved WAF evasion
            "--retries", "1",                       # Lower retries for speed
            "--timeout", "10",                      # Lower timeout for speed
            "--answers", "follow=Y,keep=N,exploit=Y",
            "--flush-session",                      # Clear previous session data for fresh scan
        ]

        if self.cookie:
            command.extend(["--cookie", self.cookie])

        try:
            # Runs the sqlmap process with a global timeout
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors='ignore',
                timeout=SQLMAP_TIMEOUT
            )

            output = result.stdout

            # Parses the output for vulnerability indicators
            vuln_stdout = self._parse_sqlmap_output(output, target_url)

            # Also check the sqlmap output directory for log files
            vuln_log = self._check_sqlmap_logs(target_url)

            # Log as Not Vulnerable if no indicators were found
            if not vuln_stdout and not vuln_log:
                self._log_result("N/A", target_url, "N/A", "Not Vulnerable", "N/A")

        except subprocess.TimeoutExpired:
            self._log_result("N/A", target_url, "N/A", "Timeout", "N/A")
        except Exception as e:
            self._log_result("N/A", target_url, "N/A", "Error", "N/A")

    # Method to parse sqlmap stdout for vulnerability indicators
    def _parse_sqlmap_output(self, output, target_url):
        """Parses sqlmap output for confirmed vulnerability indicators"""

        # Converts to lowercase for matching
        output_lower = output.lower()

        # The real strings sqlmap outputs when it finds something
        hit_indicators = [
            "sqlmap identified the following injection point",    # Full confirmation block
            "is vulnerable"                                       # Direct confirmation
        ]

        # Check for false positives first
        false_positive_indicators = [
            "false positive or unexploitable",
            "does not seem to be injectable",
            "do not appear to be injectable"
        ]

        if any(fp in output_lower for fp in false_positive_indicators):
            return False

        # Checks if any indicator is present in the output, OR if a payload was explicitly dumped
        has_payload = any(line.strip().lower().startswith("payload:") for line in output.splitlines())
        
        if has_payload or any(indicator in output_lower for indicator in hit_indicators):

            # Extracts the injection type from the output
            injection_type = "Unknown"
            type_indicators = {
                "boolean-based blind":  "Boolean-based Blind",
                "time-based blind":     "Time-based Blind",
                "error-based":          "Error-based",
                "union query":          "UNION Query",
                "stacked queries":      "Stacked Queries",
                "inline query":         "Inline Query",
            }

            # Loops over the type indicators to find the specific type
            for key, value in type_indicators.items():
                if key in output_lower:
                    injection_type = value
                    break

            # Extracts the DBMS type if available
            dbms = "Unknown"
            if "the back-end dbms is" in output_lower:
                # Finds the line with the DBMS information
                for line in output.splitlines():
                    if "back-end dbms is" in line.lower():
                        dbms = line.split("is")[-1].strip()
                        break

            # Extracts a sample poc if available
            poc = "See sqlmap logs"
            for line in output.splitlines():
                stripped = line.strip()
                if stripped.startswith("Payload:") or stripped.startswith("payload:"):
                    poc = stripped.split(":", 1)[-1].strip()
                    break

            # Logs the result
            self._log_result(injection_type, target_url, poc, "Vulnerable", dbms)
            return True
        return False

    # Method to check sqlmap's output directory for log files
    def _check_sqlmap_logs(self, target_url):
        """Checks sqlmap output directory for log files confirming vulnerabilities"""

        # Extracts the hostname from the target URL
        parsed = urlparse(target_url)
        host_dir = os.path.join(self.output_dir, parsed.netloc)

        # Checks if the host directory exists (sqlmap only creates it if it found something)
        if not os.path.isdir(host_dir):
            return False

        # Looks for the log file
        log_file = os.path.join(host_dir, "log")

        if os.path.exists(log_file):
            try:
                # Reads the log file
                with open(log_file, "r") as f:
                    log_content = f.read()

                # Checks for confirmed vulnerabilities in the log
                if "injectable" in log_content.lower() or "is vulnerable" in log_content.lower():
                    # Extracts parameters from the log
                    for line in log_content.splitlines():
                        line_lower = line.strip().lower()

                        # Looks for parameter lines
                        if "parameter:" in line_lower or "place:" in line_lower:
                            self._log_result(
                                "Log-Confirmed",
                                target_url,
                                f"See {log_file}",
                                "Vulnerable",
                                "See log"
                            )
                            return True  # Only log once per target from logs
            except:
                pass
        return False

    # Method to log result
    def _log_result(self, sqli_type, url, poc, status, dbms):
        """Thread-safe result logging with deduplication"""

        # Stores the signature for deduplication
        sig = f"{sqli_type}-{url}-{dbms}"

        # Uses the results lock to log the data
        with self.results_lock:
            # Checks for duplicates using the signature
            # Changed to be checking if the signature already exists
            if sig not in self.results:

                # Stores the entry
                self.results[sig] = {
                    "SQL_Injection_Type": sqli_type,
                    "Affected_URL": url,
                    "Proof_Of_Concept": poc,
                    "Status": status,
                    "DBMS": dbms
                }

    # Method to save results to csv
    def save_results_to_csv(self, filename="sql_injection_results.csv"):
        """Exports findings to a CSV file"""

        # Checks for results
        if not self.results:
            print("[!] No scans completed to export.")
            return

        # Creates the keys
        keys = ["SQL_Injection_Type", "Affected_URL", "Proof_Of_Concept", "Status", "DBMS"]

        # Opens the file to write data
        with open(filename, 'w', newline='') as f:
            # Writes the data to the field names
            writer = csv.DictWriter(f, fieldnames=keys)

            # Writes the header
            writer.writeheader()

            # Writes the rows from results
            writer.writerows(self.results)

        # Outputs the result is saved
        print(f"[✓] Final report saved to {filename}")

    # Method to save vulnerable targets to txt
    def save_vulnerable_targets_to_txt(self, filename="vulnerable_targets.txt"):
        """Exports only the vulnerable URLs to a text file"""

        # Filters for vulnerable results
        vulnerable_urls = [r["Affected_URL"] for r in self.results if r["Status"] == "Vulnerable"]

        if not vulnerable_urls:
            return

        # Writes the URLs to the file
        with open(filename, "w") as f:
            for url in vulnerable_urls:
                f.write(f"{url}\n")

        print(f"[✓] Vulnerable targets saved to {filename}")


def main():
    print("--- SQL Injection Detection Scanner (sqlmap + katana + subfinder) ---\n")

    # Allows the target to be inputted
    target = input("[+] Enter Target URL: ").strip()
    cookie = input("[+] Enter Session Cookie (optional, press Enter to skip): ").strip()
    mode = input("[+] Use Safe Mode? (Y/n): ").strip().lower()
    
    safe_mode = mode != 'n'

    # Does some validation
    if not target.startswith("http"):
        print("[!] Invalid URL. Make sure it includes http:// or https://")
        return

    # Starts the timer and loads the target into the scanner
    start_time = time.perf_counter()
    scanner = SQLInjectionDetection(target, cookie=cookie, safe_mode=safe_mode)

    print(f"\n[+] Starting reconnaissance on {scanner.target_domain}\n")

    # Phase 1: Subdomain discovery
    domains = scanner.run_subfinder()

    # Phase 2: Deep crawl all domains for endpoints
    discovered_urls = scanner.run_katana(domains)

    # Always include the original target
    if target not in discovered_urls:
        discovered_urls.insert(0, target)

    # Phase 3: Deduplicate and prioritise parameterised URLs
    unique_paths = {}

    # Loops over the paths discovered
    for url in discovered_urls:
        # Normalises by path only so the same file with different params isn't crawled over and over
        p = urlparse(url)

        # Checks if the path is not in the unique variable
        if p.path not in unique_paths:
            unique_paths[p.path] = url

    # Converts the paths values into a list
    all_targets = list(unique_paths.values())

    # Prioritise URLs that already have query parameters (higher SQLi value)
    param_urls = [url for url in all_targets if "?" in url]
    non_param_urls = [u for u in all_targets if "?" not in u]

    # Creates an ordered list of urls
    ordered = param_urls + non_param_urls

    # Lowers the amount of urls if they are over the maximum number of targets
    scan_list = ordered[:MAX_SCAN_TARGETS] if MAX_SCAN_TARGETS is not None else ordered

    # Prints the unique information
    print(f"[✓] Found {len(all_targets)} unique paths, selecting {len(scan_list)} for sqlmap scanning.")

    # Outputs the scan has started
    print(f"\n[+] Running sqlmap scan (this may take a while — sqlmap is thorough)\n")

    # Throttled to avoid WAF bans and resource exhaustion
    threads = MAX_SQLMAP_THREADS if safe_mode else 5
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Runs the executor scan
        executor.map(scanner.run_sqlmap, scan_list)

    # Saves the results to csv
    scanner.save_results_to_csv()
    scanner.save_vulnerable_targets_to_txt()

    # Calculates the elapsed time
    elapsed = time.perf_counter() - start_time

    # Outputs the final information
    vulnerable_hits = [r for r in scanner.results if r["Status"] == "Vulnerable"]
    print(f"\n[✓] Scan Complete in {elapsed:.2f} seconds.")
    print(f"[✓] CSV report is the only output and contains {len(scanner.results)} scan records ({len(vulnerable_hits)} vulnerabilities).")


# Starts the program
if __name__ == "__main__":
    main()