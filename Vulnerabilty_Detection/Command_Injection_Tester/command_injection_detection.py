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
MAX_SCAN_TARGETS = 30           # Max URLs that will be sent to commix (None = scan everything we find)
MAX_COMMIX_THREADS = 2          # Parallel commix processes
COMMIX_TIMEOUT = 300            # Per-process timeout in seconds

# Class to store the detection logic
class CommandInjectionDetection:
    def __init__(self, target_url, cookie="", output_dir="commix_reports"):
        self.target_url = target_url                    # Stores the target url
        self.cookie = cookie                            # Stores the session cookie
        self.target_domain = urlparse(target_url).netloc  # Sets the target domain
        self.output_dir = output_dir                    # Stores the output directory for commix logs
        self.results = []                               # Stores the results
        self.results_lock = Lock()                      # Creates a lock for the results

        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

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
            # Inserts into domain the target
            domains.insert(0, self.target_domain)

        # Outputs the found domains
        print(f"[✓] Found {len(domains)} domains (including subdomains).")

        # Returns the domains
        return domains

    # Function to run katana
    def run_katana(self, targets):
        """Crawl for hidden endpoints using katana"""

        # Checks if katana is installed
        if not shutil.which("katana"):
            # Outputs katana is not found and skips the deep crawl
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
        
        # Loops over the discovered urls
        for url in discovered:
            try:
                # Extracts the domain
                netloc = urlparse(url).netloc
                # Ensure it belongs to one of our target domains
                if any(netloc == d or netloc.endswith("." + d) for d in targets):
                    # Adds it to the in scope domains
                    in_scope_urls.append(url)
            except:
                pass

        # Returns a list without duplicates
        print(f"[✓] Katana discovered {len(set(in_scope_urls))} unique in-scope URLs.")
        
        # Returns an unduplicated list
        return list(set(in_scope_urls))

    # Method to run commix
    def run_commix(self, target_url):
        """Runs commix to detect command injection vulnerabilities"""

        # Constructs the commix command
        command = [
            "commix",
            "--url", target_url,
            "--batch",                              # No interactive prompts
            "--output-dir", self.output_dir,         # Save logs and payloads
            "--flush-session",                      # Clear previous session data
        ]

        if self.cookie:
            command.extend(["--cookie", self.cookie])

        try:
            # Runs the commix process
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors='ignore',
                timeout=COMMIX_TIMEOUT
            )

            output = result.stdout

            # Parses the output for vulnerability indicators
            is_vulnerable = self._parse_commix_output(output, target_url)

            # Log as Not Vulnerable if no indicators were found
            if not is_vulnerable:
                self._log_result("N/A", target_url, "N/A", "Not Vulnerable")

        except subprocess.TimeoutExpired:
            self._log_result("N/A", target_url, "N/A", "Timeout")
        except Exception as e:
            self._log_result("N/A", target_url, "N/A", "Error")

    # Method to parse commix stdout for vulnerability indicators
    def _parse_commix_output(self, output, target_url):
        """Parses commix output for confirmed vulnerability indicators"""

        output_lower = output.lower()

        # Commix indicators for vulnerability
        hit_indicators = [
            "is vulnerable",
            "the target is vulnerable",
            "vulnerability found",
            "os command injection"
        ]

        # Checks if any incicator is in the output
        if any(indicator in output_lower for indicator in hit_indicators):
            # Try to extract injection type or POC if possible
            
            # Stores the injection type and default poc
            injection_type = "Command Injection"
            poc = "See commix logs"
            
            # Loops over the output
            for line in output.splitlines():
                # Checks for the payload
                if "payload:" in line.lower():
                    # Extracts the poc from the output
                    poc = line.split(":", 1)[-1].strip()
                    
                    # Stops the loop
                    break
            
            # Logs the result
            self._log_result(injection_type, target_url, poc, "Vulnerable")
            
            # Returns true
            return True
        # Returns false
        return False

    # Method to log result
    def _log_result(self, vuln_type, url, poc, status):
        """Thread-safe result logging with deduplication"""

        # Creates a new signature
        sig = f"{vuln_type}-{url}"

        # Locks the thread intil it is finished
        with self.results_lock:
            # Checks if there is not dusplicate signatures detected
            if not any(f"{r['Vulnerability_Type']}-{r['Affected_URL']}" == sig for r in self.results):
                
                # Creates a new entry
                result_entry = {
                    "Vulnerability_Type": vuln_type,
                    "Affected_URL": url,
                    "Proof_Of_Concept": poc,
                    "Status": status
                }

                # Adds the entry to the results
                self.results.append(result_entry)

    # Method to save results to csv
    def save_results_to_csv(self, filename="command_injection_results.csv"):
        """Exports findings to a CSV file"""

        # Checks if there is not any results
        if not self.results:
            # Outputs no scans were found
            print("[!] No scans completed to export.")
            # Returns nothing
            return

        # Stores the keys to be used
        keys = ["Vulnerability_Type", "Affected_URL", "Proof_Of_Concept", "Status"]

        # Opens the file and adds the data in a csv format
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.results)

        # Outputs the final report is saved to a file
        print(f"[✓] Final report saved to {filename}")

    # Method to save vulnerable targets to txt
    def save_vulnerable_targets_to_txt(self, filename="vulnerable_targets.txt"):
        """Exports only the vulnerable URLs to a text file"""

        # Stores vulnerable urls
        vulnerable_urls = [result["Affected_URL"] for result in self.results if result["Status"] == "Vulnerable"]
        
        # Checks if there is not vulnerable urls
        if not vulnerable_urls:
            # Returns nothing
            return

        # Opens a file
        with open(filename, "w") as file:
            # Loops over each of the urls
            for url in vulnerable_urls:
                # Writes them to a file
                file.write(f"{url}\n")

        # Outputs the files was saved
        print(f"[✓] Vulnerable targets saved to {filename}")


def main():
    # Ouputs a header
    print("--- Command Injection Detection Scanner (commix + katana + subfinder) ---\n")

    # Allows the users to enter the target header
    target = input("[+] Enter Target URL: ").strip()

    # Allows the user to enter a session cookie
    cookie = input("[+] Enter Session Cookie (optional, press Enter to skip): ").strip()

    # Validates the target
    if not target.startswith("http"):
        # Ouputs an error message
        print("[!] Invalid URL. Make sure it includes http:// or https://")
        
        # Returns nothing
        return

    # Logs the start time
    start_time = time.perf_counter()

    # Creates the scanner object
    scanner = CommandInjectionDetection(target, cookie=cookie)

    # Outputs the reconaisense is starting 
    print(f"\n[+] Starting reconnaissance on {scanner.target_domain}\n")

    # Phase 1: Subdomain discovery
    domains = scanner.run_subfinder()

    # Phase 2: Deep crawl
    discovered_urls = scanner.run_katana(domains)

    # Checks if the target is not in the discovered urls
    if target not in discovered_urls:
        # Adds the target
        discovered_urls.insert(0, target)

    # Phase 3: Deduplicate
    unique_paths = {}

    # Loops over the urls that are discovered
    for url in discovered_urls:
        # Parses the urls
        parsed = urlparse(url)

        # Checks if the parsed path is not in unique paths
        if parsed.path not in unique_paths:
            # Stores the parsed path
            unique_paths[parsed.path] = url

    # Makes a list of all the targets from the oaths
    all_targets = list(unique_paths.values())
    
    # Prioritise param URLs
    param_urls = [url for url in all_targets if "?" in url]
    non_param_urls = [u for u in all_targets if "?" not in u]
    ordered = param_urls + non_param_urls

    # Organises the scan list
    scan_list = ordered[:MAX_SCAN_TARGETS] if MAX_SCAN_TARGETS is not None else ordered

    # Outputs the the amount of targets found
    print(f"[✓] Found {len(all_targets)} unique paths, selecting {len(scan_list)} for commix scanning.")
    print(f"\n[+] Running commix scan...\n")

    # Opens a number of threads to make the scans faster
    with ThreadPoolExecutor(max_workers=MAX_COMMIX_THREADS) as executor:
        executor.map(scanner.run_commix, scan_list)

    # Saves the scans to the results
    scanner.save_results_to_csv()
    scanner.save_vulnerable_targets_to_txt()

    # Calculates the elasped time
    elapsed = time.perf_counter() - start_time

    # Calculates the vulnerable hits
    vulnerable_hits = [r for r in scanner.results if r["Status"] == "Vulnerable"]
    
    # Outputs the final information
    print(f"\n[✓] Scan Complete in {elapsed:.2f} seconds.")
    print(f"[✓] CSV report contains {len(scanner.results)} scan records ({len(vulnerable_hits)} vulnerabilities).")

# Starts the program
if __name__ == "__main__":
    main()