import re
import shutil
import subprocess
import threading
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse


class SQLMapScanner:
    def __init__(self, target_url, threads=5, profile="normal", cookie=None):
        # Basic configuration and target parsing
        self.target_url = target_url
        
        # Ensures the domain is correctly parsed even without http prefix
        parsed_url = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        self.domain = parsed_url.netloc
        
        self.threads = threads
        self.profile = profile
        self.cookie = cookie  # Stores session cookies for authenticated sites
        
        # Tracking and storage
        self.results = []        # Stores full dictionaries for CSV export
        self.vulnerable = []     # Stores only vulnerable URLs for TXT export
        
        # Threading safety locks
        self.print_lock = threading.Lock()    # Prevents garbled console output
        self.results_lock = threading.Lock()  # Prevents data loss during list appends

    def is_in_scope(self, url):
        """Verifies the URL belongs to our target domain to prevent scope creep"""
        try:
            # Parses the discovered URL
            parsed = urlparse(url)
            # Checks if the found domain matches our target domain
            return parsed.netloc == self.domain
        except Exception:
            return False

    # ---------------------------
    # CRAWLER
    # ---------------------------

    def run_katana(self, target):
        """Crawl for hidden endpoints using Project Discovery's Katana"""

        # Verifies if the tool exists in the system path
        if not shutil.which("katana"):
            print("[!] Katana not found. Skipping crawl.")
            return []

        # Empty list to store discovered urls
        discovered = []

        # Outputs katana is starting
        print(f"[*] Starting Katana deep crawl on {target}...")

        # Formats the target
        formatted_target = target if "://" in target else f"http://{target}"

        try:
            # Builds the command with JS crawling and no-colors enabled
            cmd = ["katana", "-u", formatted_target, "-depth", "3", "-silent", "-nc", "-jc"]
            
            # Adds cookies to katana if they are provided
            if self.cookie:
                cmd += ["-headers", f"Cookie: {self.cookie}"]
            
            # Gets the result for the target
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Cleans the output lines and filters empty strings
            raw_list = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            
            # Filters out external domains and only keeps URLs with parameters
            for url in raw_list:
                if self.is_in_scope(url) and "?" in url:
                    discovered.append(url)
                    
        except Exception as e:
            print(f"[!] Katana Error: {e}")
        
        # Returns a list without duplicates
        return list(set(discovered))

    def run_subfinder(self):
        """Subdomain discovery function using subfinder"""

        # Verifies tool installation
        if not shutil.which("subfinder"):
            print("[!] Subfinder not found. Using root domain only.")
            return [self.domain]

        # Outputs the program is discovering subdomains
        print(f"[*] Discovering subdomains for {self.domain}...")

        try:
            # Gets the result of the scan
            result = subprocess.run(["subfinder", "-d", self.domain, "-silent"], capture_output=True, text=True)
            
            # Returns the domains found or falls back to root
            found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return found if found else [self.domain]
        except Exception:
            return [self.domain]

    # ---------------------------
    # SQLMAP COMMAND BUILDER
    # ---------------------------
    
    def build_sqlmap_cmd(self, url):
        """Function to build sqlmap command"""

        # Stores the base command
        base_cmd = [
            "sqlmap",
            "-u", url,
            "--batch",           # Never ask for user input
            "--random-agent",    # Use random browser headers
            "--output-dir=sqlmap_results"
        ]

        # Adds cookies if we are testing a site like DVWA
        if self.cookie:
            base_cmd += [f"--cookie={self.cookie}"]

        # Profiles for different testing scenarios

        # Checks which profile is selected
        if self.profile == "stealth":
            # Adds the new commands to the base command
            base_cmd += ["--level=1", "--risk=1", "--threads=1", "--delay=2"]
        elif self.profile == "aggressive":
            # Adds the new commands to the base command
            base_cmd += ["--level=5", "--risk=3", "--threads=10", "--technique=BEUST"]
        else:  # normal otherwise
            # Adds the new commands to the base command
            base_cmd += ["--level=3", "--risk=2", "--threads=5"]

        # Returns the command
        return base_cmd

    # ---------------------------
    # RUN SQLMAP
    # ---------------------------

    def run_sqlmap(self, url):
        """Function to run sql map"""

        # Stores the command to use in the function
        cmd = self.build_sqlmap_cmd(url)

        # Locks the output until the thread is finished
        with self.print_lock:
            # Outputs the function being tested
            print(f"[>] Testing: {url}")

        try:
            # Stores the result from the command
            result = subprocess.run(cmd, capture_output=True, text=True)
            # Stores the output
            output = result.stdout

            # Extraction Logic to check if the target is vulnerable
            is_vulnerable = any(phrase in output.lower() for phrase in ["is vulnerable", "confirming microsoft sql server"])

            # Extract metadata using regex patterns
            dbms = self._extract_value(r"back-end DBMS: (.*?)(?:\s|\n|$)", output)
            techniques = re.findall(r"Type: (.*?)[\s\n]", output)

            # Fits the data into a record dictionary
            record = {
                "url": url,
                "vulnerable": is_vulnerable,
                "technique": ",".join(set(techniques)) if techniques else "N/A",
                "dbms": dbms if dbms else "Unknown",
                "profile": self.profile,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

            # Uses results_lock to safely append to shared lists
            with self.results_lock:
                # Adds to the records
                self.results.append(record)
                if is_vulnerable:
                    # Adds to the list for txt export
                    self.vulnerable.append(url)

            # Checks if the result is vulnerable for console output
            if is_vulnerable:
                with self.print_lock:
                    # Outputs the sql discovery
                    print(f"[!] SQLi Found: {url} | DBMS: {dbms}")

        except Exception as e:
            with self.print_lock:
                # Outputs the error
                print(f"[ERROR] {url} → {e}")

    def _extract_value(self, pattern, text, flags=re.IGNORECASE):
        """Private method to extract values with regex"""
        match = re.search(pattern, text, flags)
        return match.group(1).strip() if match else None

    # ---------------------------
    # SCAN ALL TARGETS
    # ---------------------------

    def scan(self):
        """Function to run the crawl and scan on the website"""

        # Create output directory if it doesn't exist
        if not os.path.exists("sqlmap_results"):
            os.makedirs("sqlmap_results")

        # Extracts the subdomains
        subdomains = self.run_subfinder()

        # Loops over the subdomains
        for subdomain in subdomains:

            # Stores the targets found by Katana
            targets = self.run_katana(subdomain)

            # Checks if any valid targets were found
            if not targets:
                print(f"[-] No valid in-scope parameters found on {subdomain}")
                continue

            # Outputs launching scans
            print(f"[*] Launching sqlmap scans for {subdomain}...\n")

            # Runs sqlmap threads using the threadpool
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.run_sqlmap, targets)

    # ---------------------------
    # SAVE RESULTS
    # ---------------------------

    def save_results(self):
        """Function to save found vulnerabilities and full analysis"""
        
        # Checks if any results were collected
        if not self.results:
            print("\n[-] No data collected.")
            return

        # Generates a timestamp for unique filenames
        timestamp = int(time.time())
        csv_filename = f"analysis_{timestamp}.csv"
        txt_filename = f"vulnerable_{timestamp}.txt"

        # Export ALL records to CSV for full analysis
        try:
            with open(csv_filename, "w", newline="", encoding="utf-8") as f:
                # Sets up the CSV writer with headers
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
            print(f"\n[+] Full analysis data saved to {csv_filename}")
        except Exception as e:
            print(f"[ERROR] Could not save CSV: {e}")

        # Save just the vulnerable ones to TXT for easy reading
        if self.vulnerable:
            with open(txt_filename, "w") as f:
                # Loops over unique vulnerable URLs
                for url in sorted(set(self.vulnerable)):
                    f.write(url + "\n")
            print(f"[+] Vulnerable URL list saved to {txt_filename}")
        else:
            print("[-] No vulnerable URLs found to save.")

    # ---------------------------
    # RUN EVERYTHING
    # ---------------------------

    def run(self):
        """Main entry method for the class"""
        start = time.time()

        # Starts the scan orchestration
        self.scan()
        
        # Saves the final results to disk
        self.save_results()

        # Calculates and outputs elapsed time
        elapsed = time.time() - start
        print(f"\n[✓] Completed in {elapsed:.2f}s")


# ---------------------------
# MAIN FUNCTION
# ---------------------------

def main():
    """Main execution function to handle user inputs"""
    
    # Simple banner output
    print("=" * 40)
    print(" SCOPE-LOCKED SQLi SCANNER ")
    print("=" * 40)

    # Gets the target domain from the user
    target = input("Enter Target Domain (e.g. localhost:4280): ").strip()
    if not target:
        print("[!] No target provided. Exiting.")
        return

    # Gets cookies from user if they are testing protected sites
    print("\n[Optional] Enter Cookies (e.g. PHPSESSID=xxx; security=low)")
    cookie_input = input("Cookie string: ").strip()

    # Gets the profile selection from user
    print("\nProfiles: stealth, normal, aggressive")
    profile_input = input("Select Profile [normal]: ").strip().lower()
    if profile_input not in ["stealth", "normal", "aggressive"]:
        profile_input = "normal"

    # Initializes the scanner class
    scanner = SQLMapScanner(target, threads=10, profile=profile_input, cookie=cookie_input)
    
    # Runs the scanner
    scanner.run()


if __name__ == "__main__":
    # Calls the main function
    main()