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
    def __init__(self, target_url, threads=5, profile="normal"):
        # Basic configuration and target parsing
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.threads = threads
        self.profile = profile
        
        # Tracking and storage
        self.results = []        # Stores full dictionaries for CSV export
        self.vulnerable = []     # Stores only vulnerable URLs for TXT export
        
        # Threading safety locks
        self.print_lock = threading.Lock()    # Prevents garbled console output
        self.results_lock = threading.Lock()  # Prevents data loss during list appends

    # ---------------------------
    # CRAWLER
    # ---------------------------

    def run_katana(self, target):
        """Crawl for hidden endpoints using Project Discovery's Katana"""

        # Verifies if the tool exists in the system path
        if not shutil.which("katana"):
            print("[!] Katana not found. Skipping crawl.")
            return []

        discovered = []
        print(f"[*] Starting Katana deep crawl on {target}...")

        # Ensures the URL has a protocol prefix
        formatted_target = target if "://" in target else f"http://{target}"

        try:
            # Runs katana with JS crawling and no-colors enabled
            cmd = ["katana", "-u", formatted_target, "-depth", "3", "-silent", "-nc", "-jc"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Cleans the output lines and filters empty strings
            discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except Exception as e:
            print(f"[!] Katana Error: {e}")
        
        # Filters duplicates before returning
        return list(set(discovered))

    def run_subfinder(self):
        """Discover subdomains to broaden the attack surface"""

        # Verifies tool installation
        if not shutil.which("subfinder"):
            print("[!] Subfinder not found. Using root domain only.")
            return [self.domain]

        print(f"[*] Discovering subdomains for {self.domain}...")

        try:
            # Executes silent subdomain enumeration
            result = subprocess.run(["subfinder", "-d", self.domain, "-silent"], capture_output=True, text=True)
            found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            
            # Returns discovered subdomains or the root domain as a fallback
            return found if found else [self.domain]
        except Exception:
            return [self.domain]

    # ---------------------------
    # SQLMAP COMMAND BUILDER
    # ---------------------------
    
    def build_sqlmap_cmd(self, url):
        """Constructs the sqlmap command based on the selected profile"""

        # Default parameters used across all scans
        base_cmd = [
            "sqlmap",
            "-u", url,
            "--batch",           # Never ask for user input
            "--random-agent",    # Use random browser headers
            "--output-dir=sqlmap_results"
        ]

        # Applies profile-specific aggression settings
        if self.profile == "stealth":
            # Low level/risk and high delay to bypass WAF/IDS
            base_cmd += ["--level=1", "--risk=1", "--threads=1", "--delay=2"]
        elif self.profile == "aggressive":
            # Maximum depth and multiple techniques enabled
            base_cmd += ["--level=5", "--risk=3", "--threads=10", "--technique=BEUST", "--crawl=2", "--forms"]
        else:  
            # Balanced settings for standard testing
            base_cmd += ["--level=3", "--risk=2", "--threads=5", "--technique=BEUST"]

        return base_cmd

    # ---------------------------
    # RUN SQLMAP
    # ---------------------------

    def run_sqlmap(self, url):
        """Executes sqlmap and parses the raw output for data extraction"""

        cmd = self.build_sqlmap_cmd(url)

        # Standardizes console logging across threads
        with self.print_lock:
            print(f"[>] Testing: {url}")

        try:
            # Runs the tool and captures the full stdout
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout

            # Logic to determine if the target is actually exploitable
            is_vulnerable = any(phrase in output.lower() for phrase in ["is vulnerable", "confirming microsoft sql server"])

            # Uses regex to pull the specific DB type (e.g. MySQL)
            dbms = self._extract_value(r"back-end DBMS: (.*?)(?:\s|\n|$)", output)
            
            # Uses regex to find the exploitation types (e.g. error-based, time-based)
            techniques = re.findall(r"Type: (.*?)[\s\n]", output)

            # Formats the data into a structured record for analysis
            record = {
                "url": url,
                "vulnerable": is_vulnerable,
                "technique": ",".join(set(techniques)) if techniques else "N/A",
                "dbms": dbms if dbms else "Unknown",
                "profile": self.profile,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

            # Safely updates shared lists using a lock
            with self.results_lock:
                self.results.append(record)
                if is_vulnerable:
                    # Adds to the specific list for TXT export
                    self.vulnerable.append(url)

            # Instant feedback if a hit is confirmed
            if is_vulnerable:
                with self.print_lock:
                    print(f"[!] SQLi Found: {url} | DBMS: {dbms}")

        except Exception as e:
            with self.print_lock:
                print(f"[ERROR] {url} → {e}")

    def _extract_value(self, pattern, text, flags=re.IGNORECASE):
        """Helper to safely extract regex groups without crashing"""
        match = re.search(pattern, text, flags)
        return match.group(1).strip() if match else None

    # ---------------------------
    # SCAN ALL TARGETS
    # ---------------------------

    def scan(self):
        """Main scanning orchestration logic"""

        # Create output directory if it doesn't exist
        if not os.path.exists("sqlmap_results"):
            os.makedirs("sqlmap_results")

        # Step 1: Find subdomains
        subdomains = self.run_subfinder()

        # Step 2: Crawl each subdomain for entry points
        for subdomain in subdomains:
            targets = self.run_katana(subdomain)

            if not targets:
                print(f"[-] No parameters found on {subdomain}")
                continue

            print(f"[*] Testing {len(targets)} injection points on {subdomain}...\n")

            # Step 3: Run multithreaded sqlmap instances
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.run_sqlmap, targets)

    # ---------------------------
    # SAVE RESULTS
    # ---------------------------

    def save_results(self):
        """Exports data to CSV for analysis and TXT for vulnerable targets"""
        
        if not self.results:
            print("\n[-] No data collected.")
            return

        timestamp = int(time.time())
        csv_filename = f"sqlmap_analysis_{timestamp}.csv"
        txt_filename = f"vulnerable_urls_{timestamp}.txt"

        # Export ALL records (vulnerable and non-vulnerable) to CSV
        try:
            with open(csv_filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
            print(f"\n[+] Comprehensive analysis saved to: {csv_filename}")
        except Exception as e:
            print(f"[ERROR] CSV Save Failed: {e}")

        # Export ONLY vulnerable URLs to a simple text file
        if self.vulnerable:
            with open(txt_filename, "w") as f:
                # Use set() to ensure we don't save the same URL twice
                for url in sorted(set(self.vulnerable)):
                    f.write(url + "\n")
            print(f"[+] Clean vulnerable list saved to: {txt_filename}")
        else:
            print("[-] No vulnerable URLs to save to TXT.")

    # ---------------------------
    # RUN EVERYTHING
    # ---------------------------

    def run(self):
        """High-level execution flow"""
        start_time = time.time()

        self.scan()
        self.save_results()

        duration = time.time() - start_time
        print(f"\n[✓] Total Execution Time: {duration:.2f}s")


# ---------------------------
# MAIN FUNCTION
# ---------------------------

def main():
    """Handles the user interface and initial setup"""
    
    print("=" * 40)
    print("  SQLMAP AUTOMATED SCANNER & ANALYSER  ")
    print("=" * 40)

    # User Input Handling
    target = input("Enter Target Domain (e.g., target.com): ").strip()
    if not target:
        print("[!] Target required.")
        return

    print("\n[Profiles] stealth, normal, aggressive")
    prof = input("Select Profile [normal]: ").strip().lower()
    if prof not in ["stealth", "normal", "aggressive"]:
        prof = "normal"

    try:
        thread_count = input("Thread Count [5]: ").strip()
        threads = int(thread_count) if thread_count else 5
    except ValueError:
        threads = 5

    # Start the engine
    scanner = SQLMapScanner(target, threads=threads, profile=prof)
    scanner.run()


if __name__ == "__main__":
    main()