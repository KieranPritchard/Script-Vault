import requests
import time
import subprocess
import os
import json
import shutil
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

print_lock = Lock()

class XSSPayloadTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []
        self.results_lock = Lock()
        self.dalfox_path = shutil.which("dalfox")
        
        if not self.dalfox_path:
            print("[!] CRITICAL: Dalfox not found in your PATH. Please install it.")

    def run_dalfox_live(self, target_url):
        """Runs Dalfox and streams output to the console in real-time."""
        with print_lock:
            print(f"\n[*] Starting Deep Scan on: {target_url}")

        # Command optimized for maximum discovery and JSON output
        command = [
            self.dalfox_path, "url", target_url,
            "--worker", "10",            # Increase parallel workers
            "--waf-evasion",             # Try to bypass basic WAFs
            "--silence",                 # Keep output clean for our parser
            "--no-color",                # Remove ANSI codes for easier parsing
            "--format", "json"           # Standardize result format
        ]

        try:
            # We use bufsize=1 and universal_newlines=True for line-by-line streaming
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1
            )

            # Read output as it comes in
            for line in iter(process.stdout.readline, ''):
                clean_line = line.strip()
                if not clean_line: continue

                # Print the raw line so you can see progress
                with print_lock:
                    print(f"  [Dalfox Output] {clean_line}")

                # Try to parse if it's a finding (JSON)
                if clean_line.startswith('{') and clean_line.endswith('}'):
                    try:
                        data = json.loads(clean_line)
                        self._log_result(
                            f"Dalfox-{data.get('type', 'R')}", 
                            data.get("poc"), 
                            "Vulnerable", 
                            data.get("param")
                        )
                    except: pass

            process.stdout.close()
            process.wait()

        except Exception as e:
            with print_lock:
                print(f"[-] Subprocess Error: {e}")

    def _log_result(self, xtype, payload, status, param):
        sig = f"{xtype}-{param}-{payload}"
        with self.results_lock:
            if not any(f"{r['type']}-{r['parameter']}-{r['payload']}" == sig for r in self.results):
                self.results.append({"type": xtype, "payload": payload, "status": status, "parameter": param})
                with print_lock:
                    print(f"\n[!!!] HIT FOUND: {xtype} on {param}\nPoC: {payload}\n")

def main():
    target = input("Enter Target (with params, e.g., http://example.com/p.php?id=1): ").strip()
    if "?" not in target:
        print("[!] Warning: Dalfox works best on URLs with active parameters.")
    
    scanner = XSSPayloadTester(target)
    scanner.run_dalfox_live(target)

    print(f"\n[✓] Scan Finished. Total Unique Hits: {len(scanner.results)}")

if __name__ == "__main__":
    main()