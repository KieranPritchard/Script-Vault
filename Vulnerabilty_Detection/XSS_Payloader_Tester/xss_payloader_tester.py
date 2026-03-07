import requests
import time
import subprocess
import os
import json
import shutil
from urllib.parse import urljoin, urlparse

class XSSPayloadTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []
        # Try to find dalfox outside of the snap folder first to avoid permission bugs
        self.dalfox_path = shutil.which("dalfox")
        if self.dalfox_path and "/snap/" in self.dalfox_path:
            alt_path = "/usr/local/bin/dalfox"
            if os.path.exists(alt_path):
                self.dalfox_path = alt_path

    def run_dalfox_fixed(self, target_url):
        # If no params, append a common test param to force Dalfox to work
        if "?" not in target_url:
            target_url += "?id=1&query=test&name=user"
            print(f"[*] No parameters found. Appending discovery params: {target_url}")

        print(f"[*] Launching Dalfox on: {target_url}")
        
        # Command setup
        command = [self.dalfox_path, "url", target_url, "--worker", "5", "--silence", "--no-color", "--format", "json"]

        try:
            # We check if we're in a snap environment and try to fix the execution
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                env=dict(os.environ, DISABLE_WAYLAND="1") # Sometimes helps snap apps
            )

            stdout, stderr = process.communicate(timeout=120)

            if "snap-confine" in stderr:
                print("[!] Snap Error Detected. Attempting to run with 'nosnap' flags or local PATH...")
                # Fallback: Try calling dalfox directly if it exists in a common local bin
                if os.path.exists("/usr/bin/dalfox"):
                    command[0] = "/usr/bin/dalfox"
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    stdout, stderr = process.communicate(timeout=120)

            for line in stdout.splitlines():
                if line.startswith('{'):
                    try:
                        data = json.loads(line)
                        print(f"[!] HIT: {data.get('type')} on {data.get('param')}")
                        self.results.append(data)
                    except: pass
            
            if not self.results and not stderr:
                print("[-] No vulnerabilities found, but tool executed successfully.")
            elif stderr and not stdout:
                print(f"[!] Error Output: {stderr.strip()}")

        except Exception as e:
            print(f"[-] Execution Error: {e}")

def main():
    target = input("Enter Target: ").strip()
    scanner = XSSPayloadTester(target)
    if not scanner.dalfox_path:
        print("Please install Dalfox using: 'go install github.com/hahwul/dalfox/v2@latest' to avoid Snap issues.")
        return
    scanner.run_dalfox_fixed(target)

if __name__ == "__main__":
    main()