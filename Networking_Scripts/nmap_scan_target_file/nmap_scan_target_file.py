import nmap
import os

# Function to open target file and load the targets
def load_targets(file):
    # Stores the targets in a list
    targets = []
    
    try:
        # Opens the text file
        with open(file, "r") as f:
            # Loops over the file
            for target in f:
                # Adds the targets 
                targets.append(target.strip())
    except Exception as e:
        print(f"Error encountered: {e}")

    return targets

def scan_targets(targets):
    # Creates scanner object
    scanner = nmap.PortScanner()

    # Loops over the targets
    for target in targets:
        # Scans the target for services and os detection
        scanner.scan(target, arguments="-sV -O -T4")
        # Outputs the target being scanned 
        print(f"[+] Scan for {target}:")
        # Loops over the protocols in the targe
        for proto in scanner[target].all_protocols():
            # Looping over the ports in the targets
            for port in scanner[target][proto]:
                # Gets the state 
                state = scanner[target][proto][port]['state']
                # Outputs the port and protcol with the state
                print(f"  {port}/{proto} - {state}")

def main():
    while True:
        try:
            targets_list = input("Enter the path of the targets file: ")

            if os.path.isfile(targets_list):
                break
            else:
                print("[!] File not found. Try again.")
        except Exception as e:
            print(f"Error encountered: {e}")

    print(f"[+] Loading targets from {targets_list}")
    targets = load_targets(targets_list)
    if targets:
        print(f"[+] Loaded targets from {targets_list}")
        print(f"[+] Scanning {len(targets)} Target(s)")
        scan_targets(targets)
    else:
        print(f"[!] No targets from {targets_list}")