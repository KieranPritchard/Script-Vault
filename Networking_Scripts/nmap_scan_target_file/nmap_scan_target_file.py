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

def scan_targets(targets,speed):
    # Creates scanner object
    scanner = nmap.PortScanner()

    # Loops over the targets
    for target in targets:
        # Scans the target for services and os detection
        scanner.scan(target, arguments=f"-sV -O -T{speed}")
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
    # Loops while input is not correct
    while True:
        try:
            # asks for the targets file location
            targets_list = input("Enter the path of the targets file: ")

            # Checks if the path is a file
            if os.path.isfile(targets_list):
                # breaks the loop
                break
            else:
                # Outputs error message
                print("[!] File not found. Try again.")
        except Exception as e:
            # Outputs error message
            print(f"Error encountered: {e}")

    # Loops while input is not correct
    while True:
        try:
            # asks for the targets file location
            speed = input("Enter the scan speed (1-5): ")

            # Checks if the path is a file
            if speed in range(1,5):
                # breaks the loop
                break
            else:
                # Outputs error message
                print("[!] File not found. Try again.")
        except Exception as e:
            # Outputs error message
            print(f"Error encountered: {e}")

    # Outputs the targets are being loaded
    print(f"[+] Loading targets from {targets_list}")
    # Stores the loaded targeets from the function
    targets = load_targets(targets_list)
    # Checks if there are any targets returned
    if targets:
        # Outputs the targets are loaded and number of targets scanned
        print(f"[+] Loaded targets from {targets_list}")
        print(f"[+] Scanning {len(targets)} Target(s)")
        # Scanns the targets
        scan_targets(targets, speed)
    else:
        # Outputs there are no targets in the targets list
        print(f"[!] No targets from {targets_list}")