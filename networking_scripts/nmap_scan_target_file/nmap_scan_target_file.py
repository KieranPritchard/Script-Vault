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

def scan_targets(targets, speed):
    # Creates scanner object
    scanner = nmap.PortScanner()

    # Loops over each of the targets
    for target in targets:
        # Outputs the target being scanned
        print(f"[+] Scanning {target}")

        try:
            # Scans the target with service and os detection
            scanner.scan(target, arguments=f"-sV -O -T{speed}")
        except nmap.PortScannerError as e:
            # Outputs the error
            print(f"[!] Nmap error: {e}")
            # Continues to the next target
            continue
        
        # Gets all the hosts from the scaners
        hosts = scanner.all_hosts()
        # Checks if there isnt any hosts
        if not hosts:
            # Outputs no hosts responded
            print("[!] No hosts responded")
            # Continues to the next target
            continue
        
        # Loops over the hosts
        for host in hosts:
            # Outputs the host and the host name being scanned
            print(f"[+] Host: {host} ({scanner[host].hostname()})")

            # Checks if the host stat is up
            if scanner[host].state() != "up":
                # Outputs the host state
                print(f"[!] Host is {scanner[host].state()}")
                # Conntinues to the next loop
                continue

            # Checks for os type
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                # Outputs the os detection header
                print("[+] OS Detection:")
                # Loops over the os matches
                for osmatch in scanner[host]['osmatch']:
                    # Outputs the os names and accuracy
                    print(f"    {osmatch['name']} ({osmatch['accuracy']}%)")
            else:
                # Outputs error message
                print("[!] No OS fingerprint available")

            # Gets protocols from the host
            protocols = scanner[host].all_protocols()
            # Checks if there is not any protocols
            if not protocols:
                # Outputs no open ports found
                print("[!] No open ports found")
                # Continues to next iteration
                continue
            
            # Outputs open ports header
            print("[+] Open Ports:")
            # Loops over the protocols
            for proto in protocols:
                # Loops over the ports
                for port in scanner[host][proto]:
                    # Gets the state of the port
                    state = scanner[host][proto][port]['state']
                    # Prints the port and protocols state
                    print(f"    {port}/{proto} - {state}")

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
            speed = int(input("Enter the scan speed (1-5): "))

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

if __name__ == "__main__":
    main()