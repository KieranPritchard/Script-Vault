import nmap

# Function to open target file and load the targets
def load_targets(file):
    # Stores the targets in a list
    targets = []
    
    # Opens the text file
    with open(file, "r") as f:
        # Loops over the file
        for target in f:
            # Adds the targets 
            targets.append(target)

    return targets

def scan_targets(targets):
    # Creates scanner object
    scanner = nmap.PortScanner()

    # Loops over the targets
    for target in targets:
        # Scans the target for services and os detection
        scanner.scan(target, arguments="-sV -O -T4")
        # Outputs the target being scanned 
        print(f"Scan for {target}:")
        # Loops over the protocols in the targe
        for proto in scanner[target].all_protocols():
            # Looping over the ports in the targets
            for port in scanner[target][proto]:
                # Gets the state 
                state = scanner[target][proto][port]['state']
                # Outputs the port and protcol with the state
                print(f"  {port}/{proto} - {state}")