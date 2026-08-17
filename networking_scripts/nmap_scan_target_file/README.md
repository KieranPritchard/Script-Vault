# Script: Full Nmap Scan

## Project Description

### Objective

To create a Python-based automation tool that ingests a file containing multiple IP addresses and performs a serialized, deep-scan on each. This script aims to consolidate OS detection, service versioning, and port status into a single, readable output for bulk network auditing.

### Features

* Bulk Processing: Reads targets from an external .txt or .csv file, allowing for the scanning of dozens of hosts without manual intervention.

* Intelligent Error Handling: Uses try-except blocks to handle missing files or Nmap execution errors, ensuring one failed host doesn't crash the entire batch.

* Dynamic Speed Control: Prompts the user for Nmap timing templates (-T1 through -T5), allowing the user to choose between stealth (slower) or speed (faster).

* OS Fingerprinting: Leverages Nmap's OS matching logic to predict the target's operating system and accuracy percentage.

* State Filtering: Automatically identifies the "state" of the host and individual ports (e.g., up, down, open).

### Technologies and Tools Used

* Language: Python 3

* Library: python-nmap (Wrapper for the Nmap engine)

* Tools: VS Code, Git, Nmap.

### Challenges Faced

I had an issue with accessing the OS matches within the scan results. I noticed that the scanner[host] object returns deeply nested data structures. I used AI to help me understand how to reference the dictionary keys specifically (e.g., ['osmatch']) and how to iterate through those matches to extract the name and accuracy values correctly.

### Outcome

The script successfully automates the reconnaissance phase of a security audit. By moving from Bash to Python, the data is much easier to manipulate and display. This tool significantly reduces the time required to audit large subnets by replacing manual per-IP commands with a single automated file-read process.

### How To Use Script

1. **Set Up Your Environment**

* Ensure Nmap is installed on your Linux system.

* Install the Python Nmap library:

```Bash
pip install python-nmap
```
2. **Prepare the Targets File**

* Create a file (e.g., targets.txt) with one IP address or hostname per line:

```Plaintext
192.168.1.1
192.168.1.50
google.com
```

3. **Run the Script**

* Save the code as multi_scan.py.
* Run the script with root privileges (required for OS detection):

```Bash
sudo python3 multi_scan.py
```

4. **Script Behavior**

* Target Loading: The script asks for the path to your targets.txt.
* Speed Selection: Input a number from 1 to 5.
* Note: T4 is recommended for most stable networks.
* Execution: The script iterates through every IP in the file.
* Data Extraction: It pulls the hostname, OS possibilities, and all open TCP ports.

5. **Review Results**

* Results are printed directly to the terminal in an organized format:

```Plaintext
[+] Scanning 192.168.1.1
[+] Host: 192.168.1.1 (router.local)
[+] OS Detection:
    Linux 5.0 (96%)
[+] Open Ports:
    80/tcp - open
    443/tcp - open
```