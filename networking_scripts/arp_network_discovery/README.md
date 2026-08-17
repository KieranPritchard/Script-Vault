# Script: ARP Network Discovery

## Project Description

### Objective

To create a script that automatically discovers active hosts on a network by resolving IP addresses to their corresponding MAC addresses using ARP requests.

### Features

* Sends ARP broadcast requests to a specified network range
* Captures and parses ARP responses in real time
* Extracts and displays IP and MAC address pairs in a clean format
* Measures and outputs total execution time
* Handles user input safely to avoid script crashes

### Technologies and Tools Used

* **Language:** Python
* **Librarys:** Scapy, time
* **Tools:** git, VS code.

### Challenges Faced

I had issues extracting the data from the returned Scapy objects. I initially struggled because the responses were being appended as a list of packet tuples rather than individual values. I resolved this by iterating over the returned list correctly and accessing the received packet fields (psrc and hwsrc) directly.

### Outcome

The final script successfully scans a given network range and returns a list of live hosts along with their MAC addresses. It runs quickly, produces readable output, and serves as a solid foundation for further network enumeration or security automation tasks.

### How To Use Script

1. **Set Up Your Environment**
- Ensure you are using a Linux system.
- Install Scapy if it is not already installed:
```
sudo apt install python3-scapy
```
2. **Run the script with root privileges (required for ARP packets).**
- Save the Script
- Save the script to a file, for example:
```
arp_discovery.py
```
3. **Run the Script**
* Execute the script with Python:
```
sudo python3 arp_discovery.py
```
4. **Script Behavior**
* Prompts the user to enter a network range (e.g. 192.168.1.0/24)
* Sends ARP broadcast packets across the specified network
* Collects responses from active hosts
* Displays discovered IP and MAC address pairs
* Outputs total runtime upon completion

5. **Review Results**
* Active devices on the network will be displayed directly in the terminal:
```
IP: 192.168.1.1    MAC: aa:bb:cc:dd:ee:ff
```
* Execution time is displayed at the end of the scan:
```
[✓] Finished in 0.42 seconds
```