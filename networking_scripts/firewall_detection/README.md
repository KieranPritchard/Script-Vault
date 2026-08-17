# Script: Firewall Detection

## Project Description

### Objective

To create a script that uses Nmap to detect which ports are being monitored or blocked via firewalls by identifying "filtered" states.

### Features

* Root Privilege Validation: Automatically checks for root/sudo access required for Stealth SYN scans.
* Full Port Range Scanning: Scans all 65,535 ports to ensure no hidden services are missed.
* Firewall Identification: Specifically filters for open and filtered ports to distinguish between reachable services and those behind a packet filter.
* Reason Analysis: Uses the --reason flag to explain why Nmap flagged a port as filtered (e.g., "no-response" or "admin-prohibited").
* Dependency Check: Verifies if Nmap is installed before attempting to run.

### Technologies and Tools Used

* **Language:** Bash
* **Tools:** Nmap, Grep, VS Code, Git.

### Challenges Faced

I had problems with picking up filtered ports; this was fixed by changing the grep command in the script. I added the "filtered" keyword to the regex pattern to ensure that ports blocked by a firewall were included in the output alongside open ports.

### Outcome

The script provides a streamlined way to audit network security. By isolating "filtered" ports, a system administrator can quickly identify which firewall rules are active and which ports are unintentionally exposed. The use of SYN scanning (-sS) allows for a faster, less intrusive scan compared to a full TCP connect scan.

### How To Use Script

1. **Set Up Your Environment**

* Ensure you are using a Linux-based system (Kali, Ubuntu, etc.).
* Install Nmap if it is not already installed:

```Bash
sudo apt update && sudo apt install nmap -y
```

2. **Prepare the Script**

* Save the code to a file named firewall_det.sh.
* Give the script execution permissions:

```Bash
chmod +x firewall_det.sh
```

3. **Run the Script**

* Execute the script using sudo (required for the -sS SYN scan logic):

```Bash
sudo ./firewall_det.sh <Target_IP>
```
* Example: sudo ./firewall_det.sh 192.168.1.1


4. **Script Behavior**

* Dependency Check: Checks if Nmap is present on the system.
* Privilege Check: Ensures the user is running as root.
* Scan Execution: Runs a stealth scan on all ports while ignoring host discovery (-Pn) to bypass basic "ping-block" firewall rules.
* Output: Filters the noise to show only relevant port statuses.

5. **Review Results**

* The terminal will display the port, its state, and the reason for that state:

```Plaintext
[+] Starting Nmap scan against: 192.168.1.1
[+] Results found
80/tcp    open      http           syn-ack
443/tcp   open      https          syn-ack
22/tcp    filtered  ssh            no-response
```

* Open: The service is reachable.

* Filtered: A firewall, filter, or other network obstacle is covering the port.