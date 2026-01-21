# Script: Full Nmap Scan

## Project Description

### Objective

To create a comprehensive automation script that performs a deep-dive scan of a target IP, identifying open ports, service versions, OS details, and potential vulnerabilities using Nmap Scripting Engine (NSE).

### Features

* Dual Mode Execution: Offers a "Live View" for quick terminal results or a "Report Mode" for generating permanent documentation.

* Complete Port Coverage: Scans the entire TCP port range (1–65535) to ensure no non-standard services are missed.

* Deep Enumeration: Combines Service Versioning (-sV), OS Detection (-O), and Aggressive timing (-T4) for high-speed, detailed data collection.

* Automated NSE Scripting: Runs "default" and "safe" Nmap scripts to detect common configurations and security info without crashing services.

* Organized Reporting: Automatically creates dated directories and exports results in three formats (.nmap, .xml, and .gnmap) for professional auditing.

### Technologies and Tools Used

* **Language:** Bash
* **Tools:** Nmap, Grep, VS Code, Git.

### Challenges Faced

There was an issue with finding out how to detect if the script was running with sudo or not. However, I found out via AI help that $EUID detects if the script is in sudo or not. This was critical because OS detection and SYN scans require raw socket access only available to the root user.

### Outcome

The final script serves as a powerful "all-in-one" tool for the initial enumeration phase of a security audit. It eliminates the need to remember complex Nmap flags and ensures that every scan is performed consistently and saved correctly for later analysis.

### How To Use Script

1. **Set Up Your Environment**

* Ensure you are using a Linux system.
* Install Nmap:

```Bash
sudo apt update && sudo apt install nmap -y
```

2. **Prepare the Script**

* Save the code to a file named full_scan.sh.

* Give the script execution permissions:

```Bash
chmod +x full_scan.sh
```

3. **Run the Script**

* The script requires a target IP and an optional "mode" parameter.

* Option A: Terminal View (Quick) This displays only open ports and their services directly in your terminal.

```Bash
sudo ./full_scan.sh 192.168.1.1
Option B: Full Report (Comprehensive) This runs a deep scan and saves all results to a organized folder.
```

```Bash
sudo ./full_scan.sh 192.168.1.1 save
```

4. **Script Behavior**

* Privilege Check: Immediately stops if not run with sudo.

* Directory Management: If "save" is used, it creates a folder structure: nmap_reports/scan_[IP]_[TIMESTAMP]/.

* Scan Logic: * -p-: Scans all 65,535 ports.

* -A: Enables OS detection, version detection, script scanning, and traceroute.

* --script=default,safe: Runs non-intrusive scripts to gather extra info (like SSL cert details or SSH keys).

5. Review Results

* If you used the save mode, your results will be stored in the nmap_reports folder. You can view the text report using:

```Bash
cat nmap_reports/scan_192.168.1.1_2024-xx-xx/full_scan.nmap
```