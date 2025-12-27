# Script: DNS Enumeration

## Project Description

### Objective

To create a script which automatically scans through DNS subdomains using gobuster, using seclists `subdomains-top1million-20000.txt` list.

### Features

* Automatic detection and installation of gobuster if not present.
* Uses the SecLists DNS subdomain wordlist subdomains-top1million-20000.txt.
* Simplified command-line usage requiring only a target domain.
* Optimized performance by limiting thread count to prevent network issues.
* Built-in checks for required dependencies and wordlists.

### Technologies and Tools Used

* **Language:** Bash
* **Tools:** gobuster
* **Environment:** Linux (Debian/Ubuntu-based systems)

### Challenges Faced

I encountered error messages relating to requests not being made due to low bandwidth, to get aroud this I tested on another network. I also had issues where I had too many threads running for DNS enumeration, my solution was I lowered the number of threads to 10.

### Outcome

The final script successfully performs automated DNS enumeration with minimal user input. It ensures required tools are installed, validates the presence of the wordlist, and executes gobuster with optimized parameters. This results in a reliable, repeatable, and user-friendly enumeration process suitable for reconnaissance during penetration testing or security assessments.

### How To Use Script

1. **Set Up Your Environment**
* Ensure you are using a Linux system with apt package management.
* Install SecLists if not already present:
```
sudo apt install seclists
```

2. **Save the Script**
* Save the script to a file, for example:
```
dns_enum.sh
```
* Make it executable:
```
chmod +x dns_enum.sh
```
3. **Run the Script**
* Execute the script with a target domain as the argument:
```
./dns_enum.sh example.com
```

4. **Script Behavior**

* Checks if gobuster is installed and installs it if missing.
* Verifies the existence of the SecLists DNS wordlist.
* Runs gobuster in DNS enumeration mode with:
    * 10 threads
    * Cloudflare resolver (1.1.1.1)
    * Wildcard detection
    * 5-second timeout

5. **Review Results**

* Discovered subdomains will be displayed directly in the terminal.
* Results can be redirected to a file if needed:
```
./dns_enum.sh example.com > results.txt
```