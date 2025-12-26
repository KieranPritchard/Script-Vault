#!/usr/bin/env bash

# Check for domain argument
if [[ $# -ne 1 ]]; then
    # Outputs how to use the program
    echo "Usage: $0 <domain>"
    # Exits the program
    exit 1
fi

# Checks if gobuster is intalled
if ! command -v gobuster &>/dev/null; then
    # Echos that it is installing
    echo "[*] Gobuster not found. Installing..."
    # Updates and installs gobuster
    sudo apt update
    sudo apt install -y gobuster
fi

# Selects the top one million subdomain list
wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"

# Checks if the wordlist exists
if [[ ! -f "$wordlist" ]]; then
    # Outputs the word list wasnt found
    echo "[-] Wordlist not found: $wordlist"
    # Exits the program
    exit 1
fi

# Gets the domain from a postion arguement
domain="$1"
# Sets threads to 50
threads=50

# Runs gobuster in dns enumeration mode with the previous variables
gobuster dns \
-d "$domain" \
-w "$wordlist" \
-t "$threads"