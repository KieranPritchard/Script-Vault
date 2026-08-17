#!/bin/bash

# Stores variables
TARGET="$1"

# Checks if nmap is installed
if ! command -v nmap &> /dev/null; then
    # Ouputs nmap isnt installed
    echo "[-] nmap is not installed"
    # Prompts the user to install nmap
    echo "[!] Please install nmap"
    # Exits the script
    exit 1
fi

# Check for root privailages
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (SYN scan requires it)."
    exit 1
fi

# checks for if there is a required arguement
if [ -z "$TARGET" ]; then
    # Outputs usage guide and example of use
    echo "Usage $0 <Target>"
    echo "Example: $0 192.168.1.0"
    # Exits the script
    exit 1
fi

# Outputs the scan has started
    echo "[+] Starting Nmap scan against: $TARGET"

    # Gets the  results from the nmap scan
    results=$(nmap -sS -Pn -p- --reason "$TARGET" 2>/dev/null | grep -E "open|filtered")

    # Checks if there isnt any results
    if [ -z "$results" ]; then
        # Outputs no live hosts found
        echo "[-] No results found."
    else
        # Outputs results
        echo "[+] Results found"
        echo "$results"
    fi