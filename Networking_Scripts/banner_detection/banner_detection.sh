#!/bin/bash

# checks for if there is a required arguement
if [ -z "$1" ]; then
    # Outputs usage guide and example of use
    echo "Usage $0 <Target>"
    echo "Example: $0 192.168.1.0"
    # Exits the script
    exit 1
fi

# Checks if nmap is installed
if ! command -v nmap &> /dev/null; then
    # Ouputs nmap isnt installed
    echo "[-] nmap is not installed"
    # Prompts the user to install nmap
    echo "[!] Please install nmap"
    # Exits the script
    exit 1
fi

# Stores the arguement in a variable
target="$1"

# Ouputs the scan has started
echo "[+] Scanning $target for banners"

# Gets the  results from the nmap scan
results=$(nmap -sV --script=banner "$target" 2>/dev/null \
    | grep "Nmap scan report for" \
    | awk '{print $NF}')

# Checks if there isnt any results
if [ -z "$results" ]; then
    # Outputs no live hosts found
    echo "[-] No banners found."
else
    # Outputs results
    echo "[+] Banners found"
    echo "$results"
fi