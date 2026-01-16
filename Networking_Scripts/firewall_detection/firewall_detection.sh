#!/bin/bash

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