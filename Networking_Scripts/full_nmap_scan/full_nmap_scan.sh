#!/bin/bash

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (OS detection requires it)."
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

# checks for if there is a required arguement
if [ -z "$1" ]; then
    # Outputs usage guide and example of use
    echo "Usage $0 <Target> <save>"
    echo "Example: $0 192.168.1.0"
    # Exits the script
    exit 1
fi