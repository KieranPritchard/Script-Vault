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