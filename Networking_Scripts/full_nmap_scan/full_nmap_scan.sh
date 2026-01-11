#!/bin/bash

# Check for root privailages
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

# Stores variables
TARGET="$1"
MODE="$2"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
OUTDIR="nmap_reports/scan_${TARGET}_${DATE}"

if [ "$MODE" = "save" ]; then
    # Creates directiory to store nmap reports
    mkdir -p "$OUTDIR"

    # Ouputs the scan has started and is being saved
    echo "[+] Starting Nmap scan against: $TARGET"
    echo "[+] Reports will be saved to: $OUTDIR"
    echo

    # Run Nmap scan
    nmap \
        -p- \
        -sS \
        -sV \
        -O \
        -A \
        --script=default,safe \
        -T4 \
        -oA "$OUTDIR/full_scan" \
        "$TARGET"

    echo
    # Outputs successfull scan and the output files
    echo "[✓] Scan completed successfully."
    echo "[✓] Output files:"
    echo "    - Normal:    $OUTDIR/full_scan.nmap"
    echo "    - Grepable:  $OUTDIR/full_scan.gnmap"
    echo "    - XML:       $OUTDIR/full_scan.xml"
else
    # Outputs the scan has started
    echo "[+] Starting Nmap scan against: $TARGET"

    # Gets the  results from the nmap scan
    results=$(nmap -p- -sS -sV -O -A -T4 --script=default,safe "$TARGET" 2>/dev/null \
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
fi