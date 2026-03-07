#!/bin/bash

# Ensure tools are in PATH
export PATH=$PATH:$(go env GOPATH)/bin

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: ./xss_scan.sh <target_url>"
    exit 1
fi

RESULTS_CSV="xss_results.csv"
echo "type,parameter,payload,status" > "$RESULTS_CSV"

START_TIME=$(date +%s)

echo -e "\n--- PHASE 1: CRAWLING ---"
# Discovery phase
if ! command -v hakrawler &> /dev/null; then
    URLS=$(curl -s "$TARGET" | grep -oP 'href="\K[^"]+' | sed "s|^/|$TARGET/|")
else
    URLS=$(echo "$TARGET" | hakrawler -depth 2 -plain)
fi

UNIQUE_URLS=$(echo "$URLS" | sort -u)
echo "[✓] Found $(echo "$UNIQUE_URLS" | wc -l) unique targets."

echo -e "\n--- PHASE 2: NUCLEI SCAN (LIVE OUTPUT) ---"
# Removed -silent to let you see the templates being loaded and matched
nuclei -u "$TARGET" -tags xss -severity low,medium,high,critical -rl 10 | tee -a nuclei_live.txt

# Parse the live output into the CSV after the run
grep "\[" nuclei_live.txt | awk '{print "Nuclei," $4 "," $6 ",Vulnerable"}' >> "$RESULTS_CSV"
rm nuclei_live.txt

echo -e "\n--- PHASE 3: DALFOX SCAN (5 THREADS - LIVE OUTPUT) ---"
# Parallel execution showing live terminal output for each URL
echo "$UNIQUE_URLS" | xargs -I % -P 5 bash -c "
    URL='%'
    echo -e '\n[!] Testing: '\$URL
    
    # Add parameters if missing
    [[ \$URL != *'?'* ]] && URL=\"\$URL?id=1&q=test\"
    
    # Run Dalfox without --silence to see all real-time feedback
    # We use a temporary file per process to avoid terminal scrambling
    dalfox url \"\$URL\" --worker 5 --delay 100 --waf-evasion --no-color | tee dalfox_temp.txt
    
    # Extract hits for the CSV
    grep 'POC' dalfox_temp.txt >> \"$RESULTS_CSV\"
    rm dalfox_temp.txt
"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "\n--- SCAN SUMMARY ---"
echo