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
if ! command -v hakrawler &> /dev/null; then
    URLS=$(curl -s "$TARGET" | grep -oP 'href="\K[^"]+' | sed "s|^/|$TARGET/|")
else
    URLS=$(echo "$TARGET" | hakrawler -depth 2 -plain)
fi

UNIQUE_URLS=$(echo "$URLS" | sort -u)
echo "$UNIQUE_URLS" > targets.txt
echo "[✓] Found $(wc -l < targets.txt) unique targets."

echo -e "\n--- PHASE 2: HIGH-SPEED NUCLEI SCAN ---"
# -c: templates to run in parallel | -bs: hosts to scan in parallel | -rl: total requests per second
nuclei -l targets.txt -tags xss -severity low,medium,high,critical -c 50 -bs 10 -rl 100 | tee -a nuclei_live.txt

# Extract hits for CSV
grep "\[" nuclei_live.txt | awk '{print "Nuclei," $4 "," $6 ",Vulnerable"}' >> "$RESULTS_CSV"

echo -e "\n--- PHASE 3: DALFOX SCAN (5 THREADS) ---"
cat targets.txt | xargs -I % -P 5 bash -c "
    URL='%'
    echo -e '\n[!] Testing: '\$URL
    [[ \$URL != *'?'* ]] && URL=\"\$URL?id=1&q=test\"
    dalfox url \"\$URL\" --worker 5 --delay 100 --waf-evasion --no-color | tee dalfox_temp.txt
    grep 'POC' dalfox_temp.txt >> \"$RESULTS_CSV\"
    rm dalfox_temp.txt
"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
rm targets.txt nuclei_live.txt

echo -e "\n[✓] Scan Complete in $ELAPSED seconds."