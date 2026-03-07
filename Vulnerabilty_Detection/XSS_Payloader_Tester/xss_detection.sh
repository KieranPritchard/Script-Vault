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
# Fast discovery using native tools if hakrawler isn't there
if ! command -v hakrawler &> /dev/null; then
    URLS=$(curl -s "$TARGET" | grep -oP 'href="\K[^"]+' | sed "s|^/|$TARGET/|")
else
    URLS=$(echo "$TARGET" | hakrawler -depth 2 -plain)
fi

UNIQUE_URLS=$(echo "$URLS" | sort -u)
COUNT=$(echo "$UNIQUE_URLS" | wc -l)
echo "[✓] Found $COUNT unique targets."

echo -e "\n--- PHASE 2: NUCLEI SCAN ---"
# Run Nuclei and show results immediately
nuclei -u "$TARGET" -tags xss -severity low,medium,high,critical -silent -jsonl -rl 10 | while read -r line; do
    V_TYPE=$(echo "$line" | jq -r '.info.severity')
    URL_HIT=$(echo "$line" | jq -r '."matched-at"')
    echo -e "[!] NUCLEI HIT ($V_TYPE): $URL_HIT"
    echo "$line" | jq -r '[.info.severity, ."template-id", ."matched-at", "Vulnerable"] | @csv' >> "$RESULTS_CSV"
done

echo -e "\n--- PHASE 3: DALFOX SCAN (5 Threads) ---"
# Parallel processing with real-time output
echo "$UNIQUE_URLS" | xargs -I % -P 5 bash -c "
    URL='%'
    echo \"[*] Testing: \$URL\"
    
    # Add dummy params if none exist
    [[ \$URL != *'?'* ]] && URL=\"\$URL?id=1&q=test\"
    
    # Run Dalfox and pipe output to a sub-process for parsing
    dalfox url \"\$URL\" --worker 5 --delay 100 --waf-evasion --silence --no-color --format json | while read -r line; do
        if [[ \$line == {* ]]; then
            TYPE=\$(echo \"\$line\" | jq -r '.type')
            PARAM=\$(echo \"\$line\" | jq -r '.param')
            POC=\$(echo \"\$line\" | jq -r '.poc // .evidence // .injection_point // \"Manual Check\"')
            
            # Output to terminal
            echo -e \"\n[!!!] DALFOX HIT (\$TYPE) found on \$PARAM\"
            echo -e \"      PoC: \$POC\n\"
            
            # Save to CSV
            echo \"Dalfox-\$TYPE,\$PARAM,\"\$POC\",Vulnerable\" >> \"$RESULTS_CSV\"
        fi
    done
"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "\n--- SCAN SUMMARY ---"
echo "[✓] Total Scan Time: \ $ELAPSED seconds"
echo "[✓] Final Results Saved to: \ $RESULTS_CSV"