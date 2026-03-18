import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import requests
import shutil
from dotenv import load_dotenv

def extract_network_vulns(extracted_data, target):
    """Function to parse in nmap data using local scripts instead of the Vulners API script"""
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return extracted_data

    # Uses nmap's service detection to find versions which we will later feed to searchsploit
    # We use -sV for version intensity and --script vuln to check local databases
    subprocess.run(["nmap", "-sV", "--script", "vuln", "-oX", "results.xml", ip_address], capture_output=True, text=True)

    try:
        if os.path.exists('results.xml'):
            tree = ET.parse('results.xml')
            root = tree.getroot()

            for host in root.findall('host'):
                for port in host.iter('port'):
                    service = port.find('service')
                    if service is not None:
                        # Extract product and version for local auditing
                        product = service.attrib.get('product', '')
                        version = service.attrib.get('version', '')
                        
                        if product:
                            # If Nmap finds a version, we use our local auditor
                            extracted_data = audit_with_local_searchsploit(extracted_data, product, version)
    finally:
        if os.path.exists('results.xml'):
            os.remove('results.xml')
            
    return extracted_data

def audit_with_local_searchsploit(extracted_data, software, version):
    """Replaces Vulners SDK by querying the local Searchsploit (Exploit-DB) database"""
    query = f"{software} {version}".strip()
    try:
        # Runs searchsploit in JSON mode to find local exploits for the discovered version
        result = subprocess.run(
            ["searchsploit", query, "--json"],
            capture_output=True,
            text=True,
            check=False
        )
        
        data = json.loads(result.stdout)
        results_list = data.get("RESULTS_EXPLOIT", [])

        for exploit in results_list:
            # Populate data structure with local exploit information
            extracted_data["Exploit ID"].append(exploit.get("EDB-ID") or exploit.get("Title"))
            extracted_data["Type"].append(f"Local_EDB: {software}")
            # Searchsploit doesn't provide CVSS directly, so we mark as 'Check EDB'
            extracted_data["CVSS"].append("N/A") 
            extracted_data["Exploit"].append(True) # It's in Exploit-DB, so a PoC exists
            
    except Exception as e:
        print(f"[!] Local Searchsploit Error for {query}: {e}")
    
    return extracted_data

def scan_and_parse_nuclei(extracted_data, target):
    """Function to parse and scan nuclei results using local YAML templates"""
    formatted_url = target if "://" in target else f"http://{target}"
    command = ["nuclei", "-u", formatted_url, "-jsonl", "-o", "results.jsonl", "-silent"]
    
    try:
        print(f"[*] Starting Nuclei scan on: {target}...")
        subprocess.run(command, check=True)

        if os.path.exists("results.jsonl"):
            with open("results.jsonl", 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    
                    data = json.loads(line)
                    info = data.get("info", {})
                    
                    extracted_data["Exploit ID"].append(data.get("template-id"))
                    extracted_data["Type"].append(data.get("type"))
                    extracted_data["CVSS"].append(info.get("classification", {}).get("cvss-score", 0.0))
                    extracted_data["Exploit"].append(True if data.get("matched-at") else False)
            
            os.remove("results.jsonl")
        return extracted_data
    except Exception as e:
        print(f"[!] Nuclei Error: {e}")
        return extracted_data

def run_subfinder(domain):
    """Standard subdomain discovery"""
    print(f"[*] Discovering subdomains for {domain}...")
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def run_katana(targets):
    """Deep crawl to find hidden endpoints for Nuclei to check"""
    if not shutil.which("katana"):
        print("[!] Katana not found. Skipping deep crawl.")
        return []

    discovered_endpoints = []
    print(f"[*] Starting Katana deep crawl...")
    for target in targets:
        formatted_target = target if "://" in target else f"http://{target}"
        try:
            result = subprocess.run(
                ["katana", "-u", formatted_target, "-silent", "-nc", "-jc", "-jsl", "-kf"],
                capture_output=True, text=True, check=True
            )
            discovered_endpoints.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except Exception:
            continue
    return list(set(discovered_endpoints))

def check_exploit_exists(identifier):
    """Check if an ID (CVE or EDB-ID) has a verified exploit in the local database"""
    try:
        # Searchsploit can look up by CVE or ID
        search_term = str(identifier)
        result = subprocess.run(
            ['searchsploit', search_term, '--json'],
            capture_output=True, text=True, check=False
        )
        data = json.loads(result.stdout)
        return len(data.get("RESULTS_EXPLOIT", [])) > 0
    except Exception:
        return False

def main():
    extracted_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    target_domain = input("[*] Please enter the target domain: ").strip()

    if target_domain:
        # Recon phase
        subdomains = run_subfinder(target_domain)
        initial_targets = list(set([target_domain] + subdomains))
        endpoints = run_katana(initial_targets)
        targets_to_scan = list(set(initial_targets + endpoints))
        
        for sub in targets_to_scan:
            print(f"\n[+] Processing {sub}")
            # Scan using local-only tools
            extracted_data = extract_network_vulns(extracted_data, sub)
            extracted_data = scan_and_parse_nuclei(extracted_data, sub)

    # Export and Analysis
    df = pd.DataFrame(extracted_data)
    if not df.empty:
        # Deduplicate results and check for local exploits for every finding
        df = df.drop_duplicates(subset=["Exploit ID"])
        df['Verified_Exploit_Local'] = df["Exploit ID"].apply(check_exploit_exists)
        
        print("\n--- FINAL VULNERABILITY REPORT (LOCAL TOOLS ONLY) ---")
        # Ensure CVSS is numeric for sorting, treating N/A as 0
        df['CVSS_Numeric'] = pd.to_numeric(df['CVSS'], errors='coerce').fillna(0)
        print(df.sort_values(by="CVSS_Numeric", ascending=False)[["Exploit ID", "Type", "CVSS", "Verified_Exploit_Local"]])
    else:
        print("[*] No vulnerabilities detected.")

if __name__ == "__main__":
    main()