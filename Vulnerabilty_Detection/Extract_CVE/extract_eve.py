import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import shutil
from dotenv import load_dotenv

def check_exploit_exists(identifier):
    """Check if an ID (CVE or EDB-ID) has a verified exploit in the local database using the --cve flag"""
    if not identifier or not isinstance(identifier, str):
        return False
        
    try:
        # Explicitly use the --cve flag for CVE patterns to ensure Searchsploit matches correctly
        if "CVE-" in identifier.upper():
            command = ['searchsploit', '--cve', identifier, '--json']
        else:
            command = ['searchsploit', identifier, '--json']

        result = subprocess.run(command, capture_output=True, text=True, check=False)
        data = json.loads(result.stdout)
        
        # Check both exploit and shellcode results in the local Exploit-DB
        has_exploit = len(data.get("RESULTS_EXPLOIT", [])) > 0
        has_shellcode = len(data.get("RESULTS_SHELLCODE", [])) > 0
        
        return has_exploit or has_shellcode
    except Exception:
        return False

def extract_network_vulns(extracted_data, target):
    """Parse nmap data using local scripts; handles port-specific targets from input"""
    try:
        # Strip port for hostname resolution if present
        host_only = target.split(':')[0]
        ip_address = socket.gethostbyname(host_only)
    except socket.gaierror:
        return extracted_data

    # Use -Pn to treat host as up (common for specialized ports like 7001)
    nmap_cmd = ["nmap", "-sV", "--script", "vuln", "-Pn", "-oX", "results.xml", ip_address]
    
    # If the user provided a port, tell nmap to scan it specifically
    if ":" in target:
        port = target.split(':')[-1]
        nmap_cmd.insert(1, "-p")
        nmap_cmd.insert(2, port)

    subprocess.run(nmap_cmd, capture_output=True, text=True)

    try:
        if os.path.exists('results.xml'):
            tree = ET.parse('results.xml')
            root = tree.getroot()
            for host in root.findall('host'):
                for port in host.iter('port'):
                    service = port.find('service')
                    if service is not None:
                        product = service.attrib.get('product', '')
                        version = service.attrib.get('version', '')
                        if product:
                            extracted_data = audit_with_local_searchsploit(extracted_data, product, version)
    finally:
        if os.path.exists('results.xml'):
            os.remove('results.xml')
    return extracted_data

def audit_with_local_searchsploit(extracted_data, software, version):
    """Query local Searchsploit database for service versions found by Nmap"""
    query = f"{software} {version}".strip()
    try:
        result = subprocess.run(["searchsploit", query, "--json"], capture_output=True, text=True, check=False)
        data = json.loads(result.stdout)
        for exploit in data.get("RESULTS_EXPLOIT", []):
            extracted_data["Exploit ID"].append(exploit.get("EDB-ID") or exploit.get("Title"))
            extracted_data["Type"].append(f"Local_EDB: {software}")
            extracted_data["CVSS"].append("N/A") 
            extracted_data["Exploit"].append(True)
    except Exception:
        pass
    return extracted_data

def scan_and_parse_nuclei(extracted_data, target):
    """Nuclei scanner updated for better protocol handling and specific vulnerability tagging"""
    # Clean target for Nuclei to ensure it handles ports correctly
    clean_target = target if "://" in target else f"http://{target}"
    
    # Added -tags for RCE/Weblogic and -severity to ensure high-value targets aren't skipped
    command = ["nuclei", "-u", clean_target, "-tags", "cve,weblogic,rce", "-severity", "critical,high,medium", "-jsonl", "-o", "results.jsonl", "-silent"]
    
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
    except Exception as e:
        print(f"[!] Nuclei Error: {e}")
    return extracted_data

def run_subfinder(domain):
    """Subdomain discovery (skips if port is provided in domain string)"""
    if ":" in domain: return []
    print(f"[*] Discovering subdomains for {domain}...")
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def run_katana(targets):
    """Crawl for hidden endpoints"""
    if not shutil.which("katana"): return []
    discovered = []
    print(f"[*] Starting Katana deep crawl...")
    for t in targets:
        fmt = t if "://" in t else f"http://{t}"
        try:
            result = subprocess.run(["katana", "-u", fmt, "-silent", "-nc", "-jc"], capture_output=True, text=True)
            discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except: continue
    return list(set(discovered))

def main():
    extracted_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    target_input = input("[*] Please enter the target domain (e.g. pentest-ground.com:7001): ").strip()

    if target_input:
        # If input has a port, we skip general subdomain enumeration for speed
        if ":" in target_input:
            targets_to_scan = [target_input]
        else:
            subdomains = run_subfinder(target_input)
            targets_to_scan = list(set([target_input] + subdomains))
            targets_to_scan.extend(run_katana(targets_to_scan))
        
        for sub in list(set(targets_to_scan)):
            print(f"\n[+] Processing {sub}")
            extracted_data = extract_network_vulns(extracted_data, sub)
            extracted_data = scan_and_parse_nuclei(extracted_data, sub)

    df = pd.DataFrame(extracted_data)
    if not df.empty:
        df = df.drop_duplicates(subset=["Exploit ID"])
        # Apply the updated searchsploit check
        df['Verified_Exploit_Local'] = df["Exploit ID"].apply(check_exploit_exists)
        df['CVSS_Numeric'] = pd.to_numeric(df['CVSS'], errors='coerce').fillna(0)
        print("\n--- FINAL VULNERABILITY REPORT (LOCAL TOOLS ONLY) ---")
        print(df.sort_values(by="CVSS_Numeric", ascending=False)[["Exploit ID", "Type", "CVSS", "Verified_Exploit_Local"]])
    else:
        print("[*] No vulnerabilities detected.")

if __name__ == "__main__":
    main()