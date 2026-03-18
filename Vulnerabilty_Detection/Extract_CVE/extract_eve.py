import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import requests
import vulners
import shutil
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_env_setup(env_path):
    """Checks for .env file and creates it with user input if missing."""
    if not os.path.exists(env_path):
        print(f"[!] Configuration file not found at {env_path}")
        api_key = input("[*] Please enter your Vulners API Key to save it: ").strip()
        try:
            with open(env_path, "w") as f:
                f.write(f"VULNERS_KEY={api_key}\n")
            print(f"[+] .env file created successfully at {env_path}\n")
        except Exception as e:
            print(f"[!] Failed to create .env file: {e}")

def extract_network_vulns(target):
    """Function to parse in nmap vulns data"""
    findings = []
    # Unique filename for concurrency safety
    xml_file = f"nmap_{target.replace('.', '_')}.xml"
    
    # Converts the target into an ip address for nmap
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return findings

    # Runs a scan for vulnerabiltites and stores them in an xml file
    subprocess.run(["nmap", "-sV", "--script", "vulners", "-oX", xml_file, ip_address], capture_output=True, text=True)

    try:
        if os.path.exists(xml_file):
            # Parses in the tree
            tree = ET.parse(xml_file)
            # Gets the trees root
            root = tree.getroot()

            # Loops over the table elements
            for table in root.iter('table'):
                row = {"Exploit ID": None, "Type": None, "CVSS": 0.0, "Exploit": False, "Target": target}
                # Loops over the nested elements
                for elem in table:
                    # Checks if the key is id
                    if elem.attrib.get('key') == 'id':
                        row["Exploit ID"] = elem.text
                    # Checks for type key
                    elif elem.attrib.get('key') == 'type':
                        row["Type"] = elem.text
                    # Checks for cvss key 
                    elif elem.attrib.get('key') == 'cvss':
                        row["CVSS"] = elem.text
                    # Checks for the is exploit key
                    elif elem.attrib.get('key') == 'is_exploit':
                        row["Exploit"] = elem.text
                
                if row["Exploit ID"]:
                    findings.append(row)
    finally:
        # Cleanup ensures no data leaks between targets
        if os.path.exists(xml_file):
            os.remove(xml_file)
            
    # Returns the data as a list of dicts
    return findings

def scan_and_parse_nuclei(target):
    """Function to parse and scan nuclei results"""
    findings = []
    jsonl_file = f"nuclei_{target.replace('.', '_')}.jsonl"

    # Ensures protocol discovery handles HTTP-only sites like vulnweb
    formatted_url = target if "://" in target else f"http://{target}"

    # Stores the command to be run
    command = ["nuclei", "-u", formatted_url, "-jsonl", "-o", jsonl_file, "-silent"]
    
    try:
        # Outputs a scan has started
        print(f"[*] Starting Nuclei scan on: {target}...")
        # Runs the command
        subprocess.run(command, check=True, capture_output=True)

        # Parse the resulting file
        if os.path.exists(jsonl_file):
            # Opens the results file made
            with open(jsonl_file, 'r') as f:
                # Loops over the line in the file
                for line in f:
                    # Checks for if there is an actual line
                    if not line.strip(): 
                        continue
                    
                    # Loads in the data and gets the infromation from it
                    data = json.loads(line)
                    info = data.get("info", {})
                    
                    # Extracts the data from the results
                    findings.append({
                        "Exploit ID": data.get("template-id"),
                        "Type": data.get("type"),
                        "CVSS": info.get("classification", {}).get("cvss-score", 0.0),
                        "Exploit": True if data.get("matched-at") else False,
                        "Target": target
                    })
            
            # File removal prevents duplicate data in the final report
            os.remove(jsonl_file)
        return findings

    # Catches and outputs the error
    except (subprocess.CalledProcessError, Exception) as e:
        print(f"[!] Nuclei error on {target}: {e}")
        return findings

def run_subfinder(domain):
    """Function to run subfinder"""
    print(f"[*] Discovering subdomains for {domain}...")
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def run_katana(targets):
    """Function to crawl targets for deep endpoints using Katana while silencing output"""
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
                capture_output=True, 
                text=True, 
                check=True
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    discovered_endpoints.append(line.strip())
        except Exception:
            continue

    return list(set(discovered_endpoints))

def audit_with_vulners_sdk(target, api_key):
    """Probes headers and uses the Vulners Python SDK for a software audit."""
    findings = []
    v_api = vulners.VulnersApi(api_key=api_key)
    try:
        print(f"[*] Fingerprinting {target} for Vulners SDK audit...")
        res = requests.get(f"http://{target}", timeout=5, verify=False)
        server = res.headers.get("Server", "")
        
        if "/" in server:
            name, ver = server.split("/")[:2]
            results = v_api.software_audit(software=[{"software": name.lower(), "version": ver}])
            
            for item in results:
                for v in item.get('vulnerabilities', []):
                    findings.append({
                        "Exploit ID": v.get('id'),
                        "Type": f"SDK_Audit: {item['software']}",
                        "CVSS": v.get('cvss', {}).get('score', 0.0),
                        "Exploit": False,
                        "Target": target
                    })
    except Exception as e:
        print(f"[!] SDK Audit Error on {target}: {e}")
    return findings

def is_domain_active(domain):
    """Helper function to check if domain is active"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def check_exploit_exists(cve_id):
    """Checks searchsploit for local exploit availability"""
    try:
        result = subprocess.run(
            ['searchsploit', '--cve', str(cve_id), '--json'],
            capture_output=True, text=True, check=False
        )
        data = json.loads(result.stdout)
        return len(data.get("RESULTS_EXPLOIT", [])) > 0
    except Exception:
        return False

def main():
    env_file_path = "../../.env"
    check_env_setup(env_file_path)
    load_dotenv(env_file_path)
    vulners_api_key = os.getenv("VULNERS_KEY")

    target_domain = input("[*] Please enter the target domain: ").strip()

    if is_domain_active(target_domain):
        subdomains = run_subfinder(target_domain)
        initial_targets = list(set([target_domain] + subdomains))
        endpoints = run_katana(initial_targets)
        targets_to_scan = list(set(initial_targets + endpoints))
        
        all_findings = []

        # We use a ThreadPool to run scans in parallel (5 at a time)
        print(f"[*] Starting parallel scans on {len(targets_to_scan)} targets...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Create a list of tasks for each tool per target
            nmap_tasks = {executor.submit(extract_network_vulns, t): t for t in targets_to_scan}
            nuclei_tasks = {executor.submit(scan_and_parse_nuclei, t): t for t in targets_to_scan}
            sdk_tasks = {executor.submit(audit_with_vulners_sdk, t, vulners_api_key): t for t in targets_to_scan}

            # Collect results as they finish
            for future in as_completed({**nmap_tasks, **nuclei_tasks, **sdk_tasks}):
                all_findings.extend(future.result())

        # Export to Pandas for Analysis
        df = pd.DataFrame(all_findings)

        if not df.empty:
            # Filter for only rows where 'Exploit ID' starts with 'CVE'
            cve_only_df = df[df['Exploit ID'].str.startswith('CVE', na=False)].copy().drop_duplicates()

            print("\n--- FINAL CVE REPORT ---")
            if cve_only_df.empty:
                print("[*] No specific CVEs were detected for this target.")
            else:
                # Add exploit check only for unique CVEs to save time
                cve_only_df['in_metasploit'] = cve_only_df["Exploit ID"].apply(check_exploit_exists)
                print(cve_only_df.sort_values(by="CVSS", ascending=False))
        else:
            print("[!] No data collected during scan.")

# Starts the program
if __name__ == "__main__":
    main()