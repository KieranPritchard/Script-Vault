import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import shutil
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def sync_databases():
    """Update local exploit and template databases to ensure the latest CVEs are detectable."""
    
    # Outputs the local data is synchronising
    print("[*] Synchronizing local vulnerability databases...")
    try:
        # Updates the searchsploit and nuclei databases
        subprocess.run(["searchsploit", "-u"], capture_output=True, text=True, check=False)
        subprocess.run(["nuclei", "-ut"], capture_output=True, text=True, check=False)
        # Outputs the data base was updated succesfully
        print("[+] Databases synchronized successfully.")
    except Exception as e:
        # Outputs update failure 
        print(f"[!] Update failed: {e}")

def check_exploit_exists(identifier):
    """Check if an ID (CVE or EDB-ID) has a verified exploit by stripping prefixes and using fallbacks."""
    
    # Checks if the identifier is not a string instance
    if not identifier or not isinstance(identifier, str):
        # Returns false
        return False
    
    try:
        # Extracks the clean id from the identifier
        clean_id = re.sub(r'(?i)CVE-', '', identifier).strip()
        # Stores the searchsploit command to be used
        command = ['searchsploit', '--cve', clean_id, '--json']
        # Runs the commmand and stores the results
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        # Checks if there is an output
        if result.stdout.strip():
            # Loads the json results into a variable
            data = json.loads(result.stdout)
            # Checsk if the data has any items
            if len(data.get("RESULTS_EXPLOIT", [])) > 0 or len(data.get("RESULTS_SHELLCODE", [])) > 0:
                # Returns true
                return True
        # Runs a fall back command
        fallback_command = ['searchsploit', clean_id, '--json']
        # Stores the fallback result
        fb_result = subprocess.run(fallback_command, capture_output=True, text=True, check=False)
        if fb_result.stdout.strip():
            # Stores the fallback data
            fb_data = json.loads(fb_result.stdout)
            # Runs the same items check
            return len(fb_data.get("RESULTS_EXPLOIT", [])) > 0 or len(fb_data.get("RESULTS_SHELLCODE", [])) > 0
        # Returns false
        return False
    except Exception:
        # Returns false
        return False

def extract_network_vulns(target):
    """Performs Nmap scan and returns results for a single target."""
    
    # Stores the local data
    local_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    try:
        # Extracts the host from the target
        host_only = target.split(':')[0]
        # Converts the host into a ip address
        ip_address = socket.gethostbyname(host_only)
    except socket.gaierror:
        # Returns the local data
        return local_data

    # Stores the name of the XML output file
    xml_file = f"results_{target.replace(':', '_')}.xml"
    # Constructs the Nmap command for service detection and vulnerability scripting
    nmap_cmd = ["nmap", "-sV", "--script", "vuln", "-Pn", "-oX", xml_file, ip_address]
    # Checks if a port is specified in the target string
    if ":" in target:
        # Adds the port flag to the Nmap command
        nmap_cmd.insert(1, "-p")
        # Inserts the specific port number extracted from the target
        nmap_cmd.insert(2, target.split(':')[-1])

    # Executes the Nmap scan
    subprocess.run(nmap_cmd, capture_output=True, text=True)

    try:
        # Checks if the Nmap XML output was successfully created
        if os.path.exists(xml_file):
            # Parses the XML file to navigate the scan results
            tree = ET.parse(xml_file)
            root = tree.getroot()
            # Iterates through identified hosts and ports
            for host in root.findall('host'):
                for port in host.iter('port'):
                    service = port.find('service')
                    # Checks if service information is available for the port
                    if service is not None:
                        # Extracts software product name and version
                        product = service.attrib.get('product', '')
                        version = service.attrib.get('version', '')
                        if product:
                            # Queries Searchsploit for vulnerabilities matching the discovered service
                            local_data = audit_with_local_searchsploit(local_data, product, version)
    finally:
        # Ensures the temporary XML file is deleted after processing
        if os.path.exists(xml_file):
            os.remove(xml_file)
    # Returns the compiled network vulnerability data
    return local_data

def audit_with_local_searchsploit(extracted_data, software, version):
    """Search for local exploits based on software name and version."""
    # Combines software and version into a single search query
    query = f"{software} {version}".strip()
    try:
        # Executes Searchsploit with the query and requests JSON output
        result = subprocess.run(["searchsploit", query, "--json"], capture_output=True, text=True, check=False)
        data = json.loads(result.stdout)
        # Iterates through any exploits found in the local database
        for exploit in data.get("RESULTS_EXPLOIT", []):
            # Appends exploit details to the results dictionary
            extracted_data["Exploit ID"].append(exploit.get("EDB-ID") or exploit.get("Title"))
            extracted_data["Type"].append(f"Local_EDB: {software}")
            extracted_data["CVSS"].append("N/A") 
            extracted_data["Exploit"].append(True)
    except: pass # Gracefully ignores errors during the searchsploit execution
    return extracted_data

def scan_and_parse_nuclei(target):
    """Performs Nuclei scan and returns results for a single target."""
    # Initializes the results dictionary for Nuclei findings
    local_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    # Ensures the target has a proper protocol prefix
    clean_target = target if "://" in target else f"http://{target}"
    # Generates a unique filename for the Nuclei JSONL output
    output_file = f"nuclei_{target.replace(':', '_')}.jsonl"
    # Defines the Nuclei command focusing on specific tags and severities
    command = ["nuclei", "-u", clean_target, "-tags", "cve,weblogic,rce", "-severity", "critical,high,medium", "-jsonl", "-o", output_file, "-silent"]
    
    try:
        # Runs the Nuclei scanner
        subprocess.run(command, check=False, capture_output=True)
        # Checks if findings were written to the output file
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                # Reads each JSON line from the output
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    info = data.get("info", {})
                    # Populates the results dictionary with template and classification data
                    local_data["Exploit ID"].append(data.get("template-id"))
                    local_data["Type"].append(data.get("type"))
                    local_data["CVSS"].append(info.get("classification", {}).get("cvss-score", 0.0))
                    local_data["Exploit"].append(True if data.get("matched-at") else False)
            # Cleans up the temporary Nuclei output file
            os.remove(output_file)
    except: pass # Silently handles errors during Nuclei execution
    return local_data

def run_subfinder(domain):
    """Discovers subdomains for a given domain using Subfinder."""
    # Skips subdomain discovery if a specific port is already defined
    if ":" in domain: return []
    print(f"[*] Discovering subdomains for {domain}...")
    # Executes subfinder and captures the list of subdomains
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    # Returns subdomains as a list, filtering out empty lines
    return [line for line in result.stdout.splitlines() if line]

def run_katana(targets):
    """Performs a deep web crawl to find additional URLs and endpoints."""
    # Checks if the Katana tool is installed on the system
    if not shutil.which("katana"): return []
    discovered = []
    print(f"[*] Starting Katana deep crawl...")
    for t in targets:
        # Ensures URLs are formatted with a protocol
        fmt = t if "://" in t else f"http://{t}"
        try:
            # Runs Katana with JavaScript crawling and no-color options enabled
            result = subprocess.run(["katana", "-u", fmt, "-silent", "-nc", "-jc"], capture_output=True, text=True)
            # Adds new unique endpoints to the discovery list
            discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except: continue
    # Returns a unique list of discovered URLs
    return list(set(discovered))

def process_target(target):
    """Worker function for threading to handle individual target scanning."""
    print(f"[+] Scanning: {target}")
    # Executes Nmap-based network vulnerability extraction
    nmap_results = extract_network_vulns(target)
    # Executes Nuclei-based template scanning
    nuclei_results = scan_and_parse_nuclei(target)
    
    # Merges Nuclei findings into the Nmap results dictionary
    for key in nmap_results:
        nmap_results[key].extend(nuclei_results[key])
    return nmap_results

def main():
    """Main execution flow for the vulnerability scanner."""
    # Synchronizes all local vulnerability databases
    sync_databases()
    # Initializes the master dictionary to hold all results from all targets
    final_results = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    # Prompts the user for a target domain or IP
    target_input = input("\n[*] Enter target (e.g. example.com:7001): ").strip()

    if target_input:
        # Logic for handling specific ports vs. entire domains
        if ":" in target_input:
            targets_to_scan = [target_input]
        else:
            # Discovers subdomains and crawls for additional endpoints
            subdomains = run_subfinder(target_input)
            targets_to_scan = list(set([target_input] + subdomains))
            targets_to_scan.extend(run_katana(targets_to_scan))
        
        # Deduplicates the final target list
        targets_to_scan = list(set(targets_to_scan))
        print(f"[*] Threading enabled. Processing {len(targets_to_scan)} targets...")

        # Manages parallel execution of scans using a thread pool
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Maps each scan task to the target being processed
            future_to_target = {executor.submit(process_target, t): t for t in targets_to_scan}
            # Collects results as each thread completes its task
            for future in as_completed(future_to_target):
                res = future.result()
                # Aggregates thread results into the final results dictionary
                for key in final_results:
                    final_results[key].extend(res[key])

    # Processes results into a Pandas DataFrame for analysis
    df = pd.DataFrame(final_results)
    if not df.empty:
        # Removes duplicate vulnerability entries based on their ID
        df = df.drop_duplicates(subset=["Exploit ID"])
        # Verifies if an exploit exists locally for each found vulnerability
        df['Verified_Exploit_Local'] = df["Exploit ID"].apply(check_exploit_exists)
        # Ensures CVSS scores are treated as numeric for sorting purposes
        df['CVSS_Numeric'] = pd.to_numeric(df['CVSS'], errors='coerce').fillna(0)
        # Prints a formatted report to the console
        print("\n" + "="*60 + "\n--- FINAL VULNERABILITY REPORT ---\n" + "="*60)
        # Displays the most critical vulnerabilities at the top
        print(df.sort_values(by="CVSS_Numeric", ascending=False)[["Exploit ID", "Type", "CVSS", "Verified_Exploit_Local"]])
    else:
        # Notification if no issues were found
        print("[*] No vulnerabilities detected.")

if __name__ == "__main__":
    # Entry point of the script
    main()