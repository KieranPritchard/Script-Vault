import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import shutil
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

def sync_databases():
    """Update local exploit and template databases to ensure the latest CVEs are detectable."""
    print("[*] Synchronizing local vulnerability databases...")
    try:
        subprocess.run(["searchsploit", "-u"], capture_output=True, text=True, check=False)
        subprocess.run(["nuclei", "-ut"], capture_output=True, text=True, check=False)
        print("[+] Databases synchronized successfully.")
    except Exception as e:
        print(f"[!] Update failed: {e}")

def check_exploit_exists(identifier):
    """Check if an ID (CVE or EDB-ID) has a verified exploit by stripping prefixes and using fallbacks."""
    if not identifier or not isinstance(identifier, str):
        return False
    try:
        clean_id = re.sub(r'(?i)CVE-', '', identifier).strip()
        command = ['searchsploit', '--cve', clean_id, '--json']
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if len(data.get("RESULTS_EXPLOIT", [])) > 0 or len(data.get("RESULTS_SHELLCODE", [])) > 0:
                return True
        fallback_command = ['searchsploit', clean_id, '--json']
        fb_result = subprocess.run(fallback_command, capture_output=True, text=True, check=False)
        if fb_result.stdout.strip():
            fb_data = json.loads(fb_result.stdout)
            return len(fb_data.get("RESULTS_EXPLOIT", [])) > 0 or len(fb_data.get("RESULTS_SHELLCODE", [])) > 0
        return False
    except Exception:
        return False

def extract_network_vulns(target):
    """Performs Nmap scan and returns results for a single target."""
    local_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    try:
        host_only = target.split(':')[0]
        ip_address = socket.gethostbyname(host_only)
    except socket.gaierror:
        return local_data

    xml_file = f"results_{target.replace(':', '_')}.xml"
    nmap_cmd = ["nmap", "-sV", "--script", "vuln", "-Pn", "-oX", xml_file, ip_address]
    if ":" in target:
        nmap_cmd.insert(1, "-p")
        nmap_cmd.insert(2, target.split(':')[-1])

    subprocess.run(nmap_cmd, capture_output=True, text=True)

    try:
        if os.path.exists(xml_file):
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                for port in host.iter('port'):
                    service = port.find('service')
                    if service is not None:
                        product = service.attrib.get('product', '')
                        version = service.attrib.get('version', '')
                        if product:
                            local_data = audit_with_local_searchsploit(local_data, product, version)
    finally:
        if os.path.exists(xml_file):
            os.remove(xml_file)
    return local_data

def audit_with_local_searchsploit(extracted_data, software, version):
    query = f"{software} {version}".strip()
    try:
        result = subprocess.run(["searchsploit", query, "--json"], capture_output=True, text=True, check=False)
        data = json.loads(result.stdout)
        for exploit in data.get("RESULTS_EXPLOIT", []):
            extracted_data["Exploit ID"].append(exploit.get("EDB-ID") or exploit.get("Title"))
            extracted_data["Type"].append(f"Local_EDB: {software}")
            extracted_data["CVSS"].append("N/A") 
            extracted_data["Exploit"].append(True)
    except: pass
    return extracted_data

def scan_and_parse_nuclei(target):
    """Performs Nuclei scan and returns results for a single target."""
    local_data = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    clean_target = target if "://" in target else f"http://{target}"
    output_file = f"nuclei_{target.replace(':', '_')}.jsonl"
    command = ["nuclei", "-u", clean_target, "-tags", "cve,weblogic,rce", "-severity", "critical,high,medium", "-jsonl", "-o", output_file, "-silent"]
    
    try:
        subprocess.run(command, check=False, capture_output=True)
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    info = data.get("info", {})
                    local_data["Exploit ID"].append(data.get("template-id"))
                    local_data["Type"].append(data.get("type"))
                    local_data["CVSS"].append(info.get("classification", {}).get("cvss-score", 0.0))
                    local_data["Exploit"].append(True if data.get("matched-at") else False)
            os.remove(output_file)
    except: pass
    return local_data

def run_subfinder(domain):
    if ":" in domain: return []
    print(f"[*] Discovering subdomains for {domain}...")
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def run_katana(targets):
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

def process_target(target):
    """Worker function for threading."""
    print(f"[+] Scanning: {target}")
    nmap_results = extract_network_vulns(target)
    nuclei_results = scan_and_parse_nuclei(target)
    
    # Merge dictionaries
    for key in nmap_results:
        nmap_results[key].extend(nuclei_results[key])
    return nmap_results

def main():
    sync_databases()
    final_results = {"Exploit ID": [], "Type": [], "CVSS": [], "Exploit": []}
    target_input = input("\n[*] Enter target (e.g. example.com:7001): ").strip()

    if target_input:
        if ":" in target_input:
            targets_to_scan = [target_input]
        else:
            subdomains = run_subfinder(target_input)
            targets_to_scan = list(set([target_input] + subdomains))
            targets_to_scan.extend(run_katana(targets_to_scan))
        
        targets_to_scan = list(set(targets_to_scan))
        print(f"[*] Threading enabled. Processing {len(targets_to_scan)} targets...")

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_target = {executor.submit(process_target, t): t for t in targets_to_scan}
            for future in as_completed(future_to_target):
                res = future.result()
                for key in final_results:
                    final_results[key].extend(res[key])

    df = pd.DataFrame(final_results)
    if not df.empty:
        df = df.drop_duplicates(subset=["Exploit ID"])
        df['Verified_Exploit_Local'] = df["Exploit ID"].apply(check_exploit_exists)
        df['CVSS_Numeric'] = pd.to_numeric(df['CVSS'], errors='coerce').fillna(0)
        print("\n" + "="*60 + "\n--- FINAL VULNERABILITY REPORT ---\n" + "="*60)
        print(df.sort_values(by="CVSS_Numeric", ascending=False)[["Exploit ID", "Type", "CVSS", "Verified_Exploit_Local"]])
    else:
        print("[*] No vulnerabilities detected.")

if __name__ == "__main__":
    main()