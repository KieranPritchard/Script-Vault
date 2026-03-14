import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json
import requests
import vulners

def extract_network_vulns(extracted_data, target):
    """Function to parse in nmap vulns data"""

    # Converts the target into an ip address for nmap
    ip_address = socket.gethostbyname(target)

    # Runs a scan for vulnerabiltites and stores them in an xml file
    subprocess.run(["nmap", "-sV", "--script", "vulners", "-oX", "results.xml", ip_address])

    # Parses in the tree
    tree = ET.parse('results.xml')
    # Gets the trees root
    root = tree.getroot()

    # Loops over the table elements
    for table in root.iter('table'):
        # Loops over the nested elements
        for elem in table:
            # Checks if the key is id
            if elem.attrib.get('key') == 'id':
                # Adds the data the extracted data column
                extracted_data["Exploit ID"].append(elem.text)
            # Checks for type key
            elif elem.attrib.get('key') == 'type':
                # Adds the data the extracted data column
                extracted_data["Type"].append(elem.text)
            # Checks for cvss key 
            elif elem.attrib.get('key') == 'cvss':
                # Adds the data the extracted data column
                extracted_data["CVSS"].append(elem.text)
            # Checks for the is exploit key
            elif elem.attrib.get('key') == 'is_exploit':
                # Adds the data the extracted data column
                extracted_data["Exploit"].append(elem.text)
    # Returns the data
    return extracted_data

def scan_and_parse_nuclei(extracted_data, target):
    """Function to parse and scan nuclei results"""

    # Stores the command to be run
    command = ["nuclei", "-u", target, "-jsonl", "-o", "results.jsonl", "-silent"]
    
    try:
        # Outputs a scan has started
        print(f"[*] Starting Nuclei scan on: {target}...")
        # Runs the command
        subprocess.run(command, check=True)
        # Outputs the scan is complete
        print(f"[+] Scan complete. Parsing results...")

        # Parse the resulting file
        if os.path.exists("results.jsonl"):
            # Opens the results file made
            with open("results.jsonl", 'r') as f:
                # Loops over the line in the file
                for line in f:
                    # Checks for if there is an actual line
                    if not line.strip(): 
                        continue
                    
                    # Loads in the data and gets the infromation from it
                    data = json.loads(line)
                    info = data.get("info", {})
                    
                    # Extracts the data from the results
                    extracted_data["Exploit ID"].append(data.get("template-id"))
                    extracted_data["Type"].append(data.get("type"))
                    extracted_data["CVSS"].append(info.get("classification", {}).get("cvss-score", 0.0))
                    
                    # Exploit is True because the entry exists in the success log
                    extracted_data["Exploit"].append(True if data.get("matched-at") else False)
        # Returns the data
        return extracted_data

    # Catches and outputs the error
    except subprocess.CalledProcessError as e:
        print(f"[!] Nuclei command failed: {e}")
        # Returns the data
        return extracted_data
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        # Returns the data
        return extracted_data

def run_subfinder(domain):
    """Function to run subfinder"""
    print(f"[*] Discovering subdomains for {domain}...")
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def audit_with_vulners_sdk(extracted_data, target, api_key):
    """Probes headers and uses the Vulners Python SDK for a software audit."""
    
    # Creates an api object
    v_api = vulners.VulnersApi(api_key=api_key)
    try:
        # Ouputs the target is being fingerprinted
        print(f"[*] Fingerprinting {target} for Vulners SDK audit...")
        # Gets the response form the target
        res = requests.get(f"https://{target}", timeout=5, verify=False)
        # Gets the server from the header
        server = res.headers.get("Server", "")
        
        # Checks if a root is in the server
        if "/" in server:
            # Gets the name and version from the server
            name, ver = server.split("/")[:2]
            # Gets the results from the api
            results = v_api.software_audit(software=[{"software": name.lower(), "version": ver}])
            
            # Loops over item in the results
            for item in results:
                # Loops over the vulnerabilitys
                for v in item.get('vulnerabilities', []):
                    # Stores the extracted data
                    extracted_data["Exploit ID"].append(v.get('id'))
                    extracted_data["Type"].append(f"SDK_Audit: {item['software']}")
                    extracted_data["CVSS"].append(v.get('cvss', {}).get('score', 0.0))
                    extracted_data["Exploit"].append(False) # Vulners SDK returns CVEs, not active exploits
    # Catches the errors
    except Exception as e:
        # Outputs the errors
        print(f"[!] SDK Audit Error on {target}: {e}")
    # Returns the extracted data
    return extracted_data