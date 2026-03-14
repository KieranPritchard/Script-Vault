import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket
import os
import json

# Function to parse in nmap vulns data
def extract_network_vulns(extracted_data, target):
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

# Function to parse and scan nuclei results
def scan_and_parse_nuclei(extracted_data, target):
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