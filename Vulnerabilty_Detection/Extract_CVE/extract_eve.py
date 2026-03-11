import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import socket

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

    return extracted_data