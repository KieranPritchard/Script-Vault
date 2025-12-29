# Script: Domain Lookup

## Project Description

### Objective

To create a Python script which allows me to automatically resolve DNS records and gather basic WHOIS information for a given domain. The goal was to have a simple, quick tool I could run during reconnaissance to get an overview of a domain without relying on multiple external tools.

### Features

* Resolves common DNS record types (A, AAAA, NS, MX, TXT, CNAME, SOA).
* Performs a WHOIS lookup and extracts useful registration details.
* Handles inconsistent WHOIS date formats cleanly.
* Simple user input (just enter a domain).
* Clear, readable output separated into sections.

### Technologies and Tools Used

* **Language:** Python
* * **Frameworks/Librarys:** dns, whois, datetime

### Challenges Faced

I had an issue come up while testing involving date handling in the WHOIS data. The creation and expiration dates were sometimes returned as lists or datetime objects, depending on the registrar. This caused inconsistent output and errors when printing the values.

I fixed this by creating a helper function that checks the data type, extracts the first value if needed, and converts datetime objects into a clean, readable date format. This made the output consistent and prevented the script from breaking on different domains.

### Outcome

The final script successfully retrieves WHOIS information and resolves multiple DNS record types in one run. It provides a quick snapshot of a domain’s infrastructure and registration details, which is useful during initial reconnaissance or general analysis. The script is modular, easy to extend, and handles errors gracefully when records are missing or unavailable.

## How To Use Script

1. **Set Up Your Environment**
* Ensure Python 3 is installed.
* Install the required libraries:
```
pip install dnspython python-whois
```
2. **Save the Script**
* Save the script to a file, for example:
```
domain_lookup.py
```
3. **Run the Script**
* Execute the script:
```
python3 domain_lookup.py
```
4. **Script Behavior**
* Prompts the user to enter a domain name.
* Performs a WHOIS lookup and extracts:
    * Domain name
    * Registrar
    * Creation date
    * Expiration date
* Resolves and displays:
    * A records
    * AAAA records
    * NS records
    * MX records
    * TXT records
    * CNAME records
    * SOA record details
* Handles missing records without crashing.
5. **Review Results**
* All results are displayed directly in the terminal.
* Output is grouped into clearly labeled sections for readability.
* Results can be redirected to a file if needed:
```
python3 domain_lookup.py > results.txt
```