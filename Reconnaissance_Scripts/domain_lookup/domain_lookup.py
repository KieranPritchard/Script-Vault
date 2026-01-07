import dns.resolver
import whois
from datetime import datetime
import time

# Extracts the date and converts it to a a date time value
def extract_date(value):
    if isinstance(value, list):
        # Extracts the first value
        value = value[0]  # take the first date
    # Checks if the value is a datatime
    if isinstance(value, datetime):
        # Returns the date in uk format
        return value.date().isoformat()
    # Returns value
    return value

# Function to get whois records
def get_who_is(domain):
    # Header for section
    print("=" * 30)
    print("WHOIS Records")
    print("=" * 30)
    # Trys to look up the whois data
    try:
        # Looks up the whois data
        who = whois.whois(domain)

        # Outputs the relevant data
        print(f"Domain Name: {who.domain_name}")
        print(f"Registrar: {who.registrar}")
        print(f"Creation Date: {extract_date(who.creation_date)}")
        print(f"Expiration Date: {extract_date(who.expiration_date)}")
    except:
        print("Error encountered with WHOIS")

# Function to resolve A records
def get_a_records(domain):
    # Header for section
    print("=" * 30)
    print("A Records:")
    print("=" * 30)
    # Trys to resolve A records
    try:
        # Resolves the dns data for a records
        answers = dns.resolver.resolve(domain, "A")

        # Loops through the resolved data in answers
        for resolved_data in answers:
            # Outputs the address
            print(f"A Record Address: {resolved_data.address}")
    except:
        print("Error encountered with A records")

# Function to resolve AAAA records
def get_aaaa_records(domain):
    # Header for section
    print("=" * 30)
    print("AAAA Records:")
    print("=" * 30)
    # Trys to resolve AAAA records
    try:
        # Resolves the dns data for aaaa records
        answers = dns.resolver.resolve(domain, "AAAA")
        # Loops through the resolved data in answers
        for resolved_data in answers:
            # Outputs the address
            print(f"AAAA Record Address: {resolved_data.address}")
    except:
        print("Error encountered with AAAA records")

def get_ns_records(domain):
    # Header for section
    print("=" * 30)
    print("NS Records")
    print("=" * 30)
    # Trys to resolve NS records
    try:
        # Resolves NS Records
        ns = dns.resolver.resolve(domain, "NS")
        # Loops through the resolved data in answers
        for r in ns:
            print(f"NS Record Address: {r.target}")
    except:
        print("Error encountered with NS records")

def get_mx_records(domain):
    # Outputs header
    print("=" * 30)
    print("MX Records")
    print("=" * 30)
    # Trys to resolve MX records
    try:
        # Resolves MX records from the domain
        answers = dns.resolver.resolve(domain, "MX")

        # Loops through the resolved data in answers
        for record in answers:
            print(f"Priority: {record.preference}, Server: {record.exchange}")
    except:
        print("Error encountered with MX records")

def get_txt_records(domain):
    # Header for section
    print("=" * 30)
    print("TXT Records")
    print("=" * 30)
    # Trys to resolve TXT records
    try:
        # Resolves TXT Records
        answers = dns.resolver.resolve(domain, "TXT")
        # Loops through the records in answers
        for record in answers:
            # Decodes and joins the records together
            text = b"".join(record.strings).decode()
            # Outputs the txt records
            print(f"TXT Record: {text}")
    except:
        # Outputs errors
        print("Error encountered with TXT records")

def get_cname_records(domain):
    # Header for section
    print("=" * 30)
    print("CNAME Records")
    print("=" * 30)
    # Trys to resolve cname records
    try:
        # Resolves the CNAME records
        answers = dns.resolver.resolve(domain, "CNAME")
        # Loops through the answers
        for record in answers:
            # Outputs the cname records
            print(f"CNAME Target: {record.target}")
    except:
        # Outputs error message
        print("Error encountered with CNAME records")

def get_soa_record(domain):
    # Header for section
    print("=" * 30)
    print("SOA Record")
    print("=" * 30)
    # Trys to get SOA records
    try:
        # Resolves the SOA records
        answers = dns.resolver.resolve(domain, "SOA")

        # Loops through the records resolved and outputs the details
        for record in answers:
            print(f"Primary NS: {record.mname}")
            print(f"Responsible Email: {record.rname}")
            print(f"Serial: {record.serial}")
            print(f"Refresh: {record.refresh}")
            print(f"Retry: {record.retry}")
            print(f"Expire: {record.expire}")
            print(f"Minimum TTL: {record.minimum}")
    except:
        # Outputs error message
        print("Error encountered with SOA records")

def main():
    # Logs the starting time
    start_time = time.perf_counter() 

    # Outputs a header
    print("=" * 30)
    print("Domain Record Lookup")
    print("=" * 30)

    # Asks user to input a domain
    domain = input("Please enter a domain: ")

    # Calls the functions with domain as a parameter
    get_who_is(domain)
    get_a_records(domain)
    get_aaaa_records(domain)
    get_ns_records(domain)
    get_mx_records(domain)
    get_txt_records(domain)
    get_cname_records(domain)
    get_soa_record(domain)

    # Gets end time and calculates the elasped time
    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # Outputs the time
    print(f"[✓] Finished in {elapsed:.2f} seconds")

# Starts the script
if __name__ == "__main__":
    main()