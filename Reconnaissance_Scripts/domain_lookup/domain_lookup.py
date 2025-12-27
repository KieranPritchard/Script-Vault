import dns.resolver
import whois
from datetime import datetime

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
def getWhoIs(domain):
    # Looks up the whois data
    who = whois.whois(domain)

    # Outputs the relevant data
    print("=" * 30)
    print("WHOIS Records")
    print("=" * 30)
    print(f"Domain Name: {who.domain_name}")
    print(f"Registrar: {who.registrar}")
    print(f"Creation Date: {extract_date(who.creation_date)}")
    print(f"Expiration Date: {extract_date(who.expiration_date)}")

# Function to resolve A records
def getARecords(domain):
    # Resolves the dns data for a records
    answers = dns.resolver.resolve(domain, "A")
    # Loops through the resolved data in answers
    print("=" * 30)
    print("A Records:")
    print("=" * 30)
    for resolved_data in answers:
        # Outputs the address
        print(f"A Record Address: {resolved_data.address}")

def getNsRecords(domain):
    # Resolves NS Records
    ns = dns.resolver.resolve(domain, "NS")
    # Loops through the resolved data in answers
    print("=" * 30)
    print("NS Records:")
    print("=" * 30)
    for r in ns:
        print(f"NS Record Address: {r.target}")

def main():
    # Outputs a header
    print("=" * 30)
    print("Domain Record Lookup")
    print("=" * 30)

    # Asks user to input a domain
    domain = input("Please enter a domain: ")

    # Calls the functions with domain as a parameter
    getWhoIs(domain)
    getARecords(domain)
    getNsRecords(domain)

if __name__ == "__main__":
    main()