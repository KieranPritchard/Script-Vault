import dns.resolver
import whois

# Function to get whois records
def getWhoIs(domain):
    # Looks up the whois data
    who = whois.whois(domain)

    # Outputs the relevant data
    print("=" * 30)
    print(who)
    print(who.domain_name)
    print(who.registrar)
    print(who.creation_date)
    print(who.expiration_date)

# Function to resolve A records
def getARecords(domain):
    # Resolves the dns data for a records
    answers = dns.resolver.resolve(domain, "A")
    # Loops through the resolved data in answers
    print("A Records:")
    for resolved_data in answers:
        # Outputs the address
        print(resolved_data.address)

def getNsRecords(domain):
    # Resolves NS Records
    ns = dns.resolver.resolve(domain, "NS")
    # Loops through the resolved data in answers
    print("NS Records:")
    for r in ns:
        print(r.target)