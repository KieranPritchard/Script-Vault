import subprocess
import shutil

# Function to run katana
def run_katana(targets):
    """Crawl for hidden endpoints"""
    
    # Checks if katana is installed 
    if not shutil.which("katana"): return []
    
    # Empty list to store discovered urls
    discovered = []

    # Outputs katana is starting
    print(f"[*] Starting Katana deep crawl...")

    # Loops over the targets in targets
    for target in targets:
        # Formats the target
        formatted_target = target if "://" in target else f"http://{target}"
        
        try:
        
            # Gets the result for the targe
            result = subprocess.run(["katana", "-u", formatted_target, "-depth", "3", "-silent", "-nc", "-jc"], capture_output=True, text=True)
        
            # Adds the results to the discovered list
            discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        
        except: continue # Continues if there isnt anything
    
    return list(set(discovered)) # Returns a list without duplicates

def run_subfinder(domain):
    """Subdomain discovery (skips if port is provided in domain string)"""
    
    # Checks if domain has a port number
    if ":" in domain: return []

    # Outputs the program is discovering subdomains
    print(f"[*] Discovering subdomains for {domain}...")
    
    # Gets the result of the scan
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    
    # Returns the domains
    return [line for line in result.stdout.splitlines() if line]


def scan_commix(endpoints):
    """Runs a commix scan to detect command injection"""
    
    # Checks if there endpoints in the parameters
    if endpoints:
        # Outputs endpoints are being passed into commix
        print(f"[*] Passing {len(endpoints)} endpoints to Commix...")
    
        # Join endpoints by newline to pass to Commix via stdin
        input_data = "\n".join(endpoints)
        
        # -m tells commix to read multiple targets from stdin (-)
        commix_cmd = ["commix", "--batch", "-m", "-"]
        subprocess.run(commix_cmd, input=input_data, text=True)
    else:
        # Outputs there are no endpoints to scan
        print("[!] No endpoints discovered to test.")

def main():
    # Allows the user to enter a target
    target = input("Enter a target (e.g. 'example.com'): ").strip()

    # Runs subfinder to find subdomains
    subdomains = run_subfinder(target)

    # Checks if there is not any subdomains
    if not subdomains:
        # Fallback list
        subdomains = [target]

    # Stores all endpoints
    all_endpoints = []

    # Loops over each subdomain with katan
    for subdomain in subdomains:
        # Gets the results from katana
        results = run_katana(subdomain)

        # Adds the results to the
        all_endpoints.extend(results)

    if all_endpoints:
        print(f"[*] Passing {len(all_endpoints)} endpoints to Commix...")
        # Join endpoints by newline to pass to Commix via stdin
        input_data = "\n".join(all_endpoints)
        
        # -m tells commix to read multiple targets from stdin (-)
        commix_cmd = ["commix", "--batch", "-m", "-"]
        subprocess.run(commix_cmd, input=input_data, text=True)
    else:
        print("[!] No endpoints discovered to test.")