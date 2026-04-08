import subprocess

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
        fmt = target if "://" in t else f"http://{t}"
        try:
            # Gets the result for the targe
            result = subprocess.run(["katana", "-u", fmt, "-depth", "3", "-silent", "-nc", "-jc"], capture_output=True, text=True)
            # Adds the results to the discovered list
            discovered.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except: continue # Continues if there isnt anything
    return list(set(discovered)) # Returns a list without duplicates