import nmap

# Function to open target file and load the targets
def load_targets(file):
    # Stores the targets in a list
    targets = []
    
    # Opens the text file
    with open(file, "r") as f:
        # Loops over the file
        for target in f:
            # Adds the targets 
            targets.append(target)

    return targets