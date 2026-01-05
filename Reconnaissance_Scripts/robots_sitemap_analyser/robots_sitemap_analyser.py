import random

# Function to get random user agent from folder
def get_random_agent():
    # Opens the file
    with open("Script-Vault/Resources/user_agent_strings.txt", "r") as f:
        # Extracts the user agents as a list
        user_agents = [ua.strip() for ua in f if ua.strip()]

    # Selects a random index
    user_agent = random.choice(user_agents)

    # Returns the headers
    return {"User-Agent": user_agent}