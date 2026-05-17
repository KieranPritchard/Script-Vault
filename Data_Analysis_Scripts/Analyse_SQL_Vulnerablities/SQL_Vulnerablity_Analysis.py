import os
import tldextract
import pandas as pd

def read_and_clean_data(file_path):
    """Function to read in and clean data"""
    
    # Reads in the data using pandas
    df = pd.read_csv(file_path)

    # Outputs information about the data imported
    print(f"Head:\n{df.head()}")
    print(f"Info:\n{df.info()}")
    print(f"Description:\n{df.describe()}")
    print(f"Missing Values:\n{df.isna().sum()}")

    # Replaces data with n/a with None
    df.replace("N/A", None)

    # Drops the rows with null values
    df.dropna(0)

    # Returns the data
    return df

def enrich_data(df):
    """Function to enrich the data"""

    # Creates a new column called subdomain
    df["Subdomain"] = df["url"].apply(
        lambda x: tldextract.extract(x).subdomain if x else tldextract.extract(x).domain
    )

    # Returns the dataframe
    return df

def main():
    # Loops while the input is incorrect
    while True:
        # Allows a file to be entered
        file_path = input("Please enter the file path: ").strip()

        # Checks if there is not a input
        if not file_path:
            # Outputs an error message
            print("Please enter a file path.")
        elif not os.path.exists(file_path):
            # Outputs an error message
            print("Please enter a file that exists")
        elif not os.path.isfile(file_path) and os.path.isdir(file_path):
            # Outputs a message
            print("Please enter a actual file")
        else:
            break