import os
from matplotlib import pyplot as plt
import tldextract
import pandas as pd


plt.style.use("ggplot")

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
    df.dropna()

    # Creates a new column called subdomain
    df["Subdomain"] = df["Affected_URL"].apply(
        lambda x: tldextract.extract(x).subdomain if x else tldextract.extract(x).domain
    )

    # Groups the data by injection type
    grouped_by_type = df.groupby("SQL_Injection_Type").size()

    # Groups the data by subdomain
    grouped_by_subdomain = df.groupby("Subdomain").size()

    # Plots the grouped by chart first
    grouped_by_type.plot(kind="pie", autopct='%1.1f%%')

    # Adds the title
    plt.title("SQL Injection Types Found")

    plt.show()

    # Plots the subdomain chart
    grouped_by_subdomain.plot(kind="bar")

    # Names the axis
    plt.xlabel("Subdomains")
    plt.ylabel("Number of SQLi Vulns")

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()