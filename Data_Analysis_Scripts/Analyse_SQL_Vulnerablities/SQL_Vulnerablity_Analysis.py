import os

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