import os
import shutil

# Function removes any uncessary files from the folder
def remove_uncessary_files(directory):
    # List of file types to get rid of
    extensions_to_remove = [".tmp", ".log", ".bak", ".DS_Store"]

    # Go through the folder and delete these files
    for root, dirs, files in os.walk(directory):
        # Loop over all files
        for file in files:
            # Check if this file should be removed
            if any(file.endswith(extension) for extension in extensions_to_remove):
                # Full path to the file
                file_path = os.path.join(root, file)
                # Try removing it
                try:
                    os.remove(file_path)
                    # Confirm it got removed
                    print(f"Removed: {file_path}")
                except Exception as e:
                    # Show error if it fails
                    print(f"Error removing {file_path}: {e}")

# Function sorts files into the proper folders
def organise_project_folder(directory):
    # Folders we want to keep stuff in
    folders = ["test", "src", ".build", "tools", "doc", "dep", "samples", "res"]
    folder_paths = {os.path.join(directory, f) for f in folders}

    # Make the folders if they don't exist
    for folder in folders:
        folder_path = os.path.join(directory, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

    # Go through all files and move them
    for root, _, files in os.walk(directory):
        # Skip if we're already in a target folder
        if root in folder_paths:
            continue

        for file in files:
            # Decide which folder it should go in
            file_extension = file.split('.')[-1]
            if file_extension in ['py', 'html', 'css', 'cpp', 'js']:
                destination_folder = "src"
            elif file_extension in ['md', 'txt', 'rst']:
                destination_folder = "doc"
            elif file_extension in ['png', 'jpg', 'jpeg', 'gif']:
                destination_folder = "res"
            else:
                # Skip stuff we don't know
                continue

            # Make sure destination exists
            destination_folder_path = os.path.join(directory, destination_folder)
            os.makedirs(destination_folder_path, exist_ok=True)

            # Move the file
            shutil.move(os.path.join(root, file), os.path.join(destination_folder_path, file))
            print(f"Moved {file} to {destination_folder_path}")

if __name__ == "__main__":
    # Ask user for the folder to clean
    folder_to_clean = input("Enter the directory you want to clean: ")
    # Checks if the os path exists
    if os.path.exists(folder_to_clean):
        # checks if there are unnessary files and organises the files
        remove_uncessary_files(folder_to_clean)
        organise_project_folder(folder_to_clean)
    else:
        # prints that the folder doesnt exist
        print("Entered folder does not exist.")