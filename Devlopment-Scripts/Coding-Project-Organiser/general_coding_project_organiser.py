import os
import shutil

# Function removes any uncessary files from the folder
def remove_uncessary_files(directory):
    # List of file extensions to remove
    extensions_to_remove = [".tmp", ".log", ".bak", ".DS_Store"]

    # Goes through the folder to remove the files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endwith(extension) for extension in extensions_to_remove):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    print(f"Removed: {file_path}")
                except Exception as e:
                    print(f"Error removing {file_path}: {e}")

def organise_project_folder(directory):
    folders = ["test", "src", ".build", "tools", "doc", "dep", "samples", "res"]
    folder_paths = {os.path.join(directory, f) for f in folders}

    for folder in folders:
        folder_path = os.path.join(directory, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

    for root, _, files in os.walk(directory):
        if root in folder_paths:
            continue

        for file in files:
            # Checks if this which path the folder should go in.
            file_extenstion = file.split('.')[-1]
            if file_extenstion in ['py', 'html', 'css', 'cpp', 'js']:
                destination_folder = "src"
            elif file_extenstion in ['md', 'txt', 'rst']:
                destination_folder = "doc"
            elif file_extenstion in ['png', 'jpg', 'jpeg', 'gif']:
                destination_folder = "res"
            else:
                continue

            # Makes the file path for the new folder and checks if it already exists
            destination_folder_path = os.path.join(directory, destination_folder)
            os.makedirs(destination_folder_path, exist_ok=True)

            shutil.move(os.path.join(root, file), os.path.join(destination_folder_path, file))
            print(f"Moved {file} to {destination_folder_path}")