import os
import shutil

# Function removes any uncessary files from the folder
def remove_uncessary_files(directory):
    # List of file extensions to remove
    extensions = [".tmp", ".log", ".bak", ".DS_Store"]

    # Goes through the folder to remove the files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endwith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    print(f"Removed: {file_path}")
                except Exception as e:
                    print(f"Error removing {file_path}: {e}")
