import os
import shutil

# Main varibles to make the script work
downloads_folder_path = "/Users/kieranpritchard/Downloads"
sorted_files_location = "/Users/kieranpritchard/Documents/Sorted Downloads"

# Loops through files to their file path
for file in os.listdir(downloads_folder_path):
    file_path = os.path.splitext(file)[1]

    