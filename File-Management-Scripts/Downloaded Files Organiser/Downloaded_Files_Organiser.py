import os
import shutil

# Main varibles to make the script work
downloads_folder_path = "/Users/kieranpritchard/Downloads"
sorted_files_location = "/Users/kieranpritchard/Documents/Sorted Downloads"

# Loops through files to their file path
for file in os.listdir(downloads_folder_path):
    # Splits the text into a tuple and then gets the file extension.
    file_path = os.path.splitext(file)[1]

    # Checks for images in the downloads folder
    if file_path == "jpg" or file_path == "png":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Images"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Images")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Images")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Images")