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
    if file_path == "jpg" or file_path == "jpeg" or file_path == "png" or file_path == "gif" or file_path == "bmp" or file_path == "svg":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Images"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Images")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Images")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Images")
    # Checks for documents in the downloads folder
    elif file_path == "pdf" or file_path == "docx" or file_path == "doc" or file_path == "txt" or file_path == "odt" or file_path == "rtf":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Documents"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Documents")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Documents")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Documents")
    # Checks for spreadsheets in the downloads folder
    elif file_path == "xls" or file_path == "xlsx" or file_path == "csv" or file_path == "ods":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Spreadsheets"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Spreadsheets")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
    else:
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
        else: 
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")