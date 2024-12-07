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
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Spreadsheets")
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Spreadsheets")
    # Checks for presentations in the downloads folder
    elif file_path == "ppt" or file_path == "pptx" or file_path == "odp":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Presentations"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Presentations")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Presentations")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Presentations")
    # Checks for audio files in the downloads folder
    elif file_path == "mp3" or file_path == "wav" or file_path == "aac" or file_path == "flac":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Audio"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Audio")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Audio")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Audio")
    # Checks for video files in the downloads folder
    elif file_path == "mp4" or file_path == "avi" or file_path == "mov" or file_path == "mkv" or file_path == "wmv":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Vidio"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Vidio")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Vidio")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Vidio")
    # Checks for compressed files in the downloads folder
    elif file_path == "zip" or file_path == "rar" or file_path == "7z" or file_path == "tar" or file_path == "gz":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Compressed Files"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Compressed Files")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Compressed Files")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Compressed Files")
    # Checks for executable files in the downloads folder
    elif file_path == "exe" or file_path == "bat" or file_path == "sh" or file_path == "msi":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Executables"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Executables")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Executables")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Executables")
    # Checks for web development files in the downloads folder
    elif file_path == "html" or file_path == "css" or file_path == "js" or file_path == "php" or file_path == "xml":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Web Devlopement"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Web Devlopment")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Web Devlopement")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Web Devlopement")
    elif file_path == "py" or file_path == "java" or file_path == "cpp" or file_path == "js" or file_path == "rb":
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Programming"):
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Programming")
        else:
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Programming")
            shutil.move(file, "/Users/kieranpritchard/Documents/Sorted Downloads/Programming")
    # Moves any unspecified file type to a special folder
    else:
        if os.path.exists("/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified"):
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
        else: 
            os.makedirs("/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")
            shutil.move(file,"/Users/kieranpritchard/Documents/Sorted Downloads/Unspecified")