import os
import shutil
import json

def move_files_to_folder(downloads_folder_path, sorted_files_location):
    # Loops through files to their file path
    for file in os.listdir(downloads_folder_path):
        # Splits the text into a tuple and then gets the file extension.
        file_path = os.path.splitext(file)[1]

        # Checks for images in the downloads folder
        if file_path == "jpg" or file_path == "jpeg" or file_path == "png" or file_path == "gif" or file_path == "bmp" or file_path == "svg":
            if os.path.exists(sorted_files_location + "/Images"):
                shutil.move(file,sorted_files_location + "/Images")
            else:
                os.makedirs(sorted_files_location + "/Images")
                shutil.move(file, sorted_files_location + "/Images")
        # Checks for documents in the downloads folder
        elif file_path == "pdf" or file_path == "docx" or file_path == "doc" or file_path == "txt" or file_path == "odt" or file_path == "rtf":
            if os.path.exists(sorted_files_location + "/Documents"):
                shutil.move(file, sorted_files_location + "/Documents")
            else:
                os.makedirs( sorted_files_location + "/Documents")
                shutil.move(file, sorted_files_location + "/Documents")
        # Checks for spreadsheets in the downloads folder
        elif file_path == "xls" or file_path == "xlsx" or file_path == "csv" or file_path == "ods":
            if os.path.exists(sorted_files_location + "/Spreadsheets"):
                shutil.move(file, sorted_files_location + "/Spreadsheets")
            else:
                os.makedirs(sorted_files_location + "/Spreadsheets")
                shutil.move(file, sorted_files_location + "/Spreadsheets")
        # Checks for presentations in the downloads folder
        elif file_path == "ppt" or file_path == "pptx" or file_path == "odp":
            if os.path.exists(sorted_files_location + "/Presentations"):
                shutil.move(file, sorted_files_location + "/Presentations")
            else:
                os.makedirs(sorted_files_location + "/Presentations")
                shutil.move(file, sorted_files_location + "/Presentations")
        # Checks for audio files in the downloads folder
        elif file_path == "mp3" or file_path == "wav" or file_path == "aac" or file_path == "flac":
            if os.path.exists(sorted_files_location + "/Audio"):
                shutil.move(file, sorted_files_location + "/Audio")
            else:
                os.makedirs(sorted_files_location + "/Audio")
                shutil.move(file, sorted_files_location + "/Audio")
        # Checks for video files in the downloads folder
        elif file_path == "mp4" or file_path == "avi" or file_path == "mov" or file_path == "mkv" or file_path == "wmv":
            if os.path.exists(sorted_files_location + "/Video"):
                shutil.move(file, sorted_files_location + "/Video")
            else:
                os.makedirs(sorted_files_location + "/Video")
                shutil.move(file, sorted_files_location + "/Video")
        # Checks for compressed files in the downloads folder
        elif file_path == "zip" or file_path == "rar" or file_path == "7z" or file_path == "tar" or file_path == "gz":
            if os.path.exists(sorted_files_location + "/Compressed Files"):
                shutil.move(file,sorted_files_location + "/Compressed Files")
            else:
                os.makedirs(sorted_files_location + "/Compressed Files")
                shutil.move(file, sorted_files_location + "/Compressed Files")
        # Checks for executable files in the downloads folder
        elif file_path == "exe" or file_path == "bat" or file_path == "sh" or file_path == "msi":
            if os.path.exists(sorted_files_location + "/Executables"):
                shutil.move(file,sorted_files_location + "/Executables")
            else:
                os.makedirs(sorted_files_location + "/Executables")
                shutil.move(file,sorted_files_location + "/Executables")
        # Checks for web development files in the downloads folder
        elif file_path == "html" or file_path == "css" or file_path == "js" or file_path == "php" or file_path == "xml":
            if os.path.exists(sorted_files_location + "/Web Devlopement"):
                shutil.move(file,sorted_files_location + "/Web Devlopment")
            else:
                os.makedirs(sorted_files_location + "/Web Devlopement")
                shutil.move(file, sorted_files_location + "/Web Devlopement")
        # Checks for programming files in the downloads folder
        elif file_path == "py" or file_path == "java" or file_path == "cpp" or file_path == "js" or file_path == "rb":
            if os.path.exists(sorted_files_location + "/Programming"):
                shutil.move(file,sorted_files_location + "/Programming")
            else:
                os.makedirs(sorted_files_location + "/Programming")
                shutil.move(file,sorted_files_location + "/Programming")
        # Checks for system files in the downloads folder
        elif file_path == "dll" or file_path == "sys" or file_path == "log" or file_path == "ini":
            if os.path.exists(sorted_files_location + "/System Files"):
                shutil.move(file,sorted_files_location + "/System Files")
            else:
                os.makedirs(sorted_files_location + "/System Files")
                shutil.move(file,sorted_files_location + "/System Files")
        # Moves any unspecified file type to a special folder
        else:
            if os.path.exists(sorted_files_location + "/Unspecified"):
                shutil.move(file,sorted_files_location + "/Unspecified")
            else: 
                os.makedirs(sorted_files_location + "/Unspecified")
                shutil.move(file,sorted_files_location + "/Unspecified")

def main():
    config_file = "config.json"
    
    with open(config_file, "r") as config_file:
        config_data = json.load(config_file)

        downloads_folder_path = config_data["downloads_folder_path"]
        sorted_files_location = config_data["sorted_files_location"]

    move_files_to_folder(downloads_folder_path,sorted_files_location)

if __name__ == "__main__":
    main()