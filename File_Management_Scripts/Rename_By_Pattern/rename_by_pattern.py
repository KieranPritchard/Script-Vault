import os
from rich import print
from rich.progress import track

def rename_by_file_type():
    folder = input("Please input file path: ")
    print("=" * 30)

    photo_iterator = 1
    document_iterator = 1
    spreadsheet_iterator = 1
    presentaition_iterator = 1
    audio_iterator = 1
    video_iterator = 1

    for file in track(os.listdir(folder), description="Renaming photos..."):
        file_path = os.path.join(folder, file)
        if file_path[1] == "jpg" or file_path[1] == "jpeg" or file_path[1] == "png" or file_path[1] == "gif":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            photo_iterator += 1
        elif file_path[1] == "pdf" or file_path[1] == "docx" or file_path[1] == "doc" or file_path[1] == "txt" or file_path[1] == "odt" or file_path[1] == "rtf":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            document_iterator += 1
        elif file_path[1] == "xls" or file_path[1] == "xlsx" or file_path[1] == "csv" or file_path[1] == "ods":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            spreadsheet_iterator += 1
        elif file_path[1] == "ppt" or file_path[1] == "pptx" or file_path[1] == "odp":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            presentaition_iterator += 1
        elif file_path[1] == "mp3" or file_path[1] == "wav" or file_path[1] == "aac" or file_path[1] == "flac":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            audio_iterator += 1
        elif file_path[1] == "mp4" or file_path[1] == "avi" or file_path[1] == "mov" or file_path[1] == "mkv" or file_path[1] == "wmv":
            path_array = file.split("/")
            path_array[len(path_array) -1] = f"photo_{photo_iterator}"
            new_path = ""
            for x in path_array:
                new_path += f"/{x}"
            os.rename(file, new_path)
            video_iterator += 1

def rename_by_directory_name():
    return

def main():
    print("=" * 60)
    print("[bold]Rename by Pattern[/bold]")
    while(True):
        print("=" * 60)
        print("[bold]Please select your option:[/bold]")
        print("(1) Rename by file type.")
        print("(2) Rename by directory name.")
        print("(3) Quit.")
        print("=" * 60)
        user_option = int(input("Input your choice: "))
        print("=" * 60)

        if user_option == 1:
            rename_by_file_type()
        elif user_option == 2:
            rename_by_directory_name()
        elif user_option == 3:
            break
        else:
            print("Invaild Option")

if __name__ == "__main__":
    main()