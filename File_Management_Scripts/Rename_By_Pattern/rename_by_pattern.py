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
        ext = file_path.split(".")[-1].lower()
        if ext == "jpg" or ext == "jpeg" or ext == "png" or ext == "gif":
            new_file_name = f"photo_{photo_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
            photo_iterator += 1
        elif ext == "pdf" or ext == "docx" or ext == "doc" or ext == "txt" or ext == "odt" or ext == "rtf":
            new_file_name = f"document_{document_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
            document_iterator += 1
        elif ext == "xls" or ext == "xlsx" or ext == "csv" or ext == "ods":
            new_file_name = f"spreadsheet_{spreadsheet_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
            spreadsheet_iterator += 1
        elif ext == "ppt" or ext == "pptx" or ext == "odp":
            new_file_name = f"presentaition_{presentaition_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
            presentaition_iterator += 1
        elif ext == "mp3" or ext == "wav" or ext == "aac" or ext == "flac":
            new_file_name = f"audio_{audio_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
            audio_iterator += 1
        elif ext == "mp4" or ext == "avi" or ext == "mov" or ext == "mkv" or ext == "wmv":
            new_file_name = f"video_{video_iterator}.{ext}"
            new_file_path = os.path.join(folder, new_file_name)
            os.rename(file_path, new_file_path)
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