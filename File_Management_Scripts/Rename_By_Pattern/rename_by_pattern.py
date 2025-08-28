import os
from rich import print

def rename_by_file_type():
    return

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