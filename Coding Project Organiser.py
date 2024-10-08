import os
import shutil

# Main project directory path
python_project_path = "/Users/kieranpritchard/Documents/Coding Projects/Python/Projects"

# File structure for each programming language
general_file_structure = [
    "test",
    "src",
    ".build",
    "tools",
    "doc",
    "dep",
    "samples",
    "res"
]

# Function to create structure
def organise_structure(project_path):
    for folder in general_file_structure:
        folder_path = os.path.join(project_path, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

# Function moves code files to the 'src' folder
def move_code_files(project_path):
    src_folder = os.path.join(project_path, 'src')
    if not os.path.exists(src_folder):
        os.makedirs(src_folder)
    
    for root, dirs, files in os.walk(project_path):
        for file in files:
            file_path = os.path.join(root, file)
            dest_folder = None
            
            # Checks for code files
            if file.endswith('.py'):
                dest_folder = 'src'
            elif file.endswith('.html'):
                dest_folder = 'src'
            elif file.endswith('.css'):
                dest_folder = 'src'
            elif file.endswith('.js'):
                dest_folder = 'src'
            elif file.endswith('.cpp'):
                dest_folder = 'src'
            #Checks for files for 'doc' folder
            elif file.endswith('.md') or file.endswith('.rst'):
                dest_folder = 'doc'
            #Checks for files for 'tools' folder
            elif file.endswith('.sh') or file.endswith('.cmd'):
                dest_folder = 'tools'
            #Checks for files for the dep folder
            elif file == 'requirements.txt' or file == 'package.json':
                dest_folder = 'dep'

            if dest_folder:
                dest_path = os.path.join(project_path, dest_folder, file)
                if not os.path.exists(dest_path):  # Avoid deletion by checking if file exists
                    shutil.move(file_path, dest_path)
                    print(f"Moved {file} to {dest_folder}")

# Function sorts the projects
def sort_projects(directory):
    for project in os.listdir(directory):
        project_path = os.path.join(directory, project)
        if os.path.isdir(project_path):
            organise_structure(project_path)
            move_code_files(project_path)

# Example usage
sort_projects(python_project_path)