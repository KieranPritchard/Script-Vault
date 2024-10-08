import os
import shutil

#Main project directory path
python_project_path = "/Users/kieranpritchard/Documents/Coding Projects/Python/Projects"
html_css_js_project_path = "/Users/kieranpritchard/Documents/Coding Projects/HTML, CSS & JavaScript/Projects"
cpp_project_path = "/Users/kieranpritchard/Documents/Coding Projects/C++/Projects"

#File structure for each programing langage
general_file_structure = [
    "test",
    "src",
    ".build",
    "tools",
    "docs",
    "dep",
    "samples",
    "res"
]

#function to create structure
def organise_structure(project_path):
    for folder in general_file_structure:
        folder_path = os.path.join(project_path, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

def sort_projects(directory):
    for project in os.listdir(directory):
        project_path = os.path.join(directory, project)
        if os.path.isdir(project_path):
            organise_structure(project_path)

sort_projects(python_project_path)
sort_projects(html_css_js_project_path)
sort_projects(cpp_project_path)