import os
import shutil

# Main project directory paths
python_project_path = "/Users/kieranpritchard/Documents/Coding Projects/Python/Projects"
html_css_js_project_path = "/Users/kieranpritchard/Documents/Coding Projects/HTML, CSS & Javascript/Projects"
cpp_project_path = "/Users/kieranpritchard/Documents/Coding Projects/C++/Projects"
main_project_paths = [python_project_path, html_css_js_project_path, cpp_project_path]

# Special file template paths
readme_template = "Script-Vault/Coding Project Organiser/Templates/ReadMe.md"
changelog_template = "Script-Vault/Coding Project Organiser/Templates/CHANGELOG.MD"
security_template = "Script-Vault/Coding Project Organiser/Templates/SECURITY.md"
license_template = "Script-Vault/Coding Project Organiser/Templates/LICENSE.md"
codeowners_template = "Script-Vault/Coding Project Organiser/Templates/CODEOWNERS.txt"
issue_template = "Script-Vault/Coding Project Organiser/Templates/ISSUE_TEMPLATE.md"
pull_request_template = "Script-Vault/Coding Project Organiser/Templates/PULL_REQUEST_TEMPLATE.md"
special_files = [readme_template, changelog_template, security_template, license_template, codeowners_template, issue_template, pull_request_template]

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

def sort_and_organise_general_projects(directory):
    for project in os.listdir(directory):
        project_path = os.path.join(directory, project)
        # Checks project path for if it exists
        if os.path.isdir(project_path):
            # Copies special files
            for item in special_files:
                dest_path = os.path.join(project_path, os.path.basename(item))
                if os.path.exists(item) and not os.path.exists(dest_path):
                    shutil.copyfile(item, dest_path)
            # Creates file structure
            for folder in general_file_structure:
                folder_path = os.path.join(project_path, folder)
                os.makedirs(folder_path, exist_ok=True)
            # Move files to their proper folders
            for root, dirs, files in os.walk(project_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Groups file type to a folder
                    ext_to_folder = {
                        ".py": "src",
                        ".html": "src",
                        ".css": "src",
                        ".js": "src",
                        ".cpp": "src",
                        ".md": "doc",
                        ".rst": "doc",
                        ".sh": "tools",
                        ".cmd": "tools",
                    }
                    # Checks for dependency files
                    if file == "requirements.txt" or file == "package.json":
                        dest_folder = "dep"
                    elif file == "Readme.md":
                        continue
                    else:
                        # Gets dictionary name for folder to move to
                        dest_folder = ext_to_folder.get(os.path.splitext(file)[1])
                    if dest_folder:
                        dest_path = os.path.join(project_path, dest_folder, file)
                        if not os.path.exists(dest_path):  # This avoids accidental deletion
                            shutil.move(file_path, dest_path)

# Sets the script to run automatically when run
running_automation = False

# Checks if script is running automatically
if running_automation:
    while running_automation:
        # Sorts the different general projects out as automation
        for path in main_project_paths:
            sort_and_organise_general_projects(path)
else:
    for path in main_project_paths:
        sort_and_organise_general_projects(path)