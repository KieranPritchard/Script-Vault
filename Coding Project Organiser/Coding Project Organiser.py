import os
import shutil

# Main project directory paths
python_project_path = "/Users/kieranpritchard/Documents/Coding Projects/Python/Projects"
html_css_js_project_path = "/Users/kieranpritchard/Documents/Coding Projects/HTML, CSS & Javascript/Projects"
cpp_project_path = "/Users/kieranpritchard/Documents/Coding Projects/C++/Projects"

# Special file template paths
readme_template = ""
changelog_template = ""
security_template = ""
license_template = ""
codeowners_template = ""
issue_template = ""
pull_request_template = ""

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
        project_path = os.path.join(directory,project)

        # Checks project path for if it exists
        if os.path.isdir(project_path):
            # Copys special files
            shutil.copyfile(readme_template,project_path)
            shutil.copyfile(changelog_template,project_path)
            shutil.copyfile(security_template, project_path)
            shutil.copyfile(license_template,project_path)
            shutil.copyfile(codeowners_template, project_path)
            shutil.copyfile(issue_template, project_path)
            shutil.copyfile(pull_request_template,project_path)

            # Creates file structure
            for folder in general_file_structure:
                folder_path = os.path.join(project_path,folder)
                os.makedirs(folder_path,exist_ok=True)
            
            # Move files to their proper folders
            for root, dirs, files in os.walk(project_path):
                for file in files:
                    file_path = os.path.join(root,file)
                    
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
                    # Checks for dependancy files
                    if file == "requirements.txt" or file == "package.json":
                        dest_folder = "dep"
                    elif file == "Readme.md":
                        continue
                    else:
                        # Gets dictionary name for folder to move to
                        dest_folder = ext_to_folder.get(os.path.splitext(file)[1])

                    if dest_folder:
                        dest_path = os.path.join(project_path, dest_folder,file)
                        if not os.path.exists(dest_path): # This avoids accidental deletion
                            shutil.move(file_path,dest_path)

# Sets the script to run automatically when run
running_automation = False

# Checks if script is automatically
if running_automation == True:
    while running_automation == True:
        # Sorts the different general projects out as automation.
        sort_and_organise_general_projects(python_project_path)
        sort_and_organise_general_projects(html_css_js_project_path)
        sort_and_organise_general_projects(cpp_project_path)
else:
    sort_and_organise_general_projects(python_project_path)
    sort_and_organise_general_projects(html_css_js_project_path)
    sort_and_organise_general_projects(cpp_project_path)