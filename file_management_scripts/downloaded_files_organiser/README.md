# Script: Downloaded Files Organiser

## Project Description

### Objective

To create a script that when run, sorts and organises the contents of my downloads folder into a folder in my documents. the aim in doing this, is to ensure my downloads folder doesnt become packed with random files with no structure.

### Features

* Sorts and moves files in downloads folder to another folder for each type.
* Allows for easy sorting of downloads folder.

### Technologies and Tools Used

* **Language:** Python
* **Frameworks/Librarys:** Shutil, os, json 

### Challenges Faced

I only had one challenge that was with using JSON files however, that was due to me not working with them before building this script. I decided to use them based off research into what would be a good config file type.

### Outcome

I sucessfully used python and the modules listed, to create this automation. In the future, if my needs for this function change I can then make further changes.

### How To Use Script

1. **Set Up Your Environment:**
    * Make sure you have Python installed (version 3.x recommended). If not, download it from python.org.

2. **Configure the Script:**
    * The script uses a configuration file located at: `Script-Vault/File-Management-Scripts/Downloaded Files Organiser/res/config.json`

    * Open this file and specify the paths for:
        * `downloads_folder_path`: The folder containing the files to be sorted.
        * `sorted_files_location`: The folder where sorted files should be moved.

3. **Run the Script:**
    * Open a terminal or command prompt and navigate to your project directory where the script is located.
    * Use the following command to execute the script: `python script_name.py`

4. **File Sorting Process:**
    * The script will scan the downloads folder and organize files into categories like:
        * Images
        * Documents
        * Spreadsheets
        * Presentations
        * Audio
        * Video
        * Compressed Files
        * Executables
        * Web Development
        * Programming
        * System Files
        * Unspecified (for unknown file types)

5. **Verify Your Sorted Files:**
    * Check the sorted_files_location folder to confirm that files have been categorized correctly.