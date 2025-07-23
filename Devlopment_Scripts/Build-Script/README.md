# Script: Build
## Description of Script:
### Project Description
### Objective
To simplify compiling C++/C code when testing and using. Mainly, because I wanted to streamline this process and have a script to do this ready when coding with these languages.
### Features
* Quick and easy compilation with filename as only arguement.
* Simple to use.
### Technologies and Tools Used
* **Language:** Bash
* **Tools:** G++
### Challenges Faced
I didn't encounter much in the way of challenges, this was more because I was following a guide on how to use this method of scripting.
## How to use Script:
1. **Set Up Your Environment:**
	* Make sure you have a Bash-compatible terminal.
	* Ensure g++ is installed. If not, install it with:

```bash

sudo apt install g++ # For Debian/Ubuntu

brew install gcc # For macOS

```

2. **Run the Script:**
	* Open a terminal and navigate to the directory where the script is located.
	* Use the following command to compile a C++ file:
```bash

./script_name.sh your_file.cpp

```

3. **Compilation Process:**
	* The script checks if a filename is provided.
	* It verifies the existence of the specified file.
	* It ensures g++ is installed before proceeding.
	* The script compiles the file into an executable with the same name but an .exe extension.
4. **Verify the Output:**
	* If successful, the compiled executable will be in the same directory.
	* If errors occur, the script will display an appropriate message.