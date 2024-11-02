#!/bin/bash

filename = anyname
executable_name = anyname.exe

# G++ command compiles the above varibles to and executable file

echo "$filename is now compiling." 

g++ $filename -o $executable_name

echo "Compiling of $filename now completed."