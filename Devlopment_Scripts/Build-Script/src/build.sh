#!/bin/bash

# Check if a filename is passed as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

filename=$1
executable_name="${filename%.*}.exe"

# Check if the file exists
if [ ! -f "$filename" ]; then
  echo "Error: '$filename' does not exist."
  exit 1
fi

# Check if g++ is installed
if ! command -v g++ &> /dev/null; then
  echo "Error: g++ is not installed. Please install g++ and try again."
  exit 1
fi

# Try compiling with the latest C++ standard (C++26 fallback to C++23 if unsupported)
echo "Compiling $filename with the latest C++ standard..."
if g++ -std=c++26 -Wall -Wextra -pedantic -O2 "$filename" -o "$executable_name" 2>/dev/null; then
  echo "Compilation successful (C++26). Output: $executable_name"
elif g++ -std=c++23 -Wall -Wextra -pedantic -O2 "$filename" -o "$executable_name"; then
  echo "Compilation successful (C++23). Output: $executable_name"
else
  echo "Error: Compilation failed."
  exit 1
fi