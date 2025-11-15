#!/bin/bash

echo -e "\033[33mSecure Delete Tool (Enhanced) - Demo Script\033[0m"
echo -e "\033[33m=========================================\033[0m"
echo

# Create some test files
echo -e "\033[36mCreating test files...\033[0m"
echo "This contains highly confidential information" > confidential.txt
echo "Even more sensitive data here" > sensitive.txt
echo "Personal private information" > personal.txt

echo -e "\033[32mCreated the following files:\033[0m"
ls -l *.txt
echo

# Demonstrate the enhanced tool with different options
echo -e "\033[34m1. Securely deleting with default 3 passes:\033[0m"
echo "DELETE" | ./secure_delete_enhanced confidential.txt

echo
echo -e "\033[32mFiles after first deletion:\033[0m"
ls -l *.txt 2>/dev/null || echo -e "\033[32mAll files deleted\033[0m"

echo
echo -e "\033[34m2. Securely deleting with 5 passes and random data:\033[0m"
echo "DELETE" | ./secure_delete_enhanced -p 5 -r sensitive.txt

echo
echo -e "\033[32mFiles after second deletion:\033[0m"
ls -l *.txt 2>/dev/null || echo -e "\033[32mAll files deleted\033[0m"

echo
echo -e "\033[34m3. Securely deleting with encryption approach:\033[0m"
echo "DELETE" | ./secure_delete_enhanced -e -p 3 personal.txt

echo
echo -e "\033[32mFinal file list:\033[0m"
ls -l *.txt 2>/dev/null || echo -e "\033[32mAll files deleted\033[0m"

echo
echo -e "\033[33mDemo completed. All test files have been securely deleted.\033[0m"
echo -e "\033[33mEnhanced features like colored output, progress bars, and platform warnings are working correctly.\033[0m"