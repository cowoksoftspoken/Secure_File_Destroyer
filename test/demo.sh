#!/bin/bash

echo "Secure Delete Tool - Demo Script"
echo "=================================="
echo

# Create some test files
echo "Creating test files..."
echo "This is confidential data that needs secure deletion" > confidential.txt
echo "More sensitive information" > sensitive.txt
echo "Personal information here" > personal.txt

echo "Created the following files:"
ls -l *.txt
echo

# Demonstrate the tool with different options
echo "1. Securely deleting with default 3 passes:"
echo "YES" | ./secure_delete confidential.txt

echo
echo "Files after first deletion:"
ls -l *.txt 2>/dev/null || echo "All files deleted"

echo
echo "2. Securely deleting with 5 passes and random data:"
echo "YES" | ./secure_delete -p 5 -r sensitive.txt

echo
echo "Files after second deletion:"
ls -l *.txt 2>/dev/null || echo "All files deleted"

echo
echo "3. Securely deleting with 1 pass (minimal security):"
echo "YES" | ./secure_delete -p 1 personal.txt

echo
echo "Final file list:"
ls -l *.txt 2>/dev/null || echo "All files deleted"

echo
echo "Demo completed. All test files have been securely deleted."