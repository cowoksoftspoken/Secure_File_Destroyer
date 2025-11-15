#!/bin/bash

echo "Testing Secure Delete Tool with User Confirmation"
echo "================================================="

# Create a test file
echo "Creating a test file with sensitive content..."
echo "This contains very sensitive information that must be securely deleted" > test_sensitive.txt
ls -l test_sensitive.txt
echo "Content: $(cat test_sensitive.txt)"
echo

echo "Attempting to delete with incorrect confirmation (should cancel)..."
echo "NO" | ./secure_delete test_sensitive.txt
echo "After incorrect confirmation:"
ls -l test_sensitive.txt 2>/dev/null && echo "File still exists - good, operation was cancelled"
echo

echo
echo "Now trying with correct confirmation..."
echo "Type YES when prompted"
./secure_delete test_sensitive.txt << EOF
YES
EOF

echo
echo "After correct confirmation:"
if [ -f test_sensitive.txt ]; then
    ls -l test_sensitive.txt
    echo "ERROR: File still exists!"
else
    echo "SUCCESS: File has been securely deleted"
fi

# Clean up if needed
rm -f test_sensitive.txt 2>/dev/null