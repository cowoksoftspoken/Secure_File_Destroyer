# Secure Delete Tool (Enhanced)

A command-line utility written in C++ that securely deletes files by overwriting them multiple times before deletion, making recovery extremely difficult or impossible. Enhanced version includes platform-awareness, colored output, and encryption-based approaches.

## Features

- Multiple overwrite passes using different patterns
- Random data generation for additional security
- User confirmation before deletion
- File renaming as an additional security measure
- Support for custom number of overwrite passes
- Colored CLI output for better user experience
- Platform-specific warnings and recommendations
- Progress bar visualization
- Encryption-based secure deletion option
- Compliance with data sanitization standards

## Installation

```bash
# Clone or copy the source files
g++ -std=c++11 -Wall -Wextra -O2 -o secure_delete secure_delete.cpp
g++ -std=c++11 -Wall -Wextra -O2 -o secure_delete_enhanced secure_delete_enhanced.cpp

# Or use make
make

# Optionally install globally
sudo make install
```

## Usage

```bash
# Basic usage (original version)
./secure_delete [OPTIONS] <file_path>

# Enhanced version with all features
./secure_delete_enhanced [OPTIONS] <file_path>

# With specific number of overwrite passes
./secure_delete_enhanced -p 7 my_sensitive_file.txt

# Using random data for all passes
./secure_delete_enhanced -r my_very_sensitive_file.txt

# With encryption-based approach
./secure_delete_enhanced -e -p 5 my_ultra_sensitive_file.txt

# With both custom passes and random data
./secure_delete_enhanced -p 10 -r my_top_secret_file.txt

# Show help
./secure_delete_enhanced --help
```

## Options (Enhanced Version)

- `-h, --help`: Show help message
- `-p, --passes N`: Number of overwrite passes (default: 3)
- `-r, --random`: Use random data for all passes instead of standard patterns
- `-e, --encrypt`: Use encryption-based secure deletion approach
- `-v, --verbose`: Show detailed progress information

## Security Methodology

The tool uses the following approach to securely delete files:

1. **Multiple Overwrite Passes**: The file content is overwritten multiple times with different patterns
   - If using standard patterns: First pass with zeros, second with ones, third with random data
   - If using random data: Each pass uses a new random pattern
   - Additional passes use random data regardless of mode

2. **Random Data Generation**: Each overwrite pass uses cryptographically secure random data

3. **File Renaming**: After overwriting, the file is renamed to a random name before final deletion

4. **Platform Awareness**: The tool provides warnings about limitations on different platforms (Android, Windows)

5. **File System Operations**: The tool flushes data to disk after each write operation to ensure it's actually written to storage

6. **Encryption Option**: When `-e` flag is used, the tool uses an encryption-based approach (in real implementations, this would involve actual encryption)

## Platform Effectiveness

- **Linux/HDD**: Highly effective
- **Linux/SSD**: Moderately effective (TRIM may limit effectiveness)
- **Android**: Limited effectiveness due to file-based encryption and storage management
- **Windows**: Limited effectiveness due to journaling and other features

## Warning

This tool permanently and securely deletes files. Files deleted with this tool cannot be recovered using standard recovery tools. Use with extreme caution and ensure you have backups of important data before using this tool.

## Compliance

The standard overwrite pattern follows the DoD 5220.22-M standard for data sanitization (3-pass method), but allows for more passes for higher security requirements.