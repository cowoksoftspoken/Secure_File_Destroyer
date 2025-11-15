#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <iomanip>
#include <algorithm>
#include <sstream>

// Function to check if a file exists
bool fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

// Function to get file size
std::streamsize getFileSize(const std::string& filename) {
    struct stat buffer;
    if (stat(filename.c_str(), &buffer) == 0) {
        return buffer.st_size;
    }
    return -1;
}

// Function to overwrite file with a pattern
bool overwriteFile(const std::string& filename, const std::vector<char>& pattern) {
    std::fstream file;
    file.open(filename, std::ios::binary | std::ios::in | std::ios::out);
    
    if (!file.is_open()) {
        return false;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Overwrite the file with the pattern
    std::streamsize bytesWritten = 0;
    while (bytesWritten < fileSize) {
        std::streamsize chunkSize = std::min(static_cast<std::streamsize>(pattern.size()), fileSize - bytesWritten);
        file.write(pattern.data(), chunkSize);
        file.flush();
        bytesWritten += chunkSize;
    }
    
    file.close();
    return true;
}

// Function to generate random data for overwriting
std::vector<char> generateRandomPattern(std::streamsize size) {
    std::vector<char> pattern(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (std::streamsize i = 0; i < size; ++i) {
        pattern[i] = static_cast<char>(dis(gen));
    }
    
    return pattern;
}

// Function to perform secure deletion with multiple overwrite passes
bool secureDelete(const std::string& filename, int passes, bool useRandomData) {
    std::streamsize fileSize = getFileSize(filename);
    if (fileSize == -1) {
        std::cerr << "Error: Could not get file size for " << filename << std::endl;
        return false;
    }
    
    std::cout << "File size: " << fileSize << " bytes" << std::endl;
    
    // Define standard overwrite patterns (as per DoD 5220.22-M standard)
    std::vector<std::vector<char>> standardPatterns = {
        std::vector<char>(fileSize, 0x00),  // Pass 1: Fill with zeros
        std::vector<char>(fileSize, 0xFF),  // Pass 2: Fill with ones
        generateRandomPattern(fileSize)     // Pass 3: Fill with random data
    };
    
    // Perform the specified number of passes
    for (int pass = 0; pass < passes; ++pass) {
        std::cout << "Overwriting pass " << (pass + 1) << " of " << passes << "..." << std::flush;
        
        if (useRandomData) {
            // Use random data for each pass
            auto randomPattern = generateRandomPattern(fileSize);
            if (!overwriteFile(filename, randomPattern)) {
                std::cerr << "Error during overwrite pass " << (pass + 1) << std::endl;
                return false;
            }
        } else {
            // Use standard patterns for first 3 passes, then random
            if (pass < 3) {
                if (!overwriteFile(filename, standardPatterns[pass])) {
                    std::cerr << "Error during standard overwrite pass " << (pass + 1) << std::endl;
                    return false;
                }
            } else {
                auto randomPattern = generateRandomPattern(fileSize);
                if (!overwriteFile(filename, randomPattern)) {
                    std::cerr << "Error during random overwrite pass " << (pass + 1) << std::endl;
                    return false;
                }
            }
        }
        
        std::cout << " Done." << std::endl;
    }
    
    // Rename the file to a random name to further obscure it
    std::string tempName = filename;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    
    size_t lastSlash = tempName.find_last_of("/");
    std::string path = (lastSlash != std::string::npos) ? tempName.substr(0, lastSlash + 1) : "./";
    std::string newName = path + ".temp_" + std::to_string(dis(gen)) + "_" + std::to_string(time(nullptr));
    
    if (rename(filename.c_str(), newName.c_str()) != 0) {
        std::cerr << "Warning: Could not rename file before final deletion." << std::endl;
    } else {
        // Delete the renamed file
        if (unlink(newName.c_str()) != 0) {
            std::cerr << "Error: Could not delete file " << newName << std::endl;
            return false;
        }
    }
    
    std::cout << "File securely deleted: " << filename << std::endl;
    return true;
}

// Function to get user confirmation
bool getUserConfirmation(const std::string& filename) {
    std::cout << "Warning: You are about to securely delete the following file:" << std::endl;
    std::cout << "  " << filename << std::endl;
    std::cout << "This operation cannot be undone. Are you sure you want to continue?" << std::endl;
    std::cout << "Type 'YES' to confirm: ";
    
    std::string confirmation;
    std::cin >> confirmation;
    
    return (confirmation == "YES");
}

// Function to display help
void showHelp() {
    std::cout << "Secure File Deletion Tool" << std::endl;
    std::cout << "Securely wipes a file to prevent recovery" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: secure_delete [OPTIONS] <file_path>" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help         Show this help message" << std::endl;
    std::cout << "  -p, --passes N     Number of overwrite passes (default: 3)" << std::endl;
    std::cout << "  -r, --random       Use random data for all passes instead of standard patterns" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "  secure_delete my_sensitive_file.txt" << std::endl;
    std::cout << "  secure_delete -p 7 -r my_very_sensitive_file.txt" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Error: No file specified." << std::endl;
        showHelp();
        return 1;
    }
    
    // Parse command line arguments
    std::string filepath;
    int passes = 3;
    bool useRandomData = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            showHelp();
            return 0;
        } else if (arg == "-p" || arg == "--passes") {
            if (i + 1 < argc) {
                try {
                    passes = std::stoi(argv[++i]);
                    if (passes <= 0) {
                        std::cerr << "Error: Number of passes must be positive." << std::endl;
                        return 1;
                    }
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid number of passes specified." << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Error: No value specified for -p/--passes option." << std::endl;
                return 1;
            }
        } else if (arg == "-r" || arg == "--random") {
            useRandomData = true;
        } else if (arg[0] != '-') {
            // Assume it's the file path if it doesn't start with '-'
            if (filepath.empty()) {
                filepath = arg;
            } else {
                std::cerr << "Error: Multiple file paths specified. Only one file at a time is supported." << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option " << arg << std::endl;
            showHelp();
            return 1;
        }
    }
    
    if (filepath.empty()) {
        std::cerr << "Error: No file specified." << std::endl;
        showHelp();
        return 1;
    }
    
    // Check if file exists
    if (!fileExists(filepath)) {
        std::cerr << "Error: File '" << filepath << "' does not exist." << std::endl;
        return 1;
    }
    
    // Get user confirmation
    if (!getUserConfirmation(filepath)) {
        std::cout << "Operation cancelled by user." << std::endl;
        return 0;
    }
    
    // Perform secure deletion
    if (secureDelete(filepath, passes, useRandomData)) {
        std::cout << "Secure deletion completed successfully." << std::endl;
        return 0;
    } else {
        std::cerr << "Secure deletion failed." << std::endl;
        return 1;
    }
}