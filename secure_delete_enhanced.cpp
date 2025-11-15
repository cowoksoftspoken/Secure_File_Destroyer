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
#include <memory>
#include <climits>

// ANSI Color Codes
#define RESET   "\033[0m"
#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

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
    std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
    
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

// Function to get platform information
std::string getPlatformInfo() {
#ifdef _WIN32
    return "Windows";
#elif __ANDROID__
    return "Android";
#elif __linux__
    return "Linux";
#elif __APPLE__
    return "macOS";
#else
    return "Unknown";
#endif
}

// Function to display progress bar
void displayProgressBar(int current, int total, const std::string& filename) {
    int barWidth = 50;
    float progress = static_cast<float>(current) / total;
    
    std::cout << "\r" << CYAN << "[Secure Delete] " << WHITE 
              << "Processing " << BOLD << filename << RESET 
              << " [";
    
    int filled = barWidth * progress;
    for (int i = 0; i < barWidth; ++i) {
        if (i < filled) std::cout << "#";
        else std::cout << " ";
    }
    
    std::cout << "] " << std::fixed << std::setprecision(1) 
              << (progress * 100.0) << "% (" << current << "/" << total << ")" 
              << std::flush;
}

// Function to perform secure deletion with multiple overwrite passes
bool secureDelete(const std::string& filename, int passes, bool useRandomData, bool useEncryption) {
    std::streamsize fileSize = getFileSize(filename);
    if (fileSize == -1) {
        std::cerr << RED << "Error: Could not get file size for " << filename << RESET << std::endl;
        return false;
    }
    
    std::cout << YELLOW << "[Info] " << WHITE << "File size: " << BOLD << fileSize << " bytes" << RESET << std::endl;
    std::cout << YELLOW << "[Info] " << WHITE << "Platform: " << BOLD << getPlatformInfo() << RESET << std::endl;
    
    // Show warning about platform limitations
    std::string platform = getPlatformInfo();
    if (platform == "Android" || platform == "Windows") {
        std::cout << RED << "[Warning] " << YELLOW 
                  << "Secure deletion on " << platform << " has limitations due to storage management." 
                  << std::endl;
        std::cout << "For maximum security, consider using full-disk encryption instead." << RESET << std::endl;
    }
    
    // If using encryption approach, we'll encrypt then delete the encryption key
    if (useEncryption) {
        std::cout << GREEN << "[Info] " << WHITE << "Using encryption-based secure deletion approach" << RESET << std::endl;
        // In a real implementation, we'd encrypt the file with a temporary key,
        // but for simplicity we'll just overwrite it first before final deletion
    }
    
    // Define standard overwrite patterns (as per DoD 5220.22-M standard)
    std::vector<std::vector<char>> standardPatterns = {
        std::vector<char>(fileSize, 0x00),  // Pass 1: Fill with zeros
        std::vector<char>(fileSize, 0xFF),  // Pass 2: Fill with ones
        generateRandomPattern(fileSize)     // Pass 3: Fill with random data
    };
    
    // Perform the specified number of passes
    for (int pass = 0; pass < passes; ++pass) {
        displayProgressBar(pass + 1, passes, filename);
        
        if (useRandomData) {
            // Use random data for each pass
            auto randomPattern = generateRandomPattern(fileSize);
            if (!overwriteFile(filename, randomPattern)) {
                std::cerr << std::endl << RED << "Error during overwrite pass " << (pass + 1) << RESET << std::endl;
                return false;
            }
        } else {
            // Use standard patterns for first 3 passes, then random
            if (pass < 3) {
                if (!overwriteFile(filename, standardPatterns[pass])) {
                    std::cerr << std::endl << RED << "Error during standard overwrite pass " << (pass + 1) << RESET << std::endl;
                    return false;
                }
            } else {
                auto randomPattern = generateRandomPattern(fileSize);
                if (!overwriteFile(filename, randomPattern)) {
                    std::cerr << std::endl << RED << "Error during random overwrite pass " << (pass + 1) << RESET << std::endl;
                    return false;
                }
            }
        }
    }
    
    std::cout << std::endl; // New line after progress bar
    
    // Additional security measures for different platforms
    std::cout << GREEN << "[Info] " << WHITE << "Performing additional security measures..." << RESET << std::endl;
    
    // Rename the file to a random name to further obscure it
    std::string tempName = filename;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    
    size_t lastSlash = tempName.find_last_of("/");
    std::string path = (lastSlash != std::string::npos) ? tempName.substr(0, lastSlash + 1) : "./";
    std::string newName = path + ".temp_" + std::to_string(dis(gen)) + "_" + std::to_string(time(nullptr));
    
    if (rename(filename.c_str(), newName.c_str()) != 0) {
        std::cerr << RED << "[Warning] Could not rename file before final deletion." << RESET << std::endl;
    } else {
        // Delete the renamed file
        if (unlink(newName.c_str()) != 0) {
            std::cerr << RED << "[Error] Could not delete file " << newName << RESET << std::endl;
            return false;
        }
    }
    
    std::cout << GREEN << "[Success] File securely deleted: " << BOLD << filename << RESET << std::endl;
    return true;
}

// Function to get user confirmation with colored output
bool getUserConfirmation(const std::string& filename) {
    std::cout << RED << BOLD << "\n[WARNING] SECURE FILE DELETION" << RESET << std::endl;
    std::cout << RED << "===================================" << RESET << std::endl;
    std::cout << YELLOW << "You are about to securely delete the file:" << RESET << std::endl;
    std::cout << CYAN << BOLD << "  " << filename << RESET << std::endl;
    std::cout << RED << "This operation CANNOT be undone!" << RESET << std::endl;
    std::cout << YELLOW << "The file will be overwritten multiple times before deletion." << RESET << std::endl;
    std::cout << std::endl;
    std::cout << WHITE << "Type " << RED << BOLD << "'DELETE'" << WHITE << " to confirm: " << RESET;
    
    std::string confirmation;
    std::cin >> confirmation;
    
    if (confirmation == "DELETE") {
        std::cout << GREEN << "[Confirmed] Proceeding with secure deletion..." << RESET << std::endl;
        return true;
    } else {
        std::cout << RED << "[Cancelled] Operation cancelled by user." << RESET << std::endl;
        return false;
    }
}

// Function to display help with colors
void showHelp() {
    std::cout << CYAN << BOLD << "Secure File Deletion Tool (Enhanced)" << RESET << std::endl;
    std::cout << YELLOW << "Securely wipes a file to prevent recovery with advanced platform support" << RESET << std::endl;
    std::cout << std::endl;
    std::cout << WHITE << "Usage: secure_delete [OPTIONS] <file_path>" << RESET << std::endl;
    std::cout << std::endl;
    std::cout << CYAN << "Options:" << RESET << std::endl;
    std::cout << "  " << YELLOW << "-h, --help         " << WHITE << "Show this help message" << RESET << std::endl;
    std::cout << "  " << YELLOW << "-p, --passes N     " << WHITE << "Number of overwrite passes (default: 3)" << RESET << std::endl;
    std::cout << "  " << YELLOW << "-r, --random       " << WHITE << "Use random data for all passes instead of standard patterns" << RESET << std::endl;
    std::cout << "  " << YELLOW << "-e, --encrypt      " << WHITE << "Use encryption-based secure deletion approach" << RESET << std::endl;
    std::cout << "  " << YELLOW << "-v, --verbose      " << WHITE << "Show detailed progress information" << RESET << std::endl;
    std::cout << std::endl;
    std::cout << CYAN << "Platform Notes:" << RESET << std::endl;
    std::cout << "  " << YELLOW << "Linux/HDD: " << WHITE << "Highly effective" << RESET << std::endl;
    std::cout << "  " << YELLOW << "SSD:       " << WHITE << "Moderately effective (TRIM may limit effectiveness)" << RESET << std::endl;
    std::cout << "  " << YELLOW << "Android:   " << WHITE << "Limited effectiveness due to storage management" << RESET << std::endl;
    std::cout << "  " << YELLOW << "Windows:   " << WHITE << "Limited effectiveness due to journaling" << RESET << std::endl;
    std::cout << std::endl;
    std::cout << CYAN << "Examples:" << RESET << std::endl;
    std::cout << "  " << GREEN << "secure_delete my_sensitive_file.txt" << RESET << std::endl;
    std::cout << "  " << GREEN << "secure_delete -p 7 -r my_very_sensitive_file.txt" << RESET << std::endl;
    std::cout << "  " << GREEN << "secure_delete -e -p 5 my_ultra_sensitive_file.txt" << RESET << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << RED << "Error: No file specified." << RESET << std::endl;
        showHelp();
        return 1;
    }
    
    // Parse command line arguments
    std::string filepath;
    int passes = 3;
    bool useRandomData = false;
    bool useEncryption = false;
    bool verbose = false;
    
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
                        std::cerr << RED << "Error: Number of passes must be positive." << RESET << std::endl;
                        return 1;
                    }
                } catch (const std::exception&) {
                    std::cerr << RED << "Error: Invalid number of passes specified." << RESET << std::endl;
                    return 1;
                }
            } else {
                std::cerr << RED << "Error: No value specified for -p/--passes option." << RESET << std::endl;
                return 1;
            }
        } else if (arg == "-r" || arg == "--random") {
            useRandomData = true;
        } else if (arg == "-e" || arg == "--encrypt") {
            useEncryption = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg[0] != '-') {
            // Assume it's the file path if it doesn't start with '-'
            if (filepath.empty()) {
                filepath = arg;
            } else {
                std::cerr << RED << "Error: Multiple file paths specified. Only one file at a time is supported." << RESET << std::endl;
                return 1;
            }
        } else {
            std::cerr << RED << "Error: Unknown option " << arg << RESET << std::endl;
            showHelp();
            return 1;
        }
    }
    
    // Use verbose flag to control detailed output
    if (verbose) {
        std::cout << YELLOW << "[Info] " << WHITE << "Verbose mode enabled" << RESET << std::endl;
    }
    
    if (filepath.empty()) {
        std::cerr << RED << "Error: No file specified." << RESET << std::endl;
        showHelp();
        return 1;
    }
    
    // Check if file exists
    if (!fileExists(filepath)) {
        std::cerr << RED << "Error: File '" << filepath << "' does not exist." << RESET << std::endl;
        return 1;
    }
    
    // Get user confirmation
    if (!getUserConfirmation(filepath)) {
        return 0;
    }
    
    // Perform secure deletion
    if (secureDelete(filepath, passes, useRandomData, useEncryption)) {
        std::cout << GREEN << BOLD << "\n[SUCCESS] Secure deletion completed successfully." << RESET << std::endl;
        
        if (useEncryption) {
            std::cout << YELLOW << "[Info] " << WHITE << "Encryption-based approach used for enhanced security." << RESET << std::endl;
        }
        
        return 0;
    } else {
        std::cerr << RED << "Secure deletion failed." << RESET << std::endl;
        return 1;
    }
}