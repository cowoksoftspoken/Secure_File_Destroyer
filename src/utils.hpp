#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <cstdint>

#define RESET "\033[0m"
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"
#define BOLD "\033[1m"
#define UNDERLINE "\033[4m"

uint64_t file_size_bytes(const std::string &path);
bool file_exists(const std::string &path);
std::vector<uint8_t> random_buffer(size_t size);
std::vector<uint8_t> pattern_buffer(size_t size, uint8_t value);
std::string random_filename_in_same_dir(const std::string &original);
std::vector<std::string> list_all_files(const std::string &folder);
void log_write(const std::string &file, const std::string &text);

void draw_real_progress(uint64_t written,
                        uint64_t total,
                        int pass,
                        int total_pass);

#endif
