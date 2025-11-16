#include "utils.hpp"
#include <fstream>
#include <random>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>

uint64_t file_size_bytes(const std::string &path)
{
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec)
        return (uint64_t)-1;
    return size;
}

bool file_exists(const std::string &path)
{
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

std::vector<uint8_t> random_buffer(size_t size)
{
    static thread_local std::mt19937_64 rng(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    std::vector<uint8_t> buf(size);
    for (size_t i = 0; i < size; i++)
        buf[i] = dist(rng);
    return buf;
}

std::vector<uint8_t> pattern_buffer(size_t size, uint8_t value)
{
    return std::vector<uint8_t>(size, value);
}

std::string random_filename_in_same_dir(const std::string &original)
{
    auto p = std::filesystem::path(original);
    auto dir = p.parent_path();
    static thread_local std::mt19937_64 rng(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint64_t> dist;

    uint64_t r = dist(rng);
    auto newname = dir / ("__del_" + std::to_string(r));
    return newname.string();
}

std::vector<std::string> list_all_files(const std::string &folder)
{
    std::vector<std::string> out;
    std::error_code ec;
    for (auto &entry : std::filesystem::recursive_directory_iterator(folder, ec))
    {
        if (!ec && entry.is_regular_file())
        {
            out.push_back(entry.path().string());
        }
    }
    return out;
}

void log_write(const std::string &file, const std::string &text)
{
    if (file.empty())
        return;
    std::ofstream f(file, std::ios::app);
    if (!f)
        return;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    f << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
      << text << "\n";
}

void draw_real_progress(uint64_t written,
                        uint64_t total,
                        int pass,
                        int total_pass)
{
    if (total == 0)
        total = 1;

    double progress = (double)written / (double)total;
    int width = 40;
    int fill = (int)(progress * width);

    std::string bar = "[";
    bar += std::string(fill, '\\');
    bar += std::string(width - fill, ' ');
    bar += "]";

    int percent = (int)(progress * 100);

    if (percent < 50)
        std::cout << CYAN;
    else if (percent < 90)
        std::cout << YELLOW;
    else
        std::cout << GREEN;

    std::cout << "\r"
              << bar << " "
              << percent << "%  "
              << "pass " << pass << "/" << total_pass
              << RESET
              << std::flush;
}
