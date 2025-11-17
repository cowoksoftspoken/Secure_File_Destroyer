#ifndef SECURE_DELETE_HPP
#define SECURE_DELETE_HPP

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

enum class OverwriteAlgorithm
{
    SIMPLE,
    DOD,
    NSA,
    GUTMANN
};

enum class OverwriteMode
{
    Pattern,
    Random
};

struct DeleteOptions
{
    int passes = 3;
    bool verbose = false;
    bool rename_before_delete = true;
    OverwriteMode mode = OverwriteMode::Pattern;
    OverwriteAlgorithm algorithm = OverwriteAlgorithm::SIMPLE;
    std::string log_file = "";
    bool disk_fill = false;
    bool wipe_slack = false;
    bool android_purge = false;
};

struct FileDeleteStatus
{
    uint64_t bytes_total = 0;
    uint64_t bytes_written = 0;
    int current_pass = 1;
    int total_pass = 1;
};

using ProgressCallback = std::function<void(const FileDeleteStatus &)>;

bool secure_delete_file(const std::string &path,
                        const DeleteOptions &opts,
                        std::string &err_msg,
                        ProgressCallback progress = nullptr);

bool secure_delete_folder(const std::string &folder_path,
                          const DeleteOptions &opts,
                          std::string &err_msg,
                          ProgressCallback progress = nullptr);

std::vector<std::vector<uint8_t>> generate_algorithm_passes(
    OverwriteAlgorithm alg,
    uint64_t file_size);

void log_write(const std::string &file, const std::string &text);

#endif
