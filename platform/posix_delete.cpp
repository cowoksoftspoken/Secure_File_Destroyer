#include "secure_delete.hpp"
#include "utils.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <filesystem>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <vector>

static bool full_fsync(int fd)
{
    return fsync(fd) == 0;
}

bool secure_delete_file(const std::string &path,
                        const DeleteOptions &opts,
                        std::string &err_msg,
                        ProgressCallback progress)
{
    if (!file_exists(path))
    {
        err_msg = "file not found";
        return false;
    }

    std::string tmp = path;
    if (opts.rename_before_delete)
    {
        tmp = random_filename_in_same_dir(path);
        if (rename(path.c_str(), tmp.c_str()) != 0)
            tmp = path;
    }

    uint64_t size = file_size_bytes(tmp);
    if (size == (uint64_t)-1)
    {
        err_msg = "could not stat file";
        return false;
    }

    int fd = open(tmp.c_str(), O_RDWR);
    if (fd < 0)
    {
        err_msg = strerror(errno);
        return false;
    }

    const size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    auto pass_patterns = generate_algorithm_passes(opts.algorithm);
    int total_pass = (int)pass_patterns.size();

    if (opts.algorithm == OverwriteAlgorithm::SIMPLE && opts.mode == OverwriteMode::Random && opts.passes > 3)
    {
        total_pass = opts.passes;
        pass_patterns.assign(total_pass, std::vector<uint8_t>{});
    }
    else if (opts.passes != 3 && opts.algorithm == OverwriteAlgorithm::SIMPLE)
    {
        total_pass = opts.passes;
        while (pass_patterns.size() < (size_t)total_pass)
            pass_patterns.push_back({});
    }

    for (int pass = 0; pass < total_pass; pass++)
    {
        std::vector<uint8_t> pattern_vec;
        if (pass < (int)pass_patterns.size())
            pattern_vec = pass_patterns[pass];

        bool is_random = pattern_vec.empty();
        uint8_t pattern_byte = is_random ? 0 : pattern_vec[0];

        uint64_t written = 0;
        lseek(fd, 0, SEEK_SET);

        while (written < size)
        {
            size_t to_write = std::min<size_t>(CHUNK_SIZE, size - written);

            if (is_random)
            {
                if (buffer.size() != to_write)
                    buffer.resize(to_write);
                fill_random_buffer(buffer);
            }
            else
            {
                if (buffer.size() != to_write)
                    buffer.resize(to_write);
                std::fill(buffer.begin(), buffer.end(), pattern_byte);
            }

            ssize_t w = write(fd, buffer.data(), to_write);
            if (w <= 0)
            {
                close(fd);
                err_msg = strerror(errno);
                return false;
            }

            written += w;

            if (progress)
            {
                FileDeleteStatus st;
                st.bytes_total = size;
                st.bytes_written = written;
                st.current_pass = pass + 1;
                st.total_pass = total_pass;
                progress(st);
            }
            else
            {
                draw_real_progress(written, size, pass + 1, total_pass);
            }
        }

        if (!full_fsync(fd))
        {
            close(fd);
            err_msg = "fsync failed";
            return false;
        }

        log_write(opts.log_file, "Pass " + std::to_string(pass + 1) + " complete");
    }

    struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    futimens(fd, ts);

    off_t final_len = 0;
    ftruncate(fd, final_len);
    close(fd);

    if (unlink(tmp.c_str()) != 0)
    {
        err_msg = strerror(errno);
        return false;
    }

    auto parent = std::filesystem::path(tmp).parent_path().string();
    int dfd = open(parent.c_str(), O_DIRECTORY | O_RDONLY);
    if (dfd >= 0)
    {
        fsync(dfd);
        close(dfd);
    }

    log_write(opts.log_file, "File deleted: " + path);
    return true;
}