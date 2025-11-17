#include "secure_delete.hpp"
#include "utils.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <string.h>
#include <iostream>

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

    uint64_t size = file_size_bytes(path);
    if (size == (uint64_t)-1)
    {
        err_msg = "could not stat file";
        return false;
    }

    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0)
    {
        err_msg = strerror(errno);
        return false;
    }

    auto passes = generate_algorithm_passes(opts.algorithm, size);
    int total_pass = (int)passes.size();

    for (int pass = 0; pass < total_pass; pass++)
    {
        auto &buf = passes[pass];
        uint64_t written = 0;
        uint64_t offset = 0;

        while (written < size)
        {
            size_t to_write = std::min<size_t>(buf.size(), size - written);
            ssize_t w = pwrite(fd, buf.data(), to_write, offset);
            if (w <= 0)
            {
                close(fd);
                err_msg = strerror(errno);
                return false;
            }

            written += w;
            offset += w;

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

        if (opts.verbose)
            std::cerr << GREEN << "\npass " << (pass + 1) << "/" << total_pass << " done" << RESET << "\n";

        log_write(opts.log_file, "Pass " + std::to_string(pass + 1) + "/" + std::to_string(total_pass) + " complete");
    }

    close(fd);

    std::string tmp = path;
    if (opts.rename_before_delete)
    {
        tmp = random_filename_in_same_dir(path);
        rename(path.c_str(), tmp.c_str());
    }

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
