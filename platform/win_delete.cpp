#ifdef _WIN32

#include "secure_delete.hpp"
#include "utils.hpp"
#include <windows.h>
#include <string>
#include <filesystem>
#include <iostream>

static bool write_pass_real(HANDLE h,
                            const std::vector<uint8_t> &buf,
                            uint64_t size,
                            int pass,
                            int total_pass,
                            ProgressCallback progress)
{
    LARGE_INTEGER li;
    li.QuadPart = 0;
    SetFilePointerEx(h, li, NULL, FILE_BEGIN);

    uint64_t written = 0;

    while (written < size)
    {
        DWORD chunk = (DWORD)std::min<uint64_t>(buf.size(), size - written);
        DWORD out = 0;

        if (!WriteFile(h, buf.data(), chunk, &out, NULL) || out == 0)
            return false;

        written += out;

        if (progress)
        {
            FileDeleteStatus st;
            st.bytes_total = size;
            st.bytes_written = written;
            st.current_pass = pass;
            st.total_pass = total_pass;
            progress(st);
        }
        else
        {
            draw_real_progress(written, size, pass, total_pass);
        }
    }

    return FlushFileBuffers(h);
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

    HANDLE h = CreateFileA(
        path.c_str(),
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        err_msg = "CreateFile failed";
        return false;
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li))
    {
        CloseHandle(h);
        err_msg = "GetFileSizeEx failed";
        return false;
    }

    uint64_t size = li.QuadPart;

    auto passes = generate_algorithm_passes(opts.algorithm, size);
    int total_pass = (int)passes.size();

    for (int i = 0; i < total_pass; i++)
    {
        auto &buf = passes[i];

        if (!write_pass_real(h, buf, size, i + 1, total_pass, progress))
        {
            CloseHandle(h);
            err_msg = "WriteFile failed";
            return false;
        }

        if (opts.verbose)
            std::cerr << GREEN << "\npass " << (i + 1) << "/" << total_pass << " done" << RESET << "\n";

        log_write(opts.log_file, "Pass " + std::to_string(i + 1) + "/" + std::to_string(total_pass) + " complete");
    }

    CloseHandle(h);

    std::string tmp = path;
    if (opts.rename_before_delete)
    {
        tmp = random_filename_in_same_dir(path);
        MoveFileExA(path.c_str(), tmp.c_str(), MOVEFILE_REPLACE_EXISTING);
    }

    if (!DeleteFileA(tmp.c_str()))
    {
        err_msg = "DeleteFile failed";
        return false;
    }

    log_write(opts.log_file, "File deleted: " + path);
    return true;
}

#endif
