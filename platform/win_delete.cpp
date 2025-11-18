#ifdef _WIN32

#include "secure_delete.hpp"
#include "utils.hpp"
#include <windows.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <vector>
#include <algorithm>

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
        MoveFileExA(path.c_str(), tmp.c_str(), MOVEFILE_REPLACE_EXISTING);
    }

    HANDLE h = CreateFileA(
        tmp.c_str(),
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
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

        LARGE_INTEGER ptr;
        ptr.QuadPart = 0;
        SetFilePointerEx(h, ptr, NULL, FILE_BEGIN);

        uint64_t written = 0;
        while (written < size)
        {
            DWORD to_write = (DWORD)std::min<uint64_t>(CHUNK_SIZE, size - written);

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

            DWORD out = 0;
            if (!WriteFile(h, buffer.data(), to_write, &out, NULL) || out == 0)
            {
                CloseHandle(h);
                err_msg = "WriteFile failed";
                return false;
            }

            written += out;

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

        FlushFileBuffers(h);
        log_write(opts.log_file, "Pass " + std::to_string(pass + 1) + " complete");
    }

    FILE_BASIC_INFO info = {0};
    SetFileInformationByHandle(h, FileBasicInfo, &info, sizeof(info));

    FILE_DISPOSITION_INFO fdi = {TRUE};
    SetFileInformationByHandle(h, FileDispositionInfo, &fdi, sizeof(fdi));

    CloseHandle(h);

    if (!DeleteFileA(tmp.c_str()))
    {
        err_msg = "Overwritten but failed to delete entry";
        return false;
    }

    log_write(opts.log_file, "File deleted: " + path);
    return true;
}

#endif