#include "secure_delete.hpp"
#include "utils.hpp"
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>

bool secure_delete_folder(const std::string &folder_path,
                          const DeleteOptions &opts,
                          std::string &err_msg,
                          ProgressCallback progress)
{
    if (!std::filesystem::exists(folder_path))
    {
        err_msg = "folder not found";
        return false;
    }

    std::vector<std::string> all_files = list_all_files(folder_path);
    size_t total = all_files.size();

    if (total == 0)
    {
        err_msg = "folder is empty";
        return false;
    }

    std::cout << CYAN << "[*] Found " << total << " files" << RESET << "\n";

    size_t index = 0;
    for (auto &f : all_files)
    {
        index++;

        std::cout << YELLOW << "→ deleting " << index << "/" << total << ": "
                  << RESET << f << "\n";

        std::string e;
        bool ok = secure_delete_file(f, opts, e, progress);

        if (!ok)
        {
            std::cerr << RED << "[X] error deleting " << f << ": "
                      << e << RESET << "\n";
            log_write(opts.log_file, "Error deleting " + f + ": " + e);
        }
        else
        {
            std::cout << GREEN << "[✔] deleted" << RESET << "\n";
            log_write(opts.log_file, "Deleted file: " + f);
        }
    }

    log_write(opts.log_file, "Folder deletion completed: " + folder_path);
    return true;
}
