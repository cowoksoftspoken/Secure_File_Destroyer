#include "secure_delete.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>

#ifdef _WIN32
#define OS_NAME "Windows"
#elif __APPLE__
#define OS_NAME "macOS"
#else
#define OS_NAME "Linux"
#endif

void print_help()
{
    std::cout << BOLD << CYAN << "Secure File Destroyer" << RESET << "\n\n";
    std::cout << YELLOW << "Usage:" << RESET << "\n";
    std::cout << "  secure-delete " << CYAN << "[options] <file or folder>" << RESET << "\n\n";
    std::cout << YELLOW << "Options:" << RESET << "\n";
    std::cout << CYAN << "  -p <num>" << RESET << "          Manual pass count (ignored if algorithm selected)\n";
    std::cout << CYAN << "  -r" << RESET << "                Random overwrite mode\n";
    std::cout << CYAN << "  -v" << RESET << "                Verbose mode\n";
    std::cout << CYAN << "  -h, --help" << RESET << "        Show help\n";
    std::cout << CYAN << "  --log <file>" << RESET << "      Write wipe logs to file\n";
    std::cout << CYAN << "  --alg <name>" << RESET << "      Algorithm: simple, dod, nsa, gutmann\n";
    std::cout << CYAN << "  --folder" << RESET << "          Treat target as folder (recursive delete)\n\n";
    std::cout << YELLOW << "System:" << RESET << " running on " << MAGENTA << OS_NAME << RESET << "\n";
    std::cout << RED << "Note:" << RESET << " no secure delete is perfect on any OS.\n";
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_help();
        return 1;
    }

    DeleteOptions opts;
    bool folder_mode = false;
    std::string target;

    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];

        if (a == "-h" || a == "--help")
        {
            print_help();
            return 0;
        }
        else if (a == "-p" && i + 1 < argc)
        {
            opts.passes = std::stoi(argv[++i]);
        }
        else if (a == "-r")
        {
            opts.mode = OverwriteMode::Random;
        }
        else if (a == "-v")
        {
            opts.verbose = true;
        }
        else if (a == "--log" && i + 1 < argc)
        {
            opts.log_file = argv[++i];
        }
        else if (a == "--folder")
        {
            folder_mode = true;
        }
        else if (a == "--alg" && i + 1 < argc)
        {
            std::string v = argv[++i];
            if (v == "simple")
                opts.algorithm = OverwriteAlgorithm::SIMPLE;
            else if (v == "dod")
                opts.algorithm = OverwriteAlgorithm::DOD;
            else if (v == "nsa")
                opts.algorithm = OverwriteAlgorithm::NSA;
            else if (v == "gutmann")
                opts.algorithm = OverwriteAlgorithm::GUTMANN;
        }
        else if (a[0] == '-')
        {
            std::cerr << RED << "Unknown option: " << a << RESET << "\n";
            return 1;
        }
        else
        {
            target = a;
        }
    }

    if (target.empty())
    {
        std::cerr << RED << "No target specified" << RESET << "\n";
        return 1;
    }

    std::cout << CYAN << "[*] Starting secure delete for: " << RESET << BOLD << target << RESET << "\n";
    std::cout << YELLOW << "[!] Running on: " << OS_NAME << RESET << "\n";

    std::string err;

    auto pg = [&](const FileDeleteStatus &st)
    {
        draw_real_progress(st.bytes_written,
                           st.bytes_total,
                           st.current_pass,
                           st.total_pass);
    };

    bool ok = false;

    if (folder_mode)
        ok = secure_delete_folder(target, opts, err, pg);
    else
        ok = secure_delete_file(target, opts, err, pg);

    if (!ok)
    {
        std::cout << "\n"
                  << RED << "[X] Failed: " << err << RESET << "\n";
        return 1;
    }

    draw_real_progress(1, 1, opts.passes, opts.passes);

    std::cout << "\n"
              << GREEN << "[✔] Completed" << RESET << "\n";
    return 0;
}
