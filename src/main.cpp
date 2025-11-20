#include "secure_delete.hpp"
#include "utils.hpp"
#include <ssd_delete.hpp>
#include <iostream>
#include <string>
#include <cstring>
#include <csignal>

#ifdef _WIN32
#define OS_NAME "Windows"
#elif __APPLE__
#define OS_NAME "macOS"
#elif defined(__linux__)
#include <unistd.h>
#define OS_NAME "Linux"
#else
#define OS_NAME "Unknown POSIX"
#endif

#define VERSION "1.2.0"

bool is_android()
{
#ifdef __linux__
    return access("/system/build.prop", F_OK) == 0 ||
           access("/system/bin/getprop", F_OK) == 0;
#else
    return false;
#endif
}

std::string g_active_log_file = "";

void handle_sigint(int sig)
{
    std::cout << "\n\n"
              << RED << "[!] Cancelled by user" << RESET << "\n";

    if (!g_active_log_file.empty())
    {
        log_write(g_active_log_file, "Process cancelled by user (SIGINT)");
    }

    exit(1);
}

void print_help()
{
    std::string os = OS_NAME;
    if (is_android())
        os = "Android (Termux)";

    std::cout << BOLD << CYAN << "Secure File Destroyer" << RESET << "\n\n";
    std::cout << YELLOW << "Usage:" << RESET << "\n";
    std::cout << "  secure-delete " << CYAN << "[options] <file or folder>" << RESET << "\n\n";

    std::cout << YELLOW << "Options:" << RESET << "\n";

    std::cout << CYAN << "  -p <num>" << RESET
              << "          Manual pass count (ignored if algorithm selected)\n";

    std::cout << CYAN << "  -r" << RESET
              << "                Random overwrite mode\n";

    std::cout << CYAN << "  -v" << RESET
              << "                Verbose mode\n";

    std::cout << CYAN << "  -h, --help" << RESET
              << "        Show help\n";

    std::cout << CYAN << "  --log <file>" << RESET
              << "      Write wipe logs to file\n";

    std::cout << CYAN << "  --alg <name>" << RESET
              << "      Algorithm: simple, dod, nsa, gutmann\n";

    std::cout << CYAN << "  --folder" << RESET
              << "          Treat target as folder (recursive delete)\n";

    std::cout << CYAN << "  --disk-fill" << RESET
              << "        Overwrite free space (zero-fill + optional random)\n";

    std::cout << CYAN << "  --wipe-slack" << RESET
              << "       Wipe filesystem slack space (Windows: cipher /w)\n";

    std::cout << CYAN << "  --android-purge" << RESET
              << "   Remove Android thumbnails/cache (Termux only)\n\n";

    std::cout << YELLOW << "System:" << RESET
              << " running on " << MAGENTA << os << RESET << "\n";

    std::cout << RED << "Note:" << RESET
              << " no secure delete is perfect on any OS.\n";
    std::cout << "\n"
              << RED << BOLD << "SSD/Hardware Dangerous Options (Linux Root Only):" << RESET << "\n";
    std::cout << "  --alg ata        ATA Secure Erase (hdparm)\n";
    std::cout << "  --alg nvme       NVMe User Data Erase (nvme-cli)\n";
    std::cout << "  --alg crypto     Cryptographic Erase (Fastest)\n";
    std::cout << "  --auto-ssd       Auto-detect & wipe SSD\n";
}

int main(int argc, char **argv)
{

    signal(SIGINT, handle_sigint);

    if (argc < 2)
    {
        print_help();
        return 1;
    }

    DeleteOptions opts;
    bool folder_mode = false;
    bool hardware_mode = false;
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
        else if (a == "--version" || a == "--v")
        {
            std::cout << BOLD << CYAN << "Secure File Destroyer" << RESET
                      << " v" << VERSION << "\n";
            std::cout << "Build date: " << __DATE__ << " " << __TIME__ << "\n";
            return 0;
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
        else if (a == "--disk-fill")
        {
            opts.disk_fill = true;
        }
        else if (a == "--wipe-slack")
        {
            opts.wipe_slack = true;
        }
        else if (a == "--android-purge")
        {
            opts.android_purge = true;
        }
        else if (a == "--auto-ssd")
        {
            opts.auto_ssd = true;
            hardware_mode = true;
        }
        else if (a == "--alg" && i + 1 < argc)
        {
            std::string v = argv[++i];
            if (v == "ata")
            {
                opts.algorithm = OverwriteAlgorithm::ATA_SECURE_ERASE;
                hardware_mode = true;
            }
            else if (v == "nvme")
            {
                opts.algorithm = OverwriteAlgorithm::NVME_SANITIZE;
                hardware_mode = true;
            }
            else if (v == "crypto")
            {
                opts.algorithm = OverwriteAlgorithm::CRYPTOGRAPHIC_ERASE;
                hardware_mode = true;
            }
            else if (v == "simple")
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

    g_active_log_file = opts.log_file;

    if (opts.mode == OverwriteMode::Random && opts.algorithm != OverwriteAlgorithm::SIMPLE)
    {
        std::cerr << "\n"
                  << RED << "[!] Error: Argument Conflict" << RESET << "\n";
        std::cerr << YELLOW << "    You can't use '-r' (Random) together with '--alg' (Algorithm)." << RESET << "\n";
        std::cerr << "    Reason: Algorithms like DoD/NSA/Gutmann already have their own random patterns.\n\n";
        return 1;
    }

    if (hardware_mode)
    {
#ifndef __linux__
        std::cerr << RED << "[X] Hardware erase is Linux only." << RESET << "\n";
        return 1;
#endif
        bool success = perform_hardware_erase(target, opts);
        return success ? 0 : 1;
    }

    if (target.empty())
    {
        std::cerr << RED << "No target specified" << RESET << "\n";
        return 1;
    }

    std::string os = OS_NAME;
    if (is_android())
        os = "Android (Termux)";

    std::cout << CYAN << "[*] Starting secure delete for: " << RESET << BOLD << target << RESET << "\n";
    std::cout << YELLOW << "[!] Running on: " << os << RESET << "\n";

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

    std::cout << "\n";

    if (is_android())
    {
        if (opts.android_purge)
        {
            std::cout << CYAN << "[*] (Android) Purging thumbnails & cache..." << RESET << "\n";
            log_write(opts.log_file, "Android: Purging caches");
            system("rm -rf /storage/emulated/0/DCIM/.thumbnails/* 2>/dev/null");
            system("rm -rf /storage/emulated/0/Android/data//cache/ 2>/dev/null");
            system("rm -rf /storage/emulated/0/Pictures/.trashed* 2>/dev/null");
        }
        if (opts.disk_fill)
        {
            std::cout << RED << BOLD << "[!] Disk-fill Warning" << RESET << "\n";
            std::cout << YELLOW << "[*] This feature will attempt to overwrite your free space" << RESET << "\n";
            std::cout << MAGENTA << BOLD << "Are you sure to continue? (y/N)" << RESET;
            char answer;
            std::cin >> answer;
            if (answer != 'y' && answer != 'Y')
            {
                std::cout << RED << "[*] Disk-fill cancelled!" << RESET;
                opts.disk_fill = false;
                return 0;
            }
            std::cout << CYAN << "[*] (Android) Starting disk-fill (zero)..." << RESET << "\n";
            log_write(opts.log_file, "Android: Starting zero-fill");
            system("dd if=/dev/zero of=/storage/emulated/0/.filler.bin bs=4M");
            system("rm /storage/emulated/0/.filler.bin");

            std::cout << CYAN << "[*] (Android) Starting disk-fill (random)..." << RESET << "\n";
            log_write(opts.log_file, "Android: Starting random-fill");
            system("dd if=/dev/urandom of=/storage/emulated/0/.filler-rand.bin bs=1M count=128");
            system("rm /storage/emulated/0/.filler-rand.bin");
        }
    }
    else if (strcmp(OS_NAME, "Windows") == 0)
    {
        if (opts.wipe_slack)
        {
            std::cout << CYAN << "[*] (Windows) Wiping MFT slack with cipher.exe..." << RESET << "\n";
            log_write(opts.log_file, "Windows: Running cipher /w");
            system("cipher /w:C:\\");
        }
        if (opts.disk_fill)
        {
            std::cout << RED << BOLD << "[!] Disk-fill Warning" << RESET << "\n";
            std::cout << YELLOW << "[*] This feature will attempt to overwrite your free space" << RESET << "\n";
            std::cout << MAGENTA << BOLD << "Are you sure to continue? (y/N)" << RESET;
            char answer;
            std::cin >> answer;
            if (answer != 'y' && answer != 'Y')
            {
                std::cout << RED << "[*] Disk-fill cancelled!" << RESET;
                opts.disk_fill = false;
                return 0;
            }
            std::cout << CYAN << "[*] (Windows) Starting disk-fill (zero)..." << RESET << "\n";
            log_write(opts.log_file, "Windows: Starting fsutil fill");
            system("fsutil file createnew C:\\filler.bin 1000000000");
            system("del C:\\filler.bin");
        }
    }
    else if (strcmp(OS_NAME, "Linux") == 0)
    {
        if (opts.disk_fill)
        {
            std::cout << RED << BOLD << "[!] Disk-fill Warning" << RESET << "\n";
            std::cout << YELLOW << "[*] This feature will attempt to overwrite your free space" << RESET << "\n";
            std::cout << MAGENTA << BOLD << "Are you sure to continue? (y/N)" << RESET;
            char answer;
            std::cin >> answer;
            if (answer != 'y' && answer != 'Y')
            {
                std::cout << RED << "[*] Disk-fill cancelled!" << RESET;
                opts.disk_fill = false;
                return 0;
            }
            std::cout << CYAN << "[*] (Linux) Starting disk-fill (zero)..." << RESET << "\n";
            log_write(opts.log_file, "Linux: Starting zero-fill");
            system("dd if=/dev/zero of=filler.bin bs=1M");
            system("rm filler.bin");

            std::cout << CYAN << "[*] (Linux) Starting disk-fill (random)..." << RESET << "\n";
            log_write(opts.log_file, "Linux: Starting random-fill");
            system("dd if=/dev/urandom of=filler-rand.bin bs=1M count=128");
            system("rm filler-rand.bin");
#ifndef _WIN32
            sync();
#endif
        }
    }

    std::cout << "\n"
              << GREEN << "[✔] Completed" << RESET << "\n";
    return 0;
}
