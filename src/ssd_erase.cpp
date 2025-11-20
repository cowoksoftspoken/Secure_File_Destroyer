#include "ssd_delete.hpp"
#include "utils.hpp"
#include <iostream>
#ifdef __linux__
#include <filesystem>
#include <unistd.h>
#include <sys/stat.h>
namespace fs = std::filesystem;
#endif

#ifndef __linux__

bool perform_hardware_erase(DeleteOptions &opts)
{
    std::cerr << RED << "[X] Error: Hardware Erase (NVMe/ATA) is LINUX ONLY." << RESET << "\n";
    std::cerr << YELLOW << "    Windows does not support standard kernel ioctl/sysfs for this tool." << RESET << "\n";
    return false;
}

#else

std::vector<std::string> detect_block_devices()
{
    std::vector<std::string> devices;

    for (const auto &entry : fs::directory_iterator("/sys/block"))
    {
        std::string name = entry.path().filename().string();
        if (name.rfind("nvme", 0) == 0 || name.rfind("sd", 0) == 0)
        {
            devices.push_back("/dev/" + name);
        }
    }

    return devices;
}

bool is_real_block(const std::string &path)
{
    struct stat st{};
    if (stat(path.c_str(), &st) != 0)
        return false;
    return S_ISBLK(st.st_mode);
}

bool is_nvme_dev(const std::string &path)
{
    return path.find("/dev/nvme") == 0;
}

bool perform_hardware_erase(DeleteOptions &opts)
{

    if (getuid() != 0)
    {
        std::cerr << RED << "[X] Root privileges required." << RESET << "\n";
        return false;
    }

    auto devs = detect_block_devices();

    if (devs.empty())
    {
        std::cerr << RED << "[X] No NVMe/SATA devices detected." << RESET << "\n";
        return false;
    }

    std::cout << CYAN << "[*] Detected block devices:\n"
              << RESET;

    for (size_t i = 0; i < devs.size(); i++)
    {
        std::cout << "  [" << i << "] " << devs[i] << "\n";
    }

    std::cout << "\nSelect device index: ";
    int index{};
    std::cin >> index;

    if (index < 0 || index >= (int)devs.size())
    {
        std::cerr << RED << "[X] Invalid index." << RESET << "\n";
        return false;
    }

    std::string device = devs[index];

    if (!is_real_block(device))
    {
        std::cerr << RED << "[X] Device not a real block device: "
                  << device << RESET << "\n";
        return false;
    }

    if (opts.auto_ssd)
    {
        if (is_nvme_dev(device))
        {
            opts.algorithm = OverwriteAlgorithm::NVME_SANITIZE;
        }
        else
        {
            opts.algorithm = OverwriteAlgorithm::ATA_SECURE_ERASE;
        }
    }

    std::string cmd;
    std::string method;

    if (opts.algorithm == OverwriteAlgorithm::NVME_SANITIZE)
    {
        method = "NVMe User Data Erase";
        cmd = "nvme format " + device + " --ses=1 --force";
    }
    else if (opts.algorithm == OverwriteAlgorithm::CRYPTOGRAPHIC_ERASE)
    {
        method = "Cryptographic Erase";
        if (is_nvme_dev(device))
        {
            cmd = "nvme format " + device + " --ses=2 --force";
        }
        else
        {
            cmd = "hdparm --user-master u --security-set-pass NULL " + device +
                  " && hdparm --user-master u --security-erase-enhanced NULL " + device;
        }
    }
    else
    {
        method = "ATA Secure Erase";
        cmd = "hdparm --user-master u --security-set-pass NULL " + device +
              " && hdparm --user-master u --security-erase NULL " + device;
    }

    std::cout << "\n"
              << RED << BOLD
              << "[!!!] WARNING: This will permanently wipe the drive.\n"
              << RESET;
    std::cout << YELLOW << "Device: " << device << "\nMethod: "
              << method << RESET << "\n\n";

    std::cout << "Type " << RED << BOLD << "YES" << RESET << " to continue: ";
    std::string confirm;
    std::cin >> confirm;

    if (confirm != "YES")
    {
        std::cout << RED << "[X] Cancelled." << RESET << "\n";
        return false;
    }

    std::cout << GREEN << "[*] Executing firmware erase..." << RESET << "\n";

    int ret = system((cmd + " > /dev/null 2>&1").c_str());

    if (ret == 0)
    {
        std::cout << GREEN << "[✔] Erase command successful." << RESET << "\n";
        return true;
    }

    std::cout << RED << "[X] Erase command failed." << RESET << "\n";
    return false;
}

#endif