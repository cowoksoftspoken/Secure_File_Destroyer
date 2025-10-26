/*
 * ============================================================
 * Project     : Secure Delete
 * File        : main.cpp
 * Author      : Inggrit Setya Budi — (Software Engineering Student)
 * Description : Secure removal tool
 * Notes       : This tool operates at user-file level only and will
 *               refuse system/root paths. It intentionally avoids
 *               raw-device destructive features (no OS wipe).
 * ============================================================
 */

#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <random>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <system_error>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#include "picosha2.hpp"

namespace fs = std::filesystem;

bool is_root_or_system_path(const fs::path &p)
{
    std::string s = p.string();
#if defined(_WIN32)
    if (s.size() >= 2 && s[1] == ':')
    {
        std::string tail = s.substr(2);
        bool only_slash = true;
        for (char c : tail)
            if (c != '\\' && c != '/')
            {
                only_slash = false;
                break;
            }
        if (only_slash)
            return true;
    }
    std::string low = s;
    std::transform(low.begin(), low.end(), low.begin(), ::tolower);
    const std::vector<std::string> win_forbid = {
        "c:\\windows", "c:\\program files", "c:\\program files (x86)"};
    for (auto &f : win_forbid)
        if (low == f || low.find(f + "\\") == 0)
            return true;
    return false;
#else
    if (s == "/" || s == "/root" || s == "/boot" || s == "/etc")
        return true;
    const std::vector<std::string> forbid = {"/bin", "/sbin", "/usr", "/lib", "/lib64", "/system", "/data"};
    for (auto &f : forbid)
        if (s == f || s.find(f + "/") == 0)
            return true;
    return false;
#endif
}

int detect_rotational(const fs::path &p)
{
#if defined(_WIN32)
    (void)p;
    return -1;
#else
    try
    {
        auto abs = fs::absolute(p);
        struct stat st;
        std::string cur = abs.string();
        while (cur.size() > 1)
        {
            if (stat(cur.c_str(), &st) == 0 && S_ISBLK(st.st_mode))
                break;

            fs::path parent = fs::path(cur).parent_path();
            if (parent == fs::path(cur))
                break;
            cur = parent.string();
        }
        std::ifstream mounts("/proc/mounts");
        if (!mounts)
            return -1;
        std::string line;
        std::string dev;
        std::string mnt;
        std::string target = abs.string();
        size_t bestlen = 0;
        while (std::getline(mounts, line))
        {
            std::istringstream iss(line);
            if (!(iss >> dev >> mnt))
                continue;
            if (target.find(mnt) == 0 && mnt.size() > bestlen)
            {
                bestlen = mnt.size();
                dev = dev;
                mnt = mnt;
            }
        }
        if (bestlen == 0)
            return -1;

        std::string devnode = dev;
        if (devnode.rfind("/dev/") == 0)
            devnode = devnode.substr(5);

        while (!devnode.empty() && isdigit(devnode.back()))
            devnode.pop_back();
        if (devnode.empty())
            return -1;
        std::string sysf = "/sys/block/" + devnode + "/queue/rotational";
        std::ifstream f(sysf);
        if (!f)
            return -1;
        std::string val;
        std::getline(f, val);
        if (val.size() && val[0] == '0')
            return 0;
        return 1;
    }
    catch (...)
    {
        return -1;
    }
#endif
}

void log_line(const std::string &line)
{
    std::ofstream ofs("secure_delete.log", std::ios::app);
    if (ofs)
    {
        auto t = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(t);
#if defined(_WIN32)
        std::tm tm_buf;
        localtime_s(&tm_buf, &tt);
        ofs << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " - " << line << "\n";
#else
        ofs << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S") << " - " << line << "\n";
#endif
    }
}

std::string file_sha256(const fs::path &p)
{
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs)
        return {};

    std::vector<unsigned char> buffer(1024 * 1024);
    picosha2::hash256_one_by_one hasher;

    while (ifs.good())
    {
        ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        std::streamsize read_bytes = ifs.gcount();
        if (read_bytes > 0)
            hasher.process(buffer.data(), buffer.data() + read_bytes);
    }

    hasher.finish();

    std::string hex_hash;
    picosha2::get_hash_hex_string(hasher, hex_hash);
    return hex_hash;
}

#ifdef USE_OPENSSL
bool aes_ctr_encrypt_inplace(const fs::path &p, unsigned char *key, unsigned char *iv)
{
    const size_t chunk = 1024 * 1024;
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return false;
    std::vector<unsigned char> inbuf(chunk);
    std::vector<unsigned char> outbuf(chunk + 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    fs::path tmp = p;
    tmp += ".enc_tmp";
    std::ofstream out(tmp, std::ios::binary);
    if (!out)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    while (in)
    {
        in.read(reinterpret_cast<char *>(inbuf.data()), (std::streamsize)chunk);
        std::streamsize r = in.gcount();
        if (r <= 0)
            break;
        int outlen = 0;
        if (1 != EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)r))
        {
            EVP_CIPHER_CTX_free(ctx);
            out.close();
            fs::remove(tmp);
            return false;
        }
        out.write(reinterpret_cast<char *>(outbuf.data()), outlen);
    }
    int tmplen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf.data(), &tmplen))
    {
        EVP_CIPHER_CTX_free(ctx);
        out.close();
        fs::remove(tmp);
        return false;
    }
    if (tmplen > 0)
        out.write(reinterpret_cast<char *>(outbuf.data()), tmplen);
    out.flush();
#if defined(_WIN32)
#else
    int fd = fileno((FILE *)out.rdbuf());
    if (fd >= 0)
        fsync(fd);
#endif
    out.close();
    EVP_CIPHER_CTX_free(ctx);

    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec)
    {
        fs::remove(tmp);
        return false;
    }
    return true;
}
#endif

bool xor_encrypt_inplace(const fs::path &p)
{
    try
    {
        std::fstream fsf(p, std::ios::in | std::ios::out | std::ios::binary);
        if (!fsf.is_open())
            return false;
        uintmax_t sz = fs::file_size(p);
        const size_t chunk = 1024 * 1024;
        std::vector<char> buf(static_cast<size_t>(std::min<uintmax_t>(chunk, sz)));
        std::random_device rd;
        std::mt19937_64 rng(rd());
        uintmax_t processed = 0;
        while (processed < sz)
        {
            size_t toread = (size_t)std::min<uintmax_t>(buf.size(), sz - processed);
            fsf.read(buf.data(), (std::streamsize)toread);
            std::streamsize r = fsf.gcount();
            if (r <= 0)
                break;
            for (size_t i = 0; i < r; i += 8)
            {
                uint64_t v = rng();
                size_t copy = std::min<size_t>(8, (size_t)r - i);
                for (size_t j = 0; j < copy; ++j)
                    buf[i + j] ^= reinterpret_cast<char *>(&v)[j];
            }
            fsf.seekp((std::streamoff)processed);
            fsf.write(buf.data(), (std::streamsize)r);
            fsf.flush();
#if !defined(_WIN32)
            int fd = fileno((FILE *)fsf.rdbuf());
            if (fd >= 0)
                fsync(fd);
#endif
            processed += (uintmax_t)r;
        }
        fsf.close();
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool fsync_parent_dir(const fs::path &p)
{
    std::error_code ec;
    fs::path parent = p.parent_path();
#if defined(_WIN32)
    std::wstring dirw = parent.wstring();
    HANDLE h = CreateFileW(dirw.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    bool ok = (FlushFileBuffers(h) != 0);
    CloseHandle(h);
    return ok;
#else
    int dfd = open(parent.c_str(), O_DIRECTORY | O_RDONLY);
    if (dfd < 0)
        return false;
    int r = fsync(dfd);
    close(dfd);
    return r == 0;
#endif
}

bool overwrite_with_passes_posix(const fs::path &p, int passes)
{
#if !defined(_WIN32)
    int fd = open(p.c_str(), O_WRONLY | O_SYNC);
    if (fd < 0)
        return false;
    uintmax_t sz = fs::file_size(p);
    const size_t chunk = 1024 * 1024;
    std::vector<char> buf(static_cast<size_t>(std::min<uintmax_t>(chunk, sz)));
    std::random_device rd;
    std::mt19937_64 rng(rd());
    for (int pass = 0; pass < passes; ++pass)
    {
        if (pass % 2 == 0)
        {
            for (size_t i = 0; i < buf.size(); i += 8)
            {
                uint64_t v = rng();
                size_t copy = std::min<size_t>(8, buf.size() - i);
                memcpy(buf.data() + i, &v, copy);
            }
        }
        else
        {
            memset(buf.data(), 0, buf.size());
        }
        off_t offset = 0;
        while ((uintmax_t)offset < sz)
        {
            size_t towrite = (size_t)std::min<uintmax_t>(buf.size(), sz - offset);
            ssize_t w = pwrite(fd, buf.data(), towrite, offset);
            if (w <= 0)
            {
                close(fd);
                return false;
            }
            offset += w;
        }
        if (fsync(fd) != 0)
        {
            close(fd);
            return false;
        }
    }
    if (ftruncate(fd, 0) != 0)
    {
        close(fd);
        return false;
    }
    fsync(fd);
    close(fd);
    return true;
#else
    std::fstream fsf(p, std::ios::in | std::ios::out | std::ios::binary);
    if (!fsf.is_open())
        return false;
    uintmax_t sz = fs::file_size(p);
    const size_t chunk = 1024 * 1024;
    std::vector<char> buf(static_cast<size_t>(std::min<uintmax_t>(chunk, sz)));
    std::random_device rd;
    std::mt19937_64 rng(rd());
    for (int pass = 0; pass < passes; ++pass)
    {
        if (pass % 2 == 0)
        {
            for (size_t i = 0; i < buf.size(); i += 8)
            {
                uint64_t v = rng();
                size_t copy = std::min<size_t>(8, buf.size() - i);
                memcpy(buf.data() + i, &v, copy);
            }
        }
        else
        {
            memset(buf.data(), 0, buf.size());
        }
        fsf.seekp(0);
        uintmax_t written = 0;
        while (written < sz)
        {
            size_t towrite = (size_t)std::min<uintmax_t>(buf.size(), sz - written);
            fsf.write(buf.data(), (std::streamsize)towrite);
            if (!fsf)
            {
                fsf.close();
                return false;
            }
            written += towrite;
        }
        fsf.flush();
        HANDLE h = (HANDLE)_get_osfhandle(_fileno((FILE *)fsf.rdbuf()));
        if (h != INVALID_HANDLE_VALUE)
            FlushFileBuffers(h);
    }
    fsf.close();
    std::ofstream trunc(p, std::ios::binary | std::ios::trunc);
    trunc.close();
    return true;
#endif
}

bool wipe_free_space_on_partition(const fs::path &dir, bool dry_run = false)
{
    if (dry_run)
    {
        std::cout << "[dry-run] wipe free space in " << dir << "\n";
        return true;
    }
    try
    {
        fs::path tmp = dir / ("__sd_wipe_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".tmp");
        std::ofstream ofs(tmp, std::ios::binary);
        if (!ofs)
            return false;
        const size_t chunk = 1024 * 1024;
        std::vector<char> buf(chunk, 0);
        while (true)
        {
            ofs.write(buf.data(), (std::streamsize)chunk);
            if (!ofs)
                break;
        }
        ofs.close();
        fs::remove(tmp);
        fsync_parent_dir(tmp);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool secure_erase_file(const fs::path &orig, int passes = 3, bool dry_run = false, bool do_wipe_free_space = false)
{
    try
    {
        if (is_root_or_system_path(orig))
        {
            std::cerr << "Refusing to operate on system/root path: " << orig << "\n";
            return false;
        }
        if (!fs::exists(orig) || !fs::is_regular_file(orig))
        {
            std::cerr << "Not a regular file: " << orig << "\n";
            return false;
        }

        std::string rnd = "sd_tmp_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        fs::path tmp = orig.parent_path() / rnd;
        if (!dry_run)
        {
            std::error_code ec;
            fs::rename(orig, tmp, ec);
            if (ec)
            {
                std::cerr << "Rename failed: " << ec.message() << "\n";
                return false;
            }
            fsync_parent_dir(tmp);
        }
        else
        {
            std::cout << "[dry-run] rename " << orig << " -> " << tmp << "\n";
        }

        if (!dry_run)
        {
            bool got = overwrite_with_passes_posix(tmp, passes);
            if (!got)
            {
                std::cerr << "Overwrite failed\n";
                return false;
            }
        }
        else
        {
            std::cout << "[dry-run] overwrite passes on " << tmp << "\n";
        }

        if (!dry_run)
        {
            fsync_parent_dir(tmp);
        }

        if (!dry_run)
        {
            std::error_code ec;
            fs::remove(tmp, ec);
            if (ec)
            {
                std::cerr << "Remove failed: " << ec.message() << "\n";
                return false;
            }
            fsync_parent_dir(tmp);
        }
        else
        {
            std::cout << "[dry-run] remove " << tmp << "\n";
        }

        if (do_wipe_free_space)
        {
            if (!wipe_free_space_on_partition(orig.parent_path(), dry_run))
            {
                std::cerr << "Warning: wipe free space failed or incomplete.\n";
            }
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool confirm_steps(const fs::path &target, const std::string &sha)
{
    std::cout << "\nCONFIRMATION REQUIRED — multiple steps to avoid accidents.\n";
    std::cout << "Target: " << target << "\n";
    std::cout << "SHA256: " << sha << "\n";
    std::string in;
    std::cout << "Step 1 - type the EXACT absolute path to confirm: ";
    std::getline(std::cin, in);
    if (in != target.string())
    {
        std::cout << "Path mismatch. Aborting.\n";
        return false;
    }
    std::cout << "Step 2 - type the SHA256 shown above: ";
    std::getline(std::cin, in);
    if (in != sha)
    {
        std::cout << "SHA mismatch. Aborting.\n";
        return false;
    }
    std::cout << "Step 3 - type CONFIRM (all caps) to proceed: ";
    std::getline(std::cin, in);
    if (in != "CONFIRM")
    {
        std::cout << "No CONFIRM. Aborting.\n";
        return false;
    }
    std::cout << "Final: Are you SURE? type yes to continue: ";
    std::getline(std::cin, in);
    if (in != "yes")
    {
        std::cout << "Aborting.\n";
        return false;
    }
    return true;
}

bool encrypt_then_delete(const fs::path &p, bool dry_run = false)
{
    if (dry_run)
    {
        std::cout << "[dry-run] encrypt then delete " << p << "\n";
        return true;
    }

#ifdef USE_OPENSSL
    unsigned char key[32], iv[16];
    if (1 != RAND_bytes(key, sizeof(key)))
        return false;
    if (1 != RAND_bytes(iv, sizeof(iv)))
        return false;
    bool ok = aes_ctr_encrypt_inplace(p, key, iv);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    if (!ok)
        return false;

    std::error_code ec;
    fs::path tmp = p;
    if (!fs::remove(p, ec))
    {
        std::cerr << "Failed to remove after encrypt: " << ec.message() << "\n";
        return false;
    }
    return true;
#else
    bool ok = xor_encrypt_inplace(p);
    if (!ok)
        return false;
    std::error_code ec;
    if (!fs::remove(p, ec))
    {
        std::cerr << "Remove failed: " << ec.message() << "\n";
        return false;
    }
    return true;
#endif
}

void scan_folder(const fs::path &root, std::vector<fs::path> &out, const std::vector<std::string> &excludes)
{
    out.clear();
    for (auto &entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied))
    {
        try
        {
            if (!entry.is_regular_file())
                continue;
            fs::path p = entry.path();
            bool skip = false;
            for (auto &ex : excludes)
                if (!ex.empty() && p.string().find(ex) != std::string::npos)
                {
                    skip = true;
                    break;
                }
            if (skip)
                continue;
            out.push_back(p);
        }
        catch (...)
        {
        }
    }
}

int main(int argc, char **argv)
{
    std::cout << "Secure-delete — safe-by-default secure delete tool\n";
    if (argc < 2)
    {
        std::cout << "Usage: secure_delete <folder-to-scan>\n";
        return 1;
    }
    fs::path root = fs::absolute(argv[1]);
    if (!fs::exists(root) || !fs::is_directory(root))
    {
        std::cerr << "Invalid folder.\n";
        return 1;
    }
    if (is_root_or_system_path(root))
    {
        std::cerr << "Refusing to scan system/root paths.\n";
        return 1;
    }

    std::vector<std::string> excludes;
    std::cout << "Optional: enter comma-separated substrings to EXCLUDE (or empty): ";
    std::string exline;
    std::getline(std::cin, exline);
    if (!exline.empty())
    {
        std::istringstream iss(exline);
        std::string tok;
        while (std::getline(iss, tok, ','))
        {
            tok.erase(std::remove_if(tok.begin(), tok.end(), ::isspace), tok.end());
            if (!tok.empty())
                excludes.push_back(tok);
        }
    }

    std::vector<fs::path> files;
    std::cout << "Scanning folder (this may take a while)...\n";
    scan_folder(root, files, excludes);
    if (files.empty())
    {
        std::cout << "No regular files found (after excludes).\n";
        return 0;
    }
    for (size_t i = 0; i < files.size(); ++i)
    {
        std::cout << "[" << i << "] " << files[i] << " (" << fs::file_size(files[i]) << " bytes)\n";
    }

    std::cout << "\nSelect files: 'all' or indices like '0,3,5-8': ";
    std::string sel;
    std::getline(std::cin, sel);
    std::vector<size_t> selected;
    auto push_index = [&](size_t idx)
    { if (idx < files.size()) selected.push_back(idx); };
    if (sel == "all")
    {
        for (size_t i = 0; i < files.size(); ++i)
            push_index(i);
    }
    else
    {
        std::istringstream iss(sel);
        std::string part;
        while (std::getline(iss, part, ','))
        {
            auto dash = part.find('-');
            if (dash == std::string::npos)
            {
                try
                {
                    push_index(std::stoul(part));
                }
                catch (...)
                {
                }
            }
            else
            {
                try
                {
                    size_t a = std::stoul(part.substr(0, dash));
                    size_t b = std::stoul(part.substr(dash + 1));
                    for (size_t k = a; k <= b && k < files.size(); ++k)
                        push_index(k);
                }
                catch (...)
                {
                }
            }
        }
    }
    if (selected.empty())
    {
        std::cout << "No selection. Exiting.\n";
        return 0;
    }
    std::sort(selected.begin(), selected.end());
    selected.erase(std::unique(selected.begin(), selected.end()), selected.end());

    std::cout << "Choose method:\n1) overwrite (recommended for HDD)\n2) encrypt-then-delete (recommended for SSD/hybrid)\n3) move-to-trash (safer; not secure erase)\n4) force delete (attempt remove)\nMethod (1-4): ";
    std::string m;
    std::getline(std::cin, m);
    int method = 1;
    try
    {
        method = std::stoi(m);
    }
    catch (...)
    {
        method = 1;
    }

    std::cout << "Dry-run? (type yes to only simulate): ";
    std::string dr;
    std::getline(std::cin, dr);
    bool dry_run = (dr == "yes");
    std::cout << "Do wipe free-space on partition after deletion? (yes/no): ";
    std::string wf;
    std::getline(std::cin, wf);
    bool do_wipe = (wf == "yes");
    if (do_wipe)
    {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(h, 14);
        std::cout << "\n[!] Filling all available free space on this drive to securely overwrite residual data...\n";
        std::cout << "[!] This will temporarily make your free space appear completely full.\n";
        SetConsoleTextAttribute(h, 10);
        std::cout << "[✓] Once completed, the temporary wipe file will be deleted and free space will return to normal.\n\n";
        SetConsoleTextAttribute(h, 7);
#else
        std::cout << "\033[33m\n[!] Filling all available free space on this drive to securely overwrite residual data...\n";
        std::cout << "[!] This will temporarily make your free space appear completely full.\033[0m\n";
        std::cout << "\033[32m[✓] Once completed, the temporary wipe file will be deleted and free space will return to normal.\n\n\033[0m";
#endif
    }
    int rot = detect_rotational(root);
    if (rot == 0)
    {
        std::cout << "\nNOTICE: Partition looks like non-rotational (SSD/eMMC). Overwrite may be ineffective.\n";
        std::cout << "Recommended: use method 2 (encrypt-then-delete) or vendor ATA Secure Erase / full-disk encryption + key destruction.\n\n";
    }
    else if (rot == 1)
    {
        std::cout << "\nNOTICE: Partition looks like rotational disk (HDD). Overwrite (method 1) is effective.\n\n";
    }
    else
    {
        std::cout << "\nNOTICE: Unable to detect disk type reliably on this platform. Choose method accordingly.\n\n";
    }

    std::cout << "Computing SHA256 for selected files...\n";
    std::vector<std::string> shas(files.size());
    for (size_t idx : selected)
    {
        shas[idx] = file_sha256(files[idx]);
        std::cout << "[" << idx << "] " << files[idx] << " SHA256: " << shas[idx] << "\n";
    }

    for (size_t idx : selected)
    {
        fs::path target = files[idx];
        std::cout << "\n=== Processing: " << target << " ===\n";
        if (!confirm_steps(target, shas[idx]))
        {
            log_line("Aborted by user: " + target.string());
            continue;
        }
        bool ok = false;
        switch (method)
        {
        case 1:
            log_line("Overwrite start: " + target.string());
            ok = secure_erase_file(target, 3, dry_run, do_wipe);
            break;
        case 2:
            log_line("Encrypt-then-delete start: " + target.string());
            ok = encrypt_then_delete(target, dry_run);
            if (ok && do_wipe)
                wipe_free_space_on_partition(target.parent_path(), dry_run);
            break;
        case 3:
            log_line("Move-to-trash start: " + target.string());
            if (dry_run)
            {
                std::cout << "[dry-run] move-to-trash " << target << "\n";
                ok = true;
            }
            else
            {
                std::error_code ec;
                ok = fs::remove(target, ec);
                if (!ok)
                    log_line("Move-to-trash failed: " + ec.message());
            }
            break;
        case 4:
            log_line("Force delete start: " + target.string());
            if (dry_run)
            {
                std::cout << "[dry-run] remove " << target << "\n";
                ok = true;
            }
            else
            {
                std::error_code ec;
                ok = fs::remove(target, ec);
                if (!ok)
                    log_line("Force delete failed: " + ec.message());
            }
            break;
        default:
            std::cout << "Unknown method.\n";
        }
        std::cout << (ok ? "DONE\n" : "FAILED\n");
        log_line(std::string(ok ? "Success: " : "Failed: ") + target.string());
    }

    std::cout << "\nAll done. Check secure_delete.log for details.\n";
    std::cout << "Reminder: For SSDs, vendor ATA secure-erase or full-disk encryption + key destruction gives highest assurance.\n";
    return 0;
}
