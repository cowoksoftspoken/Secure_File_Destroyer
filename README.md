    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗     ██████╗ ███████╗████████╗███████╗██████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ██║  ███╗█████╗     ██║   █████╗  ██████╔╝
    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██║   ██║██╔══╝     ██║   ██╔══╝  ██╔══██╗
    ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ╚██████╔╝███████╗   ██║   ███████╗██║  ██║
    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

# Secure Delete --- Cross‑Platform Data Destruction Engine

Secure Delete is a modern, industrial‑grade file destruction tool built
in C++.\
It provides reliable, forensic‑resistant data wiping on Windows, Linux,
and macOS using platform‑native APIs.

This tool is built for developers, security engineers, researchers, and
power‑users who require **transparent, deterministic, and
audit‑friendly** file destruction.

---

# 🚀 Why Secure Delete Exists

Most file deletion tools either:

- use weak overwrite methods\
- provide fake progress bars\
- rely on outdated assumptions\
- lack Windows/POSIX parity\
- hide behind closed‑source binaries

**Secure Delete fixes that.**

It gives you:

- real‑time progress\
- transparent algorithms\
- readable C++ code\
- platform‑native low‑level file access\
- clear logs\
- predictable behavior\
- safe folder‑level deletion

This makes it suitable for:

- incident response / malware cleanup\
- secure developer workflows\
- automated pipelines\
- research environments\
- privacy‑focused distributions\
- pentesting toolkits

---

# ✨ Features (Fully Implemented)

### 🔥 1. Real Forensic‑Grade Overwrite Engine

Every byte is overwritten using `WriteFile` (Windows) or `pwrite`
(POSIX).\
After each pass, the tool forces OS‑level persistence using:

- `FlushFileBuffers` (Windows)
- `fsync` (Linux/macOS)

This guarantees data is physically committed to disk instead of sitting
in cache.

### 🔥 2. Government‑Grade Algorithms

You can choose:

- **Simple** (fast)
- **DoD 5220.22‑M** (3‑pass)
- **NSA 7‑pass**
- **Gutmann 35‑pass**

Each algorithm produces deterministic patterns or cryptographically
strong random data.

### 🔥 3. Real Progress Bar

Not fake.\
Not a spinner.\
The progress bar updates based on real:

- bytes written\
- total bytes\
- current pass\
- total passes

Example:

    [\\\\\\\\\\\\\\\\\\--------------] 54%  (pass 2/3)

### 🔥 4. Secure Folder Deletion

Recursive deletion that processes files one by one, each with its own
wipe workflow.

Perfect for:

- wiping logs\
- wiping build directories\
- wiping entire user folders

### 🔥 5. Renaming Before Deletion

Before deletion, files are renamed to random tokens.\
This prevents recovering metadata such as:

- original filename\
- partial directory structure references\
- cached file entry names

### 🔥 6. Detailed Log File

When enabled, the tool writes:

- timestamps\
- failed passes\
- success notes\
- algorithm used\
- file list

Great for automated systems.

### 🔥 7. CMake Build System

Cross‑platform CMake build for Windows, Linux, macOS.

### 🔥 8. Cross‑Platform Architecture

Completely separate backends:

- `platform/win_delete.cpp`
- `platform/posix_delete.cpp`

Each uses native system calls for maximum reliability.

---

# 📦 Installation

### Clone

    git clone -b enhanced-version https://github.com/cowoksoftspoken/Secure_File_Destroyer.git
    cd Secure_File_Destroyer

### Build

    cmake -S . -B build
    cmake --build build

Binary will be generated in:

    bin/secure-delete

---

# 🧨 Usage Examples

### Delete a File

    secure-delete myfile.txt

### Random Overwrite

    secure-delete -r image.png

### Use Algorithms

    secure-delete --alg dod   secret.txt
    secure-delete --alg nsa   logs.db
    secure-delete --alg gutmann archive.zip

### Custom Passes

    secure-delete -p 5 binary.dump

### Delete a Folder (Recursive)

    secure-delete --folder ./sensitive_docs

### Logging

    secure-delete --log wipe.log keyfile.pem

### Verbose Mode

    secure-delete -v confidential.bin

### Help

    secure-delete --help

---

# ⚙️ How It Works (Deep Explanation)

### 1. **File Opening**

Uses:

- `CreateFileA()` on Windows\
- `open()` on POSIX

Files are opened with both read/write privileges and direct overwrite
flags.

### 2. **Algorithm Pass Generation**

The engine builds a vector of overwrite buffers based on:

- algorithm selected\
- file size\
- security level

### 3. **Overwrite Loop**

For each pass:

- file pointer resets\
- buffer is written chunk‑by‑chunk\
- progress bar updates\
- bytes are flushed to disk

This ensures:

- write‑through\
- non‑cached\
- immediate persistence

### 4. **Renaming**

The file is renamed using a random filename generator in the same
directory.

### 5. **Deletion**

After rename:

- `DeleteFileA()` on Windows\
- `unlink()` on POSIX

This removes filesystem references.

### 6. **Directory Sync**

POSIX requires explicit directory sync to ensure metadata deletion is
committed.

### 7. **Cleanup & Logging**

Logs are finalized and a success output is shown.

---

# 🧠 Effectiveness

Platform Effectiveness Notes

---

HDD ⭐⭐⭐⭐⭐ Nearly unrecoverable with modern forensic tools
SSD ⭐⭐⭐ Wear‑leveling limits overwrite reliability
Windows ⭐⭐⭐⭐ NTFS MFT entry destruction + overwrite
Linux/macOS ⭐⭐⭐⭐⭐ pwrite/fsync ensure real overwrite

No software can fully defeat SSD wear‑leveling, but this tool performs
as strongly as modern data‑wipe utilities.

---

# ⚠️ Disclaimer

This tool **permanently destroys data**.\
There is no recovery.\
Use with caution.

---

# 🧪 Testing

    ctest --test-dir build

---

# 💬 Support / Contributions

Pull requests and feature requests are welcome.\
Future expansions may include:

- ADS wiping (Windows)
- MFT slack wiping
- File timestamp scrubbing
- SSD Secure Erase integration
- Parallel destruction mode
- Config file support
