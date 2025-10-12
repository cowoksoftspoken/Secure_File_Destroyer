# 🔒 Secure Delete Portfolio

> **Safe-by-default, SSD-aware secure file deletion tool — built for real-world data security practice.**

This project is an **educational secure file destroyer tool** made to demonstrate real secure deletion principles without being destructive to your system.  
It’s designed to *overwrite, encrypt, and safely remove* files so they **can’t be recovered by standard recovery software**.

---

## 🚀 Features

✅ **Recursive folder scan** — automatically lists all files and sizes.  
✅ **Multi-pass overwrite (3x)** — random → zeros → random, ensuring the data is unrecoverable.  
✅ **Encrypt-then-delete mode** — XOR fallback or AES-256 CTR (with OpenSSL).  
✅ **Rename + O_SYNC + fsync flush** — guarantees data is physically written before deletion.  
✅ **Free-space wipe** — fills unused disk blocks with dummy data to erase leftovers.  
✅ **Automatic SSD/HDD detection** — shows warning & secure erase recommendations.  
✅ **Detailed logging** — every operation saved in `secure_delete.log`.  
✅ **Multi-step confirmation** — prevents accidental deletion.  
✅ **Colorful CLI output** — clear progress and status messages.  
✅ **Cross-platform** — works on Windows and Linux.

---

## ⚙️ Build Instructions

### 🧩 Requirements
- CMake 3.16+
- C++17 compiler (MSVC / GCC / Clang)
- (Optional) [vcpkg](https://github.com/microsoft/vcpkg) + OpenSSL if you want AES mode.

### 🏗️ Build (Simple - XOR mode)
```bash
mkdir build
cd build


cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
