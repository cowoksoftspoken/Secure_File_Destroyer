# 🔒 Secure Delete File Destroyer

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
```

## 🧠 Build (Advanced - AES + OpenSSL)
```bash
cmake .. -A x64 -DUSE_OPENSSL=ON -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```
Executable will be placed in:
```bash
build/bin/secure_delete.exe
```
## 💻 Usage

### 🔹 Basic
```bash
secure_delete.exe <folder_path>
```

**Example:**
```bash
secure_delete.exe ./test
```

The tool will:
1. Scan the folder recursively.
2. Ask which files to delete.
3. Request confirmation with full path & SHA256 hash.
4. Ask if you want to wipe free-space on the partition.
5. Securely delete the files.

---

## 🧩 Encryption Modes

| Mode | Description | Requires OpenSSL |
|------|--------------|------------------|
| XOR (default) | Lightweight pseudo-random encryption for demo | ❌ No |
| AES-256 CTR | Strong encrypt-then-delete (industry standard) | ✅ Yes |

Even the XOR mode ensures file contents are unrecoverable by common recovery tools.

---

## 🧹 Free-space Wipe

When enabled, the tool creates a large temporary file (`__sd_wipe_<random>.tmp`) that fills all free space on the drive.  
This overwrites any traces of previously deleted files.

**Don’t panic** if your drive looks full — it’s temporary!  
Once the process completes, the file is deleted automatically and free space returns to normal.

---

## ⚠️ Safety Notes

⚡ The tool **only operates on user-specified paths** — it refuses to touch system folders like:
```
C:\Windows\
/usr/
/etc/
```

💀 **Do not use this on drives or partitions you don’t own.**  
🧠 For SSDs, complete forensic wipe is limited due to wear-leveling — use vendor Secure Erase for 100% clean.

---

## 📜 Logs

All actions and results are logged into:
```
secure_delete.log
```

**Example:**
```
[OK] Overwritten 3x and deleted: Screenshot (14).png (336962 bytes)
[OK] Encrypted-then-deleted: report.pdf (SHA256: abcdef...)
```

---

## 📂 Project Structure

```
.
├── src/
│   └── main.cpp
├── build/
│   └── bin/
│       └── secure_delete.exe
├── CMakeLists.txt
└── README.md
```

---

## 🧠 Technical Notes

- Uses `O_SYNC` / `FlushFileBuffers` for guaranteed writes.  
- Performs `fsync` on parent directories after rename/unlink.  
- Detects SSD/HDD using device IOCTL (Windows) or `/sys/block` (Linux).  
- Optional full free-space wipe after file deletion.  
- Educational — **not for malicious use**.

---

## ✨ Author

**Inggrit Setya Budi**  
Software Engineering Student  
Built with ❤️ for portfolio & addressing file deletion concerns.

---

## 📜 License

MIT License — free to use, modify, and share.  
Just don’t use it to nuke other people’s files 😭

---

> _“Delete responsibly — your data’s gone for good.”_
