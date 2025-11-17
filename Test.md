███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗     ██████╗ ███████╗████████╗███████╗██████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ██║  ███╗█████╗     ██║   █████╗  ██████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██║   ██║██╔══╝     ██║   ██╔══╝  ██╔══██╗
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ╚██████╔╝███████╗   ██║   ███████╗██║  ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

# Secure Delete — Cross-Platform Data Destruction Engine

Secure Delete is a modern C++ data destruction engine
designed for Windows, Linux, macOS, and Android (Termux).
It uses native low-level APIs to ensure that overwrite operations
are actually committed to physical storage.

## Why This Exists

Most "secure delete" tools:

- use weak overwrite methods
- simulate progress bars instead of real progress
- rely on outdated assumptions
- behave differently across OSes
- hide their implementation details

Secure Delete provides:

- real progress based on bytes written
- transparent and auditable algorithms
- deterministic behavior
- directory sync to ensure metadata removal
- fully open and readable C++ source

## Core Features

1. **Forensic-Grade Overwrite Engine**
   Windows:

   - WriteFile
   - FlushFileBuffers
     POSIX:
   - pwrite
   - fsync
     Ensures data is physically persisted.

2. **Supported Algorithms**

   - simple (1 pass)
   - DoD 5220.22-M (3 passes)
   - NSA 7-pass
   - Gutmann 35-pass
   - custom pass count

3. **Real Progress Bar**
   Updates based on:

   - bytes_written
   - bytes_total
   - current_pass / total_pass

4. **Secure Folder Deletion**
   Processes files one-by-one using the same overwrite engine.

5. **Rename-Before-Delete**
   Hides metadata such as:

   - original filename
   - directory entry remnants

6. **Detailed Logging**
   Optional logging of:

   - each pass result
   - timestamps
   - errors
   - file list

7. **Disk-Fill Mode (Optional, High-Risk)**
   Fills free space with random or zeroed dummy files to wipe residual
   free-block leftovers.
   Effective but can heavily stress the drive.

8. **Cross-Platform CMake Build System**

# Build Instructions

## Linux / macOS / Android (Termux)

Just run:

    cmake -S . -B build
    cmake --build build

Binary output:

    bin/secure-delete

## Windows

Requirements:

- MinGW (gcc / g++)
- make
- cmake

Recommended installation via **Scoop**:

    scoop install mingw
    scoop install cmake
    scoop install make

Then:

    cmake -S . -B build -G "MinGW Makefiles"
    cmake --build build

# Usage Examples

Delete a file:

    secure-delete file.txt

Random overwrite:

    secure-delete -r photo.png

Use algorithms:

    secure-delete --alg dod   secret.txt
    secure-delete --alg nsa   logs.db
    secure-delete --alg gutmann archive.zip

Custom passes:

    secure-delete -p 5 dump.bin

Delete folder:

    secure-delete --folder ./documents

Enable logging:

    secure-delete --log wipe.log key.pem

Disk-Fill mode:

    secure-delete --disk-fill

Help:

    secure-delete --help

## Effectiveness

| Storage / OS | Reliability | Notes                            |
| ------------ | ----------- | -------------------------------- |
| HDD          | ⭐⭐⭐⭐⭐  | Overwrites fully effective       |
| SSD          | ⭐⭐⭐      | Wear-leveling reduces guarantees |
| Windows NTFS | ⭐⭐⭐⭐    | Metadata wipe + overwrite        |
| Linux/macOS  | ⭐⭐⭐⭐⭐  | Strong POSIX overwrite semantics |

SSD note:
No software can guarantee full sanitization because wear-leveling
redirects writes to new blocks, but Secure Delete wipes as reliably
as modern OS APIs allow.

## Disclaimer

This tool irreversibly destroys data.
Use at your own risk.

## Testing

    ctest --test-dir build
