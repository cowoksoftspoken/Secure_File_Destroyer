# Secure Delete — Cross-Platform Data Destruction Engine

Secure Delete is a cross-platform data-destruction tool written in C++.
It provides deterministic, transparent, and audit-friendly secure deletion
for Windows, Linux, macOS, and Android (Termux).  
The tool uses native low-level APIs on every platform to guarantee that
overwrite operations are actually committed to disk instead of sitting
in memory caches.

## Purpose

Most data wiping utilities rely on outdated assumptions or provide an
illusion of wiping. Secure Delete aims to provide a reliable, modern,
and fully inspectable engine suitable for:

- privacy-driven workflows
- secure developer operations
- incident response
- research and education
- automated CI/CD cleanup
- cross-platform toolkits

## Core Features

1. Native Overwrite Engine  
   Windows:

   - WriteFile
   - FlushFileBuffers  
     POSIX (Linux, macOS, Android):
   - pwrite
   - fsync  
     Ensures written bytes are committed to storage.

2. Algorithms  
   Supported algorithms:

   - simple (1 pass)
   - DoD 5220.22-M (3 passes)
   - NSA 7-pass
   - Gutmann 35-pass
   - custom manual pass count  
     Each algorithm constructs deterministic or random overwrite buffers.

3. Rename-Before-Delete  
   Files can be renamed to a random filename before deletion to obscure
   metadata such as the original file name and associated directory entry.

4. Secure Folder Processing  
   Recursively processes all files inside a directory, running the
   overwrite engine on each file individually.

5. Logging  
   Optional logging that records:

   - algorithm used
   - each pass completion
   - timestamps
   - encountered errors
   - file list

6. Wipe-Slack  
   Wipes the cluster slack or block tail of a file.  
   Slack space is the unused bytes at the end of the last filesystem block.  
   Purpose:

   - removes hidden residues stored after file end
   - prevents forensic retrieval of block remnants  
     Behavior varies by filesystem, since not all expose slack reliably.

7. Android-Purge  
   A cleanup mode for Termux installations.  
   Removes:

   - temporary caches inside the Termux app directory
   - app-generated residue files
   - data directories left behind by deleted apps  
     This does not root the device and does not modify protected system
     partitions. It focuses on user-accessible storage.

8. Disk-Fill Mode  
   Fills free space with one or more large temporary files until the disk
   is nearly full.  
   Purpose:

   - overwrites previously deleted but still-recoverable free blocks
   - reduces remnants that can be extracted using low-level forensic tools  
     Notes:
   - extremely intensive on SSD wear-leveling
   - can heavily degrade device responsiveness while active
   - should not be used frequently  
     This is optional and disabled by default.

9. Platform-Native Metadata Sync  
   After deletion, Secure Delete performs:
   POSIX: fsync on parent directory  
   Windows: uses DeleteFileA plus flush semantics  
   Ensures directory entries and metadata are persisted.

10. Cross-Platform CMake Build System  
    Buildable on all major platforms using the same workflow.

## Effectiveness

HDD:

- Very effective. Overwrites and disk-fill behave predictably.
  SSD:
- Reasonably effective, but subject to wear-leveling.  
   No software can guarantee complete sanitization on an SSD without using
  manufacturer firmware-level secure erase.
  Windows NTFS:
- Reliable overwrite plus directory entry removal.
  Linux/macOS:
- Strong POSIX overwrite semantics provide consistent results.
  Android:
- Depends on filesystem (usually f2fs or ext4).  
  Overwrites are applied, but SSD characteristics still apply.

# Build Instructions

## Linux / macOS / Android (Termux)

    cmake -S . -B build
    cmake --build build

Output:
bin/secure-delete

## Windows

Requirements:

- MinGW (gcc, g++)
- make
- cmake

Recommended installation via Scoop:

    scoop install mingw
    scoop install cmake
    scoop install make

Then:

    cmake -S . -B build -G "MinGW Makefiles"
    cmake --build build

# Usage Examples

Basic delete:
```bash
secure-delete file.txt
```

Random overwrite:
```bash
secure-delete -r file.bin
```

Algorithms:
```bash
secure-delete --alg dod sensitive.txt
secure-delete --alg nsa credentials.db
secure-delete --alg gutmann vm-dump.img
```

Custom passes:
```bash
secure-delete -p 7 dump.raw
```

Folder deletion:
```bash
secure-delete --folder ./secure-data
```

Slack wipe:
```bash
secure-delete --wipe-slack target.bin
```

Android purge:
```bash
secure-delete --android-purge
```

Disk fill:
```bash
secure-delete --disk-fill
```

Logging:
```bash
secure-delete --log report.log file.dat
```

Help:
```bash
secure-delete --help
```

## License
```
MIT LICENSE
```

## Disclaimer

This tool permanently destroys data.  
The user is responsible for understanding its impact.  
No guarantee of complete sanitization can be made on SSDs due to
unpredictable wear-leveling behavior.
