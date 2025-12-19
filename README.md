# Password Cracker – Digital Forensics Lab Demo

This project is a password-cracking lab demonstration for CS436 (Digital Forensics).
The program loads password hashes and a dictionary, applies multiple cracking strategies, and writes cracked results to a text file.

---

## Requirements

### All Platforms

* **CMake ≥ 3.16**
* **C++ compiler with C++17 support**

---

### macOS

* Xcode Command Line Tools:

```bash
xcode-select --install
```

* Install CMake (recommended via Homebrew):

```bash
brew install cmake
```

Verify:

```bash
cmake --version
```

---

### Windows

* **Visual Studio 2022**

  * Install the **Desktop development with C++** workload
* **CMake** (install from [https://cmake.org/download/](https://cmake.org/download/) or via winget)

Verify in PowerShell:

```powershell
cmake --version
```

---

## Build & Run

### macOS / Linux

```bash
git clone https://github.com/lrsdht/CS436-Digital-Forensics-Final-Project-Password-Cracker-.git
cd CS436-Digital-Forensics-Final-Project-Password-Cracker-
cmake -S . -B build
cmake --build build
./build/cracker
```

---

### Windows (PowerShell)

```powershell
git clone https://github.com/lrsdht/CS436-Digital-Forensics-Final-Project-Password-Cracker-.git
cd CS436-Digital-Forensics-Final-Project-Password-Cracker-
cmake -S . -B build
cmake --build build
.\build\Debug\cracker.exe
```

> Note: Depending on your CMake generator, the executable may also be located at
> `.\build\cracker.exe`

---

## Input Files

* `dictionary.txt` — list of dictionary words
* `passwords.txt` — list of password hashes to crack

These files are loaded automatically at runtime.

---

## Output

After execution, cracked passwords are written to:

```
results/cracked.txt
```

Open this file to view the results.

---

## Notes

* This project uses **CMake** for cross-platform builds.
* No platform-specific APIs are used.
* All file paths are handled relative to the project root for portability.
