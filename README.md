# eccsi-sakke-core Cross-Platform Build Guide

eccsi-sakke-core is a cross-platform C++ project designed for easy building on Windows and other environments using CMake Presets.

---

## 1. Overview

eccsi-sakke-core is a C++ project implementing the RFC 6507 and 6508 standards, providing easy cross-platform builds and execution using CMake presets.  
This project uses OpenSSL for cryptographic functions and includes a demo program for testing with RFC vectors.

> **Note:** This project re-implements the sakke/tlpairing logic from the ECCSI-SAKKE repository (https://github.com/jim-b/ECCSI-SAKKE) in C++.  
> The original algorithms and logic structure were referenced and adapted in compliance with the Apache License 2.0.

---

## 2. Requirements

- **CMake 3.19 or later**
- **OpenSSL** (required for cryptographic operations)

---

## 3. Tested Environment

This project has been built and tested in the **Visual Studio 2022** environment.

---

## 4. Build Preset Structure

The `CMakePresets.json` file provides presets for each platform and build type (Debug/Release):

- Windows (MSVC, MinGW)
- Linux (GCC)
- Android (NDK, arm64-v8a)
- iOS (Xcode, arm64)

> ⚠️ **Note:** Only the Windows environment has been directly built and tested.  
> Presets for other environments are provided for reference only.

---

## 5. Build and Run Instructions

The following command works on all supported platforms.  
Please replace `<preset-name>` with the appropriate preset for your environment and purpose.

```cmd
cmake --preset <preset-name>
```

---

## 6. OpenSSL Integration

This project requires the OpenSSL library to enable cryptographic and security features.  
**Before building**, make sure that OpenSSL is either installed on your system (and recognized by CMake), or that prebuilt OpenSSL binaries are placed in the `external/openssl` directory within the project.
You can download the official OpenSSL source or binaries from the [OpenSSL website](https://www.openssl.org/).

---

## 7. Example Usage

After building the project, you can run the demo program to verify the implementation and compare the output with the RFC documents.
Run the demo with the following command (the executable name may differ depending on your platform):

```cmd
test_demo.exe
```

You should see debug logs similar to the following:
extractsakke mask :  9BD4EA1E801D37E62AD2FAB0D4F5BBF7
extractsakke SSV result: 123456789abcdef0123456789abcdef0

---

## 8. License

This project is provided under the **Apache License 2.0**.  
Please refer to the NOTICE, LICENSE, and THIRD_PARTY_NOTICES files for more information.

This project references and adapts implementation logic from the ECCSI-SAKKE repository (https://github.com/jim-b/ECCSI-SAKKE) in compliance with the Apache License 2.0.
