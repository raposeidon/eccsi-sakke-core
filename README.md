# eccsi-sakke-core Cross-Platform Build Guide

eccsi-sakke-core is a project that can be easily built in Windows environments using CMake Presets.

---

## 1. Project Overview

eccsi-sakke-core is a C++ project implementing the 6507 and 6508 standards, designed for easy build and execution across multiple platforms via CMake presets.  
The project utilizes OpenSSL for security features and includes a demo program for testing with RFC vectors.

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

```sh
cmake --preset <preset-name>
```

---

## 6. OpenSSL Integration

This project requires the OpenSSL library to enable cryptographic and security features.  
**Before building**, make sure that OpenSSL is either installed on your system (and discoverable by CMake), or that prebuilt OpenSSL binaries are placed in the `external/openssl` directory within the project.  
You can download the official OpenSSL source or binaries from the [OpenSSL website](https://www.openssl.org/).

---

## 7. Example Usage

After building the project, you can run the demo program to verify the implementation and compare the output with the RFC documents.  
Use the following command to run the demo (the executable name may vary depending on your platform):

```sh
./test_demo
```

[DEBUG][SAKKE] (sakke.cpp:783) extractsakke mask :  9BD4EA1E801D37E62AD2FAB0D4F5BBF7
[DEBUG][SAKKE] (sakke.cpp:800) extractsakke SSV result: 123456789abcdef0123456789abcdef0

---

## 8. License

This project is licensed under the **Apache License, Version 2.0**.  
You may obtain a copy of the License at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the License for the specific language governing permissions and limitations under the License.
