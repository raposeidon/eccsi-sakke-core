# eccsi-sakke-core Cross-Platform Build Guide

eccsi-sakke-core는 Windows 환경에서 CMake Presets로 손쉽게 빌드할 수 있는 프로젝트입니다.

---

## 1. 프로젝트 개요

eccsi-sakke-core는 RFC 6507, 6508 표준을 구현하는 C++ 프로젝트로, 다양한 플랫폼에서 손쉽게 빌드하고 실행할 수 있도록 CMake 프리셋을 제공합니다.  
이 프로젝트는 보안 기능을 위해 OpenSSL을 사용하며, RFC 벡터를 테스트하는 데모 프로그램을 포함하고 있습니다.

> **본 프로젝트는 ECCSI-SAKKE(https://github.com/jim-b/ECCSI-SAKKE) 저장소의 sakke/tlpairing 로직을 C++로 포팅하여 구현되었습니다.  
> 원본 구현의 알고리즘 및 로직 구조를 참고 및 변환하였으며, Apache License 2.0의 조건을 준수합니다.**

---

## 2. 요구 사항

- **CMake 3.19 이상**
- **OpenSSL** (암호화 작업을 위해 필수)

---

## 3. 테스트 환경

이 프로젝트는 **Visual Studio 2022** 환경에서 빌드 및 테스트하였습니다.

---

## 4. 빌드 프리셋 구조

`CMakePresets.json`에는 아래와 같이 각 플랫폼과 빌드 타입(디버그/릴리즈)별 프리셋이 정의되어 있습니다.

- Windows (MSVC, MinGW)
- Linux (GCC)
- Android (NDK, arm64-v8a)
- iOS (Xcode, arm64)

> ⚠️ **참고:** Windows 환경에서만 직접 빌드 및 테스트하였으며, 
> Windows 외 환경의 프리셋은 참고용으로만 제공합니다.

---

## 5. 빌드/실행 방법

아래 명령어는 모든 플랫폼에서 동일하게 동작합니다.  
프리셋 이름은 각 환경과 목적에 맞게 변경하여 사용하세요.

```cmd
cmake --preset <preset-name>
```

---

## 6. OpenSSL 사용

본 프로젝트는 OpenSSL 라이브러리를 활용하여 암호화 및 보안 관련 기능을 구현합니다. 빌드 이전에, OpenSSL이 시스템에 사전 설치되어 있거나, 외부 경로인 'external/openssl' 폴더에 미리 빌드된 라이브러리가 위치해야 합니다.
OpenSSL 라이브러리는 [공식 웹사이트](https://www.openssl.org/)에서 다운로드 가능합니다.

---

## 7. 사용 예시

프로젝트를 빌드하고 데모 프로그램을 실행하면 RFC 문서와 비교할 수 있는 데이터를 로그로 표시합니다.
데모 실행 방법은 아래와 같으며, 실행 파일 이름은 플랫폼에 따라 다를 수 있습니다.

```cmd
test_demo.exe
```

실행 시, 아래와 같은 디버그 로그를 확인할 수 있습니다.
extractsakke mask :  9BD4EA1E801D37E62AD2FAB0D4F5BBF7
extractsakke SSV result: 123456789abcdef0123456789abcdef0

---


## 8. 라이선스

이 프로젝트는 **Apache License 2.0** 하에 제공됩니다.

- 본 프로젝트는 ECCSI-SAKKE(https://github.com/jim-b/ECCSI-SAKKE) 저장소의 sakke/tlpairing 로직 및 구현 아이디어를 참고 및 변환하여 사용하였으며, Apache License 2.0의 조건을 따릅니다.
- 자세한 사항은 NOTICE, LICENSE, THIRD_PARTY_NOTICES 파일을 참고하십시오.
