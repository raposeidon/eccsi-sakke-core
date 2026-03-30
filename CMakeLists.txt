cmake_minimum_required(VERSION 3.19)
project(eccsi-sakke-core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Standalone vs submodule detection ─────────────────────────────────────────
# CMAKE_PROJECT_NAME == PROJECT_NAME only when this is the top-level project.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(_ECCSI_STANDALONE ON)
else()
    set(_ECCSI_STANDALONE OFF)
endif()

option(BUILD_SHARED "Build shared library" ON)
option(BUILD_STATIC "Build static library" OFF)
# Demo app is built by default only in standalone mode.
option(ECCSI_SAKKE_BUILD_DEMO "Build demo executable" ${_ECCSI_STANDALONE})

# Character encoding (prevent Korean text issues on Windows)
if(MSVC)
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/source-charset:utf-8>")
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/execution-charset:utf-8>")
endif()

# ── OpenSSL resolution ────────────────────────────────────────────────────────
# Use CMAKE_CURRENT_SOURCE_DIR (not CMAKE_SOURCE_DIR) so paths are correct
# when this project is included as a submodule.
set(_ECCSI_OPENSSL_BASE ${CMAKE_CURRENT_SOURCE_DIR}/external/openssl)
if(ANDROID)
    set(_ECCSI_OPENSSL_BUNDLED ${_ECCSI_OPENSSL_BASE}-android-${ANDROID_ABI})
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(_ECCSI_OPENSSL_BUNDLED ${_ECCSI_OPENSSL_BASE}-ios-arm64)
else()
    set(_ECCSI_OPENSSL_BUNDLED ${_ECCSI_OPENSSL_BASE})
endif()

# Step 1: prefer system / parent-provided OpenSSL (no bundled hint yet).
# In submodule mode this is the only allowed source of OpenSSL, which prevents
# symbol conflicts when both projects would otherwise link different copies.
find_package(OpenSSL QUIET)

set(_ECCSI_OPENSSL_IS_BUNDLED FALSE)

if(OpenSSL_FOUND)
    message(STATUS "[eccsi-sakke] Using system/parent OpenSSL ${OPENSSL_VERSION}")
    set(_ECCSI_OPENSSL_USE_IMPORTED TRUE)

elseif(_ECCSI_STANDALONE)
    # Step 2 (standalone only): try bundled OpenSSL with hint.
    set(OPENSSL_ROOT_DIR ${_ECCSI_OPENSSL_BUNDLED})
    unset(OPENSSL_SSL_LIBRARY    CACHE)
    unset(OPENSSL_CRYPTO_LIBRARY CACHE)
    unset(OPENSSL_INCLUDE_DIR    CACHE)
    find_package(OpenSSL QUIET)
    set(_ECCSI_OPENSSL_IS_BUNDLED TRUE)

    if(OpenSSL_FOUND)
        message(STATUS "[eccsi-sakke] Using bundled OpenSSL ${OPENSSL_VERSION} from ${_ECCSI_OPENSSL_BUNDLED}")
        set(_ECCSI_OPENSSL_USE_IMPORTED TRUE)
    else()
        # Last resort: manually link pre-built bundled binaries.
        message(STATUS "[eccsi-sakke] Using bundled OpenSSL (manual link) from ${_ECCSI_OPENSSL_BUNDLED}")
        set(_ECCSI_OPENSSL_USE_IMPORTED FALSE)
    endif()

else()
    # Submodule build with no OpenSSL available → hard error.
    message(FATAL_ERROR
        "[eccsi-sakke-core] Submodule build: OpenSSL not found via find_package.\n"
        "Add 'find_package(OpenSSL REQUIRED)' in the parent CMakeLists.txt "
        "before 'add_subdirectory(eccsi-sakke-core)'."
    )
endif()

# Helper: apply OpenSSL linkage + Android extras to a target.
# Uses PUBLIC so that consumers can compile against this library's headers,
# which directly include <openssl/ec.h>, <openssl/bn.h>, etc.
function(_eccsi_apply_openssl target_name)
    if(_ECCSI_OPENSSL_USE_IMPORTED)
        target_link_libraries(${target_name} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    else()
        # Manual bundled linkage (fallback when FindOpenSSL couldn't find the bundled copy)
        set(_lib_dir ${_ECCSI_OPENSSL_BUNDLED}/lib)
        target_include_directories(${target_name} PUBLIC ${_ECCSI_OPENSSL_BUNDLED}/include)
        if(WIN32)
            target_link_libraries(${target_name} PUBLIC
                ${_lib_dir}/libssl.lib
                ${_lib_dir}/libcrypto.lib
            )
        elseif(EXISTS "${_lib_dir}/libssl.a")
            target_link_libraries(${target_name} PUBLIC
                ${_lib_dir}/libssl.a
                ${_lib_dir}/libcrypto.a
            )
        else()
            target_link_libraries(${target_name} PUBLIC
                ${_lib_dir}/libssl.so
                ${_lib_dir}/libcrypto.so
            )
        endif()
    endif()
    # Android logcat support — independent of OpenSSL, always required on Android.
    if(ANDROID)
        target_link_libraries(${target_name} PRIVATE log)
    endif()
endfunction()

# ── Source files ───────────────────────────────────────────────────────────────
file(GLOB_RECURSE LIB_SRC src/*.cpp)

# ── Static Library ─────────────────────────────────────────────────────────────
if(BUILD_STATIC)
    add_library(eccsisakke_static STATIC ${LIB_SRC})
    set_target_properties(eccsisakke_static PROPERTIES OUTPUT_NAME eccsisakke)
    target_include_directories(eccsisakke_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(eccsisakke_static PRIVATE ECCSISAKKE_STATIC)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(eccsisakke_static PRIVATE DEBUG)
    endif()
    _eccsi_apply_openssl(eccsisakke_static)
endif()

# ── Shared Library ─────────────────────────────────────────────────────────────
if(BUILD_SHARED)
    add_library(eccsisakke_shared SHARED ${LIB_SRC})
    set_target_properties(eccsisakke_shared PROPERTIES OUTPUT_NAME eccsisakke)
    target_include_directories(eccsisakke_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(eccsisakke_shared PRIVATE ECCSISAKKE_EXPORTS)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(eccsisakke_shared PRIVATE DEBUG)
    endif()
    _eccsi_apply_openssl(eccsisakke_shared)
endif()

# ── Demo executable (standalone only by default) ───────────────────────────────
if(ECCSI_SAKKE_BUILD_DEMO)
    add_executable(test_demo test/demo.cpp)
    target_include_directories(test_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    if(BUILD_SHARED)
        target_link_libraries(test_demo PRIVATE eccsisakke_shared)
        target_compile_definitions(test_demo PRIVATE ECCSISAKKE_SHARED)
    elseif(BUILD_STATIC)
        target_link_libraries(test_demo PRIVATE eccsisakke_static)
        target_compile_definitions(test_demo PRIVATE ECCSISAKKE_STATIC)
    endif()

    # Auto copy OpenSSL DLLs on Windows when using the bundled copy.
    # System-installed OpenSSL is expected to be on PATH already.
    if(WIN32 AND _ECCSI_OPENSSL_IS_BUNDLED AND EXISTS "${_ECCSI_OPENSSL_BUNDLED}/bin/libssl-3-x64.dll")
        add_custom_command(TARGET test_demo POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${_ECCSI_OPENSSL_BUNDLED}/bin/libssl-3-x64.dll
                $<TARGET_FILE_DIR:test_demo>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${_ECCSI_OPENSSL_BUNDLED}/bin/libcrypto-3-x64.dll
                $<TARGET_FILE_DIR:test_demo>
        )
    endif()
endif()
