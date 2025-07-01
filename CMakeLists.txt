cmake_minimum_required(VERSION 3.19)
project(eccsi-sakke-core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(BUILD_SHARED "Build shared library" ON)
option(BUILD_STATIC "Build static library" OFF)

# Character encoding (prevent Korean text issues on Windows)
if(MSVC)
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/source-charset:utf-8>")
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/execution-charset:utf-8>")
endif()

# OpenSSL build: direct path (for bundled OpenSSL builds)
set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIB_DIR ${OPENSSL_ROOT_DIR}/lib)
set(OPENSSL_BIN_DIR ${OPENSSL_ROOT_DIR}/bin)

message(STATUS "Using OpenSSL from: ${OPENSSL_ROOT_DIR}")

# Source and header search
file(GLOB_RECURSE LIB_SRC src/*.cpp)

# OpenSSL (try system, fallback to bundled)
find_package(OpenSSL QUIET)
set(USE_SYSTEM_OPENSSL FALSE)

if(OpenSSL_FOUND)
    set(USE_SYSTEM_OPENSSL TRUE)
endif()

# Static Library
if(BUILD_STATIC)
    add_library(eccsisakke_static STATIC ${LIB_SRC})
    set_target_properties(eccsisakke_static PROPERTIES OUTPUT_NAME eccsisakke)
    target_include_directories(eccsisakke_static PUBLIC ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(eccsisakke_static PRIVATE ECCSISAKKE_STATIC)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(eccsisakke_static PRIVATE DEBUG)
    endif()

    # OpenSSL for static
    if(USE_SYSTEM_OPENSSL)
        target_include_directories(eccsisakke_static PUBLIC ${OPENSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(eccsisakke_static OpenSSL::SSL OpenSSL::Crypto)
    else()
        target_include_directories(eccsisakke_static PUBLIC ${OPENSSL_INCLUDE_DIR})

        if(WIN32)
            target_link_libraries(eccsisakke_static
                ${OPENSSL_LIB_DIR}/libssl.lib
                ${OPENSSL_LIB_DIR}/libcrypto.lib
            )
        else()
            target_link_libraries(eccsisakke_static
                ${OPENSSL_LIB_DIR}/libssl.so
                ${OPENSSL_LIB_DIR}/libcrypto.so
            )
        endif()
    endif()
endif()

# Shared Library
if(BUILD_SHARED)
    add_library(eccsisakke_shared SHARED ${LIB_SRC})
    set_target_properties(eccsisakke_shared PROPERTIES OUTPUT_NAME eccsisakke)
    target_include_directories(eccsisakke_shared PUBLIC ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(eccsisakke_shared PRIVATE ECCSISAKKE_EXPORTS)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(eccsisakke_shared PRIVATE DEBUG)
    endif()

    # OpenSSL for shared
    if(USE_SYSTEM_OPENSSL)
        target_include_directories(eccsisakke_shared PUBLIC ${OPENSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(eccsisakke_shared OpenSSL::SSL OpenSSL::Crypto)
    else()
        target_include_directories(eccsisakke_shared PUBLIC ${OPENSSL_INCLUDE_DIR})

        if(WIN32)
            target_link_libraries(eccsisakke_shared
                ${OPENSSL_LIB_DIR}/libssl.lib
                ${OPENSSL_LIB_DIR}/libcrypto.lib
            )
        else()
            target_link_libraries(eccsisakke_shared
                ${OPENSSL_LIB_DIR}/libssl.so
                ${OPENSSL_LIB_DIR}/libcrypto.so
            )
        endif()
    endif()
endif()

# --- Add test executable (test/demo.cpp) ---
add_executable(test_demo test/demo.cpp)
target_include_directories(test_demo PRIVATE ${CMAKE_SOURCE_DIR}/include)

if(BUILD_SHARED)
    target_link_libraries(test_demo PRIVATE eccsisakke_shared)
    target_compile_definitions(test_demo PRIVATE ECCSISAKKE_SHARED)
elseif(BUILD_STATIC)
    target_link_libraries(test_demo PRIVATE eccsisakke_static)
    target_compile_definitions(test_demo PRIVATE ECCSISAKKE_STATIC)
endif()

# --- Auto copy OpenSSL DLLs on Windows after build ---
if(WIN32 AND EXISTS "${OPENSSL_BIN_DIR}/libssl-3-x64.dll")
    add_custom_command(TARGET test_demo POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_BIN_DIR}/libssl-3-x64.dll
        $<TARGET_FILE_DIR:test_demo>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll
        $<TARGET_FILE_DIR:test_demo>
    )
endif()
