# -----------------------------------------------------------------------------
# mTLS-Core-C++ — CMake build
#
# A minimal, memory-safe TLS 1.3 record-layer engine (RFC 8446) built with
# C++20, OpenSSL 3.x EVP APIs, and GoogleTest (TDD).
#
# Design principles reflected here:
#   * Target-based CMake: every compile option, include dir, and link library
#     is attached to a TARGET (not set globally). This makes the build modular
#     and reusable — consumers of mtls_core get the right flags by linking
#     mtls_core::mtls_core.
#   * C++20 pinned, extensions off: no GNU/MSVC language extensions slip in.
#   * Strict warnings on our code, system-header treatment for GoogleTest.
#   * Opt-in ASan/UBSan, with the MSVC-specific /fsanitize=address spelling.
# -----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.20)

# NOTE: we name the CMake project mTLS_Core_CPP (no '++') because some
# generators (e.g. Visual Studio solutions) are picky about non-alphanumeric
# characters in project/target names. The on-disk directory is mTLS-Core-C++.
project(
    mTLS_Core_CPP
    VERSION 0.1.0
    DESCRIPTION "Minimal memory-safe TLS 1.3 record layer engine (RFC 8446)"
    LANGUAGES CXX
)

# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------
option(MTLS_CORE_BUILD_TESTS "Build the mTLS-Core unit tests" ON)
option(MTLS_CORE_ENABLE_ASAN  "Build with AddressSanitizer"       OFF)
option(MTLS_CORE_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)

# -----------------------------------------------------------------------------
# C++ standard
# -----------------------------------------------------------------------------
# CMAKE_CXX_STANDARD_REQUIRED ON  -> error if the compiler lacks C++20.
# CMAKE_CXX_EXTENSIONS OFF        -> forbid -std=gnu++20 / /std:c++20 with
#                                    vendor extensions, so our code is ISO C++.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------------------------------------------------------
# Warning helpers (target-based)
# -----------------------------------------------------------------------------
# We attach the strictest, still-reasonable warning set to every target we own.
# MSVC uses /W4 (equivalent to GCC/Clang -Wall -Wextra) plus /permissive- to
# enforce standards conformance. GCC/Clang add conversion and shadow warnings,
# which catch the kinds of silent value-truncation bugs that are deadly in
# crypto code (e.g. a size_t narrowed into a 2-byte length field).

function(mtls_core_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            /permissive-
            /EHsc            # enable C++ exceptions (needed by GTest)
        )
        # Suppress MSVC's "unsafe CRT function" warnings (strcpy_s etc.). We
        # never use those functions, but GTest's headers can trip the warning.
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Wshadow
        )
    endif()
endfunction()

# -----------------------------------------------------------------------------
# Sanitizer helpers (target-based)
# -----------------------------------------------------------------------------
# ASan/UBSan catch out-of-bounds access, use-after-free, and undefined behavior
# at runtime — exactly what we want for a memory-safe crypto engine.
#
# MSVC quirk: on Windows the ASan flag is /fsanitize=address (not the
# -fsanitize=address used by GCC/Clang). MSVC does not support UBSan.

function(mtls_core_enable_sanitizers target)
    if(NOT MTLS_CORE_ENABLE_ASAN AND NOT MTLS_CORE_ENABLE_UBSAN)
        return()
    endif()

    if(MSVC)
        if(MTLS_CORE_ENABLE_ASAN)
            target_compile_options(${target} PRIVATE /fsanitize=address)
            target_link_options(${target} PRIVATE /fsanitize=address)
        endif()
    else()
        set(_san_flags "")
        if(MTLS_CORE_ENABLE_ASAN)
            list(APPEND _san_flags -fsanitize=address)
        endif()
        if(MTLS_CORE_ENABLE_UBSAN)
            list(APPEND _san_flags -fsanitize=undefined)
        endif()
        # -fno-omit-frame-pointer keeps stack traces readable in ASan reports.
        target_compile_options(${target} PRIVATE ${_san_flags} -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE ${_san_flags})
    endif()
endfunction()

# -----------------------------------------------------------------------------
# OpenSSL discovery — "use real OpenSSL, never override the system default"
# -----------------------------------------------------------------------------
# Strategy (scoped to THIS project's build only):
#   * We never touch the system default. On macOS, /usr/bin/openssl is LibreSSL
#     (it lacks TLS 1.3 and reports a misleading version number). We leave it
#     exactly as-is; OPENSSL_ROOT_DIR here only tells *this* configure where to
#     look. It is a plain CMake variable and cannot leak to other projects.
#   * Priority:
#       1. An explicit -DOPENSSL_ROOT_DIR=... from the user always wins.
#       2. On macOS, ask Homebrew for the prefix of an actually-installed
#          OpenSSL formula (prefer the 3.x family we target), and only accept a
#          prefix whose headers really exist — so a dangling alias (e.g.
#          `openssl` -> openssl@4 when @4 is not installed) is skipped.
#       3. Elsewhere, let find_package() search the standard locations.

if(NOT OPENSSL_ROOT_DIR AND APPLE)
    find_program(MTLS_BREW_EXECUTABLE brew)
    if(MTLS_BREW_EXECUTABLE)
        # brew's formula names drift over time (currently `openssl` is an alias
        # for `openssl@4`, which is NOT installed here). Rather than hardcoding a
        # versioned path, query brew and verify the headers actually exist.
        foreach(_formula openssl@3 openssl openssl@1.1)
            execute_process(
                COMMAND "${MTLS_BREW_EXECUTABLE}" --prefix "${_formula}"
                OUTPUT_VARIABLE _mtls_prefix
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _mtls_rc
            )
            if(_mtls_rc EQUAL 0 AND _mtls_prefix
               AND EXISTS "${_mtls_prefix}/include/openssl/evp.h")
                set(OPENSSL_ROOT_DIR "${_mtls_prefix}")
                break()
            endif()
        endforeach()
    endif()
endif()

# On Windows, if OpenSSL is not auto-discovered, set OPENSSL_ROOT_DIR to the
# install prefix (e.g. C:/OpenSSL-Win64) before configuring.
find_package(OpenSSL 3.0 REQUIRED)

# find_package(OpenSSL) reports OPENSSL_VERSION as a bare number ("3.6.2") for
# real OpenSSL AND a similar-looking number for LibreSSL ("3.3.6"), so the
# version alone cannot distinguish them. LibreSSL also fakes OPENSSL_VERSION_NUMBER.
# The only reliable signal is the human-readable OPENSSL_VERSION_TEXT macro in
# opensslv.h, which says "OpenSSL ..." vs "LibreSSL ...". We grep the header.
if(OPENSSL_INCLUDE_DIR)
    file(READ "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" _mtls_ossl_header)
    if(_mtls_ossl_header MATCHES "LibreSSL")
        message(FATAL_ERROR
            "LibreSSL detected in ${OPENSSL_INCLUDE_DIR}, but mTLS-Core-C++ "
            "requires OpenSSL 3.x. Point OPENSSL_ROOT_DIR at a real OpenSSL 3.x "
            "install (e.g. -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3).")
    endif()
endif()

message(STATUS "Using OpenSSL ${OPENSSL_VERSION} from ${OPENSSL_ROOT_DIR}")

# -----------------------------------------------------------------------------
# Library target
# -----------------------------------------------------------------------------
add_library(mtls_core STATIC
    src/version.cpp
)
add_library(mtls_core::mtls_core ALIAS mtls_core)

target_include_directories(mtls_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Require C++20 for anyone linking against us (propagates the standard).
target_compile_features(mtls_core PUBLIC cxx_std_20)

# We link OpenSSL::Crypto (not OpenSSL::SSL) because the record layer only
# needs the EVP symmetric crypto primitives, not the TLS/SSL protocol state.
target_link_libraries(mtls_core PUBLIC OpenSSL::Crypto)

mtls_core_enable_warnings(mtls_core)
mtls_core_enable_sanitizers(mtls_core)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(MTLS_CORE_BUILD_TESTS)
    enable_testing()

    include(FetchContent)

    # MSVC quirk: GoogleTest defaults to the static CRT (/MT), but our code and
    # ASan build with the dynamic CRT (/MD). Mixing CRTs across translation
    # units causes link errors, so we force GoogleTest onto the shared CRT.
    set(gtest_force_shared_crt ON CACHE BOOL "Use shared CRT for GoogleTest (MSVC)" FORCE)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.18.0
    )
    FetchContent_MakeAvailable(googletest)

    # Treat GoogleTest headers as SYSTEM headers: they are third-party code, and
    # our strict warning flags (-Wconversion, -Wshadow, ...) must not fire
    # inside them, only in our own code.
    foreach(_gtarget gtest gtest_main)
        get_target_property(_gt_inc ${_gtarget} INTERFACE_INCLUDE_DIRECTORIES)
        set_target_properties(${_gtarget} PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "")
        target_include_directories(${_gtarget} SYSTEM INTERFACE ${_gt_inc})
    endforeach()

    add_executable(mtls_core_tests
        tests/cipher_suite_test.cpp
        tests/record_constants_test.cpp
        tests/version_test.cpp
    )
    target_link_libraries(mtls_core_tests PRIVATE
        mtls_core::mtls_core
        GTest::gtest_main
    )

    mtls_core_enable_warnings(mtls_core_tests)
    mtls_core_enable_sanitizers(mtls_core_tests)

    include(GoogleTest)
    gtest_discover_tests(mtls_core_tests)
endif()
