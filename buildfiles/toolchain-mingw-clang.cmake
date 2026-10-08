# CMake toolchain: clang + libc++ targeting mingw-w64 (Windows).
#
# Written to match the toolchain recovered from the savemgo reference binary
# (rpcs3.exe.bak) — see buildfiles/MGO_TOOLCHAIN.md for the evidence.
#
#   clang/LLVM 22.1.8, libc++, x86_64-w64-mingw32, win32 threads, lld.
#
# This file is UNTESTED: no such toolchain exists on the machine it was written
# on, which only has GCC 16.2.0 (WinLibs). It exists so that the build is
# reproducible on a machine that has one.
#
# Usage:
#   cmake -B build-mingw -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=buildfiles/toolchain-mingw-clang.cmake \
#     -DCMAKE_BUILD_TYPE=Debug -DLLVM_ENABLE_LIBCXX=ON \
#     -DUSE_NATIVE_INSTRUCTIONS=OFF -DDISABLE_LTO=TRUE
#
# Required beforehand:
#   * LLVM 19+ (the reference used 22.1.8) with MinGW-w64 support
#   * a mingw-w64 sysroot providing the CRT headers and import libraries
#   * Qt 6 built against this same toolchain — Qt publishes no official
#     MinGW build, so this must be self-built
#   * Vulkan SDK 1.3+

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Let clang find its own default MSVC-style layout first; override below if a
# sysroot is supplied.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# --- sysroot ---------------------------------------------------------------
# Point this at a mingw-w64 installation. Left empty so a plain LLVM-for-Windows
# install (which ships its own mingw-w64 support) works unmodified.
#
# set(MGO_MINGW_SYSROOT "" CACHE PATH "mingw-w64 sysroot for clang")
# if(MGO_MINGW_SYSROOT)
#     set(CMAKE_SYSROOT "${MGO_MINGW_SYSROOT}")
# endif()

# --- compiler --------------------------------------------------------------
set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_C_COMPILER_TARGET   x86_64-w64-windows-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-w64-windows-gnu)

# --- flags -----------------------------------------------------------------
# libc++ rather than the GCC-shipped libstdc++. The reference binary's symbols
# are mangled with the libc++ inline namespace (NSt3__1), so matching it means
# matching the standard library, not just the compiler driver.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-stdlib=libc++ -fuse-ld=lld")

# Debug info: the reference is a Debug build (DWARF present in the image).
set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)

# LTO is rejected by the top-level CMakeLists (it hard-fails configure if -flto
# is present), and LLVM's MinGW defaults enable it. Keep it off.
set(DISABLE_LTO TRUE CACHE BOOL "" FORCE)

# -march=native makes the build machine-dependent; the reference was built with
# a fixed target.
set(USE_NATIVE_INSTRUCTIONS OFF CACHE BOOL "" FORCE)

# RPCS3 has no supported Windows/MinGW configuration, so the parts of the build
# that assume MSVC or POSIX need to be told to proceed.
set(BUILD_GUI ON CACHE BOOL "" FORCE)
set(USE_SYSTEM_CURL   OFF CACHE BOOL "" FORCE)
set(USE_SYSTEM_ZLIB   OFF CACHE BOOL "" FORCE)
set(USE_SYSTEM_LIBPNG OFF CACHE BOOL "" FORCE)
set(USE_FAUDIO        OFF CACHE BOOL "" FORCE)
