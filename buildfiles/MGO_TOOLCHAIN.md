# Toolchain

The reference binary this fork is reconstructed from — `rpcs3.exe.bak` in
`~/Desktop/research/MGO2` — was not built with MSVC. Everything below was
recovered from strings the compiler and CRT embed in the image
(`tools/probe_toolchain.py` in `~/Desktop/mgo2-plugin`).

## What the reference was built with

| Property | Value | Evidence |
|---|---|---|
| Compiler | **LLVM/clang 22.1.8** | `LLVM version 22.1.8 (d34feaaa…)` at file offset `0x4697700` |
| C++ standard library | **libc++** | 302,846 COFF symbols, `_ZNSt3__1*` inline-namespace mangling; **zero** `_ZNSt7__cxx11` (libstdc++) symbols |
| Target | `x86_64-w64-mingw32` | mingw-w64 CRT source paths, `D:/W/B/src/mingw-w64/mingw-w64-crt/crt/tls_atexit.c` |
| Threads model | `win32` | 33 `win32` hits vs 4 `posix` |
| Linker | `lld` | LLVM built-in-linker symbol table (`llvm.aarch64.*` aliases) |
| Debug info | DWARF | 564 `dwarf` hits — a Debug build, not Release |
| Build timestamp | `0x6abee964` = 2026-10-01T23:14:44Z | PE `TimeDateStamp` |
| Symbols | **not stripped** | COFF symbol table at `0x5035800`, 302,846 entries |
| Build host | **Arch Linux, cross-compiling** | DWARF paths: `/mnt/0E88FF7D88FF619F/Arch/ughhanotherrpcs3/rpcs3-savemgo/…` (a WSL mount) |
| Build tree | `/mnt/0E88FF7D88FF619F/Arch/ughhanotherrpcs3/rpcs3-savemgo/` | same; the fork's own source paths are in the image |

The build host matters: the reference was not built on Windows at all. It is a
Linux cross-compile to `x86_64-w64-mingw32`, which is why the compiler identity,
the CRT, and the host paths all disagree with a native MSVC or a native MinGW
build. Reproducing it means cross-compiling from Linux, not compiling on
Windows.

The Itanium mangling with a `St3__1` inline namespace is the giveaway: MSVC would
mangle `std::string` as `?AV?$basic_string@...`, and libstdc++ would use
`NSt7__cxx11`. Neither appears.

Upstream also requires **clang ≥ 19.0** (`CMakeLists.txt:19-23`), so 22.1.8 is
consistent with a supported configuration rather than something exotic.

## Status on this machine

| Requirement | Present? |
|---|---|
| clang 19+ / 22.1.8 | **No** — only GCC 16.2.0 (WinLibs) |
| Windows SDK | **No** |
| MSVC (`cl.exe`) | **No** — VS 2022 dir present but empty |
| Qt6 | **No** |
| Vulkan SDK | **No** |
| GCC 16.2.0 `x86_64-w64-mingw32` | Yes |
| CMake 4.4.2 / Ninja 1.13.2 | Yes |

So the reference toolchain cannot be reproduced here as-is. What *is* possible is
matching the parts that affect our code's semantics.

## What was actually verified

The MGO sources compile cleanly with GCC 16.2.0 / MinGW-w64 using the include
set below. This is a real compile (`-fsyntax-only`, zero errors), not a
hand-check:

```bash
g++ -fsyntax-only -std=c++20 -DARCH_X64 \
  -I. -Irpcs3 -I3rdparty \
  -I3rdparty/yaml-cpp/yaml-cpp/include -I3rdparty/zlib/zlib \
  -I3rdparty/ffmpeg/include -I3rdparty/stblib/stb \
  -I3rdparty/asmjit/asmjit/src -I3rdparty/wolfssl/wolfssl \
  -I3rdparty/wolfssl/extra/win32 -I3rdparty/miniupnp/miniupnp/miniupnpc/include \
  -I3rdparty/curl/curl/include -I3rdparty/rtmidi/rtmidi \
  -I3rdparty/libusb/libusb/libusb -I3rdparty/libsdl-org/SDL/include \
  rpcs3/Emu/Cell/SPUTaskHLE/ppu_task_hle.cpp
```

Two files — `rpcs3/Emu/System.cpp` and `rpcs3/Emu/Cell/PPUThread.cpp` — are
large enough that a clean result could mean "skipped" rather than "checked".
Both were confirmed to genuinely parse by appending `static_assert(false, …)` and
observing the error. Do that again if you touch them.

### Not verified

`rpcs3/Emu/system_config.h` consumers, `rpcs3qt/settings_dialog.cpp` and
`Settings.cpp` need Qt6 headers. `3rdparty/opencv` is not initialised. These
files have not been compiled in this session.

## To actually reproduce the reference toolchain

Upstream's `CMakePresets.json` only ships `gcc` and `clang` presets for Ninja on
POSIX; there is no Windows/MinGW preset, so a toolchain file is hand-written.
This repo now carries both:

- `buildfiles/toolchain-mingw-clang.cmake` — clang + libc++ targeting
  `x86_64-w64-mingw32`, with `DISABLE_LTO=TRUE` and
  `USE_NATIVE_INSTRUCTIONS=OFF` forced.
- the **`mingw-clang` preset** in `CMakePresets.json`, which wires that toolchain
  file up so the invocation is just:

```bash
# On a Linux host cross-compiling to Windows, which is what the reference did:
cmake --preset mingw-clang
cmake --build --preset mingw-clang
```

Requirements for that to work at all:

- LLVM ≥ 19 with a mingw-w64 sysroot (the reference used 22.1.8)
- `LLVM_ENABLE_LIBCXX=ON`, so the standard library matches the reference rather
  than the mingw-shipped libstdc++
- Qt 6 built against the *same* toolchain — Qt publishes no official MinGW
  build, so this has to be self-built
- Vulkan SDK 1.3+

`DISABLE_LTO=TRUE` is not optional: `CMakeLists.txt:117` hard-fails the configure
step if `-flto` appears in the flags, and LLVM's default MinGW builds enable it.

The preset and the toolchain file are both **untested** — no clang, Qt6, or
Vulkan SDK exists on the machine they were written on, so a full link has never
been attempted. They encode a configuration that is known to be self-consistent,
not one that has been observed to build.

## Verifying the reconstruction instead

Since byte-identity is out of reach (§ *Honest scope*), the useful target is
behavioural parity, and that needs the RE claims to be checkable rather than
asserted. `buildfiles/mgo_verify_re.py` does that:

```bash
python buildfiles/mgo_verify_re.py --elf MGO2.ELF --exe rpcs3.exe.bak
```

It re-derives from the two artefacts every number this project treats as
recovered — the eight hook records and their call sites, the `bl` encode and
decode, the modelsetup handler's `lr-4` dispatch, the toolchain identity — and
exits non-zero if anything disagrees. It currently passes 117 checks.

This is not a formality. It caught a sign-extension bug in its own `bl` decoder
and a wrong assumption about where the third modelsetup call site's immediate
appears (it is in `.rdata` as a table entry, so a whole-image byte search finds
it even though the handler never compares against it — the check only means
anything when scoped to the function).

## Honest scope

Getting a byte-identical `rpcs3.exe` is not achievable by any amount of toolchain
work, because:

1. **The source does not exist.** The fork is closed; `rpcs3-savemgo` returns
   zero hits on GitHub. Matching the binary means reproducing a compiler's codegen
   for ~236 HLE handler bodies that have to be reconstructed from disassembly
   first — and reconstruction will not be instruction-identical.
2. **`TimeDateStamp` is a build-time value.** It is `0x6abee964` in the
   reference. Any rebuild stamps its own.
3. **DWARF debug info encodes absolute build paths.** The fork's own source
   paths are in the image (`/mnt/0E88FF7D88FF619F/Arch/ughhanotherrpcs3/
   rpcs3-savemgo/…`), as are the mingw-w64 CRT's (`D:/W/B/src/...`). These land
   in the image and depend on where the build ran.

There is now a fourth, and it is the reason the reconstruction cannot converge:
the reference image is **not stripped**, so all 302,846 of the fork's own symbol
names survive — including its internal namespaces, its per-rig lifter classes,
and its source file names. Those names are the most useful thing recovered from
this binary, and no amount of toolchain matching reproduces them for a codebase
that has never seen the source.

What the toolchain work *does* buy is narrower and worth stating plainly: it
makes the reconstruction **behaviourally** faithful rather than accidentally
different, and it gives a reproducible way to check parity. That is a real goal.
Byte-identity is not.
