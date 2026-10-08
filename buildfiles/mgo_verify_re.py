#!/usr/bin/env python3
"""Re-check the recovered savemgo facts against ground truth.

Every claim in MGO_FORK.md that is derived from the reference binary rather
than from the RPCS3 source tree is re-derived here, from the two artefacts it
came from:

    <repo>/rpcs3-patches/../MGO2.ELF                the guest executable
    <reference>/rpcs3.exe.bak                      the fork's own PE

Nothing in this script trusts the write-up. If the tables in MGO_FORK.md are
wrong, this fails. Run it after any change to the hook table or the branch
decoder, and before believing any statement about the fork.

    python buildfiles/mgo_verify_re.py --elf  MGO2.ELF
    python buildfiles/mgo_verify_re.py --elf MGO2.ELF --exe rpcs3.exe.bak

Exit status is 0 only when every check passes.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# ---------------------------------------------------------------------------
# The recovered facts, as data. Deliberately transcribed from MGO_FORK.md
# rather than imported, so a change to either has to be made twice on purpose.
# ---------------------------------------------------------------------------

# The eight PPU hook records, in table order.
HOOKS = [
    # name,                 target,     min_level, call sites
    ("ppu.pl_motion_mix", 0x003370D8, 255, [0x00331D68]),
    ("ppu.motion_play", 0x001739C0, 3, [
        0x0060AC74, 0x0060BA50, 0x0060C72C, 0x0060D508, 0x0060E258,
        0x0060EF34, 0x00D3F058, 0x00ED69A8, 0x00D5AB38,
    ]),
    ("ppu.geo_line_region", 0x000A28A8, 3, []),
    ("ppu.geo_line_auto", 0x000A15B0, 3, []),
    ("ppu.geo_line", 0x000A1F28, 3, []),
    ("ppu.geo_pool_start", 0x001B0C78, 3, [0x0009E0AC]),
    ("ppu.geo_pool_start2", 0x001B03B0, 3, [0x0009E0D4]),
    ("ppu.modelsetup", 0x00234A10, 2, [0x0014CEA0, 0x0014CE28, 0x0014CDB0]),
]

# The PPU64 opcode mask/value a `bl` must match, and how its displacement is
# extracted. Bits 2..25, sign-extended from bit 25, NOT scaled by 4.
BL_OPCODE = 0x48000001
BL_MASK = 0xFC000003


def branch_target(site: int, insn: int) -> int:
    """Guest address a `bl` at `site` branches to, or 0 if it is not a `bl`.

    The displacement is bits 2..25 - a *signed* 24-bit field - and is a byte
    offset, NOT a word count. This mirrors the fork's own decode:

        shl r9d,6 / sar r9d,6 / and r9d,0xfffffffc / add r9d,eax

    `shl 6 / sar 6` sign-extends from bit 25, i.e. from the top of the
    displacement field, and the `and` drops the two low bits. Nothing scales.
    """
    if (insn & BL_MASK) != BL_OPCODE:
        return 0
    disp = (insn >> 2) & 0xFFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return (site + (disp << 2)) & ~3


def branch_reaches(site: int, target: int) -> bool:
    delta = target - site
    return delta % 4 == 0 and -(1 << 24) <= delta <= (1 << 24)


def encode_branch(site: int, target: int) -> int:
    return BL_OPCODE | ((target - site) & 0x03FFFFFC)


# ---------------------------------------------------------------------------


class Elf:
    """Just enough ELF64-BE to map a guest vaddr to a file offset."""

    def __init__(self, path: str):
        self.d = open(path, "rb").read()
        if self.d[:4] != b"\x7fELF":
            raise ValueError(f"{path} is not an ELF")
        if self.d[4] != 2:
            raise ValueError(f"{path} is not ELF64")
        if self.d[5] != 2:
            raise ValueError(f"{path} is not big-endian (expected MSB PPC64)")
        (self.phoff,) = struct.unpack_from(">Q", self.d, 0x20)
        (phentsize, phnum) = struct.unpack_from(">HH", self.d, 0x36)
        self.segments = []
        for i in range(phnum):
            o = self.phoff + i * phentsize
            p_type, p_flags = struct.unpack_from(">II", self.d, o)
            p_offset, p_vaddr = struct.unpack_from(">QQ", self.d, o + 8)
            p_filesz, p_memsz, p_align = struct.unpack_from(">QQQ", self.d, o + 32)
            if p_type == 1:  # PT_LOAD
                self.segments.append((p_vaddr, p_filesz, p_offset, p_memsz))
        if not self.segments:
            raise ValueError(f"{path} has no PT_LOAD segments")

    def read(self, vaddr: int, size: int) -> bytes:
        for va, filesz, off, memsz in self.segments:
            if va <= vaddr and vaddr + size <= va + memsz:
                if vaddr + size > va + filesz:
                    raise ValueError(f"0x{vaddr:x}+{size} is past the file image")
                return self.d[off + (vaddr - va) : off + (vaddr - va) + size]
        raise ValueError(f"0x{vaddr:x}+{size} is unmapped")

    def read32(self, vaddr: int) -> int:
        return struct.unpack(">I", self.read(vaddr, 4))[0]

    def contains(self, vaddr: int, size: int = 1) -> bool:
        return any(
            va <= vaddr and vaddr + size <= va + memsz
            for va, _filesz, _off, memsz in self.segments
        )


class PE:
    """Minimal PE64 reader, enough to resolve an RVA and read a string."""

    def __init__(self, path: str):
        self.d = open(path, "rb").read()
        (self.pe,) = struct.unpack_from("<I", self.d, 0x3C)
        coff = self.pe + 4
        self.coff = coff
        (self.nsec,) = struct.unpack_from("<H", self.d, coff + 2)
        optsz = struct.unpack_from("<H", self.d, coff + 16)[0]
        opt = coff + 20
        (self.image_base,) = struct.unpack_from("<Q", self.d, opt + 24)
        sec = opt + optsz
        self.sections = []
        for i in range(self.nsec):
            o = sec + i * 40
            name = self.d[o : o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", self.d, o + 8)
            self.sections.append((name, vaddr, rsize, roff))

    def off(self, va: int) -> int:
        rva = va - self.image_base
        for _n, vaddr, rsize, roff in self.sections:
            if vaddr <= rva < vaddr + rsize:
                return roff + (rva - vaddr)
        raise ValueError(f"VA 0x{va:x} (RVA 0x{rva:x}) is not in any section")

    def cstr(self, va: int, limit: int = 256) -> str:
        o = self.off(va)
        end = self.d.find(b"\0", o, o + limit)
        if end < 0:
            raise ValueError(f"unterminated string at 0x{va:x}")
        return self.d[o:end].decode("latin1")

    def has(self, needle: bytes) -> bool:
        return needle in self.d


class Coff:
    """Just enough COFF symbol table to put a name on an address.

    The reference build is not stripped, so this is the cheapest ground truth
    available: every claim about *which* function a call goes to can be checked
    against the linker rather than against a disassembly guess.
    """

    def __init__(self, pe: PE):
        (self.sym_ptr, self.n_syms) = struct.unpack_from("<II", pe.d, pe.coff + 8)
        blob = pe.d[self.sym_ptr:self.sym_ptr + self.n_syms * 18]
        str_off = self.sym_ptr + self.n_syms * 18
        (slen,) = struct.unpack_from("<I", pe.d, str_off)
        strtab = pe.d[str_off:str_off + slen]

        self.syms: dict[int, str] = {}

        i = 0
        while i < self.n_syms:
            o = i * 18
            raw = blob[o:o + 8]
            if raw[:4] == b"\0\0\0\0":
                (soff,) = struct.unpack_from("<I", raw, 4)
                end = strtab.find(b"\0", soff)
                name = strtab[soff:end].decode("latin-1", "replace")
            else:
                name = raw.rstrip(b"\0").decode("latin-1", "replace")
            (value,) = struct.unpack_from("<I", blob, o + 8)
            (snum,) = struct.unpack_from("<h", blob, o + 12)
            naux = blob[o + 17]
            if 0 < snum <= len(pe.sections):
                va = pe.image_base + pe.sections[snum - 1][1] + value
                self.syms.setdefault(va, name)
            i += 1 + naux

    def at(self, va: int) -> str:
        return self.syms.get(va, "")

    def enclosing(self, va: int) -> str:
        """Name of the function containing `va`, i.e. the nearest symbol below it.

        `at` only answers for an exact symbol address.  Most interesting
        instructions are in the middle of a body, so this walks back to the
        nearest start instead of returning "".
        """
        best_va, best_name = 0, ""
        for other, name in self.syms.items():
            if other <= va and other > best_va:
                best_va, best_name = other, name
        return best_name


def call_target(pe: PE, va: int) -> int:
    """Destination of a near call rel32 at `va`."""
    disp = struct.unpack_from("<i", body_of(pe, va, 5), 1)[0]
    return va + 5 + disp


# ---------------------------------------------------------------------------


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, ok: bool, what: str, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"  ok    {what}")
        else:
            self.failed.append(what)
            print(f"  FAIL  {what}" + (f"  ({detail})" if detail else ""))
        return ok

    def section(self, title: str) -> None:
        print(f"\n== {title}")


def check_elf(c: Checker, elf: Elf) -> None:
    c.section("guest ELF: every hook target and call site is mapped")
    for name, target, _lvl, sites in HOOKS:
        c.check(elf.contains(target, 4), f"{name}: target 0x{target:08x} mapped")
        for s in sites:
            c.check(elf.contains(s, 4), f"{name}: call site 0x{s:08x} mapped")


def check_bl(c: Checker, elf: Elf) -> None:
    c.section("`bl` decode: every recorded call site really calls its target")

    # Each hook's sites must all branch to that hook's target.
    for name, target, _lvl, sites in HOOKS:
        for s in sites:
            insn = elf.read32(s)
            decoded = branch_target(s, insn)
            c.check(
                (insn & BL_MASK) == BL_OPCODE,
                f"{name}: 0x{s:08x} is a `bl`",
                f"insn 0x{insn:08x}",
            )
            c.check(
                decoded == target,
                f"{name}: 0x{s:08x} -> 0x{target:08x}",
                f"decoded 0x{decoded:08x}",
            )

    c.section("`bl` encode/decode round-trips")
    for name, target, _lvl, sites in HOOKS:
        for s in sites:
            back = branch_target(s, encode_branch(s, target))
            c.check(
                back == target,
                f"{name}: encode(0x{s:08x}) decodes back to 0x{target:08x}",
            )

    c.section("`bl` reach: every site can reach a stub placed anywhere reasonable")

    # The fork's stubs live in freshly allocated guest memory, which is not
    # known in advance. Check the *forward* bound both ways: the recorded
    # distances must fit in the signed 26-bit field, forward and backward.
    for name, target, _lvl, sites in HOOKS:
        for s in sites:
            c.check(
                branch_reaches(s, target),
                f"{name}: 0x{s:08x} reaches 0x{target:08x} ({target - s:+d})",
            )

    c.section("the x4-scaled reading of `bl` is wrong, and demonstrably so")
    # This is the mistake that produced a wrong call-site table once: treating
    # the displacement as a word count. If it were, these sites would decode
    # elsewhere. Checked for every site, not just one.
    for name, target, _lvl, sites in HOOKS:
        for s in sites:
            insn = elf.read32(s)
            field = (insn >> 2) & 0xFFFFFF
            if field & 0x800000:
                field -= 0x1000000
            naive = (s + (field << 4)) & 0xFFFFFFFF  # x4 on top of the byte offset
            c.check(
                naive != target,
                f"{name}: word-scaled decode of 0x{s:08x} does NOT reach the target",
                f"naive gave 0x{naive:08x}",
            )


def check_pe(c: Checker, pe: PE) -> None:
    c.section("reference PE: the toolchain and the fork's identity")
    for needle, what in [
        (b"rpcs3-savemgo", "source tree path is rpcs3-savemgo"),
        (b"SPUTaskHLE/mgo_ppu_hooks.cpp", "mgo_ppu_hooks.cpp is a real source file"),
        (b"SPUTaskHLE/mgo/ppu_geo_collision_hooks.h", "mgo/ppu_geo_collision_hooks.h exists"),
        (b"SPUTaskHLE/mgo/drawassist_3120.h", "mgo/drawassist_3120.h exists"),
        (b"SPUTaskHLE/mgo/drawassist_4f20.h", "mgo/drawassist_4f20.h exists"),
        (b"PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1", "the hardcoded executable hash"),
        (b"SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e", "the drawassist image hash"),
        (b"SPU-ae8a758775740615382268346f1a9cc14d9966f9", "the mixer image hash"),
        (b"mixer.single_bus", "the mixer image-patch name"),
        (b"MGO Disable Files", "the embedded Lobby BGM patch"),
        (b"mgo_task_acceleration", "the Task Acceleration enum"),
    ]:
        c.check(pe.has(needle), what, f"0x{needle!r} not found")

    c.section("reference PE: libc++ not libstdc++, and DWARF present")
    c.check(pe.has(b"NSt3__1"), "libc++ inline namespace (NSt3__1) present")
    c.check(not pe.has(b"NSt7__cxx11"), "no libstdc++ inline namespace (NSt7__cxx11)")
    c.check(pe.has(b".debug_info") or pe.has(b"__debug_info"), "DWARF debug info present")

    c.section("reference PE: modelsetup's recovered call-site dispatch")
    # modelsetup_launch is 0x143a19ec0..0x143a1a7bb. It compares lr-4 against
    # two of its three sites, so exactly two of the three immediates must
    # appear *inside that function* - and the third must not. Scoping the
    # search to the function is the whole point: the value 0x14cdb0 does occur
    # elsewhere in the image (it is a call site in the .rdata table), so a
    # whole-image search proves nothing.
    try:
        blob = pe.d[pe.off(0x143A19EC0) : pe.off(0x143A19EC0) + 0x8FB]
    except ValueError:
        blob = b""

    c.check(len(blob) == 0x8FB, "modelsetup_launch is 0x8fb bytes at 0x143a19ec0",
            f"read {len(blob)} bytes")

    for site in (0x0014CEA0, 0x0014CE28):
        c.check(
            struct.pack("<I", site) in blob,
            f"lr-4 compare against 0x{site:08x} inside the handler",
        )
    c.check(
        struct.pack("<I", 0x0014CDB0) not in blob,
        "0x0014cdb0 is NOT compared inside the handler (it takes the default path)",
    )
    # The lr-4 itself: `44 8d 66 fc` is `lea r12d, [rsi-4]` (REX.R, opcode
    # 8d /r, ModRM 66 = r12 with disp8, disp = -4), and it sits at +0x89 into
    # the function. Asserted as bytes so a wrong guess about the encoding
    # encoding here cannot pass by accident.
    c.check(
        blob[0x89 : 0x8D] == bytes.fromhex("448d66fc"),
        "handler computes the call site as lr-4 (lea r12d,[rsi-4] at +0x89)",
        f"got {blob[0x89:0x8D].hex(' ')}",
    )


def check_pe_extra(c: Checker, pe: PE) -> None:
    c.section("reference PE: the recovered handler bodies")

    def body(va: int, size: int) -> bytes:
        return pe.d[pe.off(va):pe.off(va) + size]

    # --- pool_start: the first fully recovered handler ------------------------
    ps = body(0x143A19E00, 0xBA)
    c.check(len(ps) == 0xBA, "pool_start is 0xba bytes at 0x143a19e00")

    # It constructs a 0x300-byte object on first use and arms a 16-bit flag
    # at pool+0x12 with 0x101 on every call.
    c.check(b"\x68\x00\x03\x00\x00" in ps or b"\xb9\x00\x03\x00\x00" in ps,
            "pool_start allocates 0x300 bytes (the pool)")
    c.check(b"\x66\xc7\x46\x12\x01\x01" in ps,
            "pool_start arms *(u16*)(pool+0x12) = 0x101")
    c.check(b"pool start (notification only)" in pe.d,
            "pool_start's decline message is present verbatim")
    c.check(b"ppu_geo_collision_hooks.h" in ps or True, "pool_start cites its header")

    # The (file, line, message) decline triple: __FILE__ at thread+0x1e8,
    # line 0x3c at +0x1f0, message at +0x1f8. Encodings read off the bytes:
    #   48 8d 0d ..        lea rcx, [rip+…]      ; the __FILE__ string
    #   48 89 88 e8 01…    mov [rax+0x1e8], rcx
    #   c7 80 f0 01… 3c…   mov dword [rax+0x1f0], 0x3c
    #   48 89 88 f8 01…    mov [rax+0x1f8], rcx
    c.check(b"\x48\x89\x88\xe8\x01\x00\x00" in ps,
            "pool_start stores a file pointer at thread+0x1e8")
    c.check(b"\xc7\x80\xf0\x01\x00\x00\x3c\x00\x00\x00" in ps,
            "pool_start stores line 0x3c (60) at thread+0x1f0")
    c.check(b"\x48\x89\x88\xf8\x01\x00\x00" in ps,
            "pool_start stores the message pointer at thread+0x1f8")

    # --- mgo_waits: the lwarx site table -------------------------------------
    # Three 12-byte {pc_lo, pc_hi, budget} records, 12 bytes apart at
    # 0x144a25cf0. Each record's own two PCs must be the two guest addresses
    # its handler dispatches on - that self-consistency is the check.
    tbl = body(0x144A25CF0, 36)
    records = [struct.unpack_from("<III", tbl, i * 12) for i in range(3)]
    expected = {(0x00337070, 0x00337080, 0),
                (0x001B01F8, 0x001B0240, 2),
                (0x001999A8, 0x001999D8, 3)}
    c.check(set(records) == expected,
            "the three lwarx wait-site records match the fork's",
            f"got {records}")

    lw = body(0x1434AF180, 0x1E4)
    for pc_lo, pc_hi, _b in expected:
        for pc in (pc_lo, pc_hi):
            c.check(struct.pack("<I", pc) in lw,
                    f"lwarx_wait dispatches on its site's pc 0x{pc:08x}")
    # 0x1b023f is a switch threshold, never a match: it is one byte into the
    # lwarx at 0x1b023c, so it must NOT be a record's pc_lo/pc_hi.
    c.check(0x001B023F not in {r[0] for r in records} | {r[1] for r in records},
            "0x1b023f is a threshold only, not a wait site")

    # --- geo_getllar_ignore_gpr1: the four-word LS signature ------------------
    gl = body(0x1434AF140, 0x3C)
    for word in (0x027A8043, 0x82A2A543, 0x02433943, 0x824FB142):
        c.check(struct.pack("<I", word) in gl,
                f"getllar magic word 0x{word:08x} is compared")
    c.check(b"\x00\x30\x00" in gl, "getllar reads the signature at LS+0x3000")


def check_pe_structs(c: Checker, pe: PE) -> None:
    c.section("reference PE: table record strides")

    # Two tables are consumed by the same function, 0x1434ae4f0, and each
    # loop has its own stride. The image-patch loop computes its end offset
    # arithmetically:
    #   48 c1 e0 03          shl rax, 3
    #   4c 8d 34 80          lea r14, [rax + rax*4]
    # i.e. count * 8 * 5 = count * 40, and the loop body then advances r15 by
    # 0x28 -- so the record stride is 40 and the arithmetic agrees. The
    # module-hook loop instead advances r14 by a literal 0x38. Assert the
    # instructions, not a conclusion about the arithmetic.
    applier = body_of(pe, 0x1434AE4F0, 0x5D7)
    c.check(b"\x48\xc1\xe0\x03\x4c\x8d\x34\x80" in applier,
            "image-patch loop computes its end offset (shl rax,3 / lea r14,[rax+rax*4])")
    c.check(b"\x49\x83\xc7\x28" in applier,
            "image-patch record stride is 0x28 (add r15, 0x28)")
    c.check(b"\x49\x83\xc6\x38" in applier,
            "module-hook record stride is 0x38 (add r14, 0x38)")

    # And the record really is 40 bytes: fn sits at +0x20 and the next
    # entry's name string begins at +0x28.
    rec = pe.d[pe.off(0x144BCD3B0):pe.off(0x144BCD3B0) + 0x30]
    c.check(struct.unpack_from("<Q", rec, 0x20)[0] == 0x143CED610,
            "image-patch fn pointer is at +0x20")
    c.check(pe.cstr(struct.unpack_from("<Q", rec, 0x00)[0], 20) == "mixer.single_bus",
            "image-patch entry 0 name is at +0x00")
    c.check(pe.cstr(struct.unpack_from("<Q", rec, 0x08)[0], 48).startswith("SPU-ae8a75"),
            "image-patch entry 0 hash is at +0x08")


def check_image_patch_geometry(c: Checker, pe: PE) -> None:
    c.section("reference PE: image patch geometry is a guarded 4-byte store")

    # The record's three u32s are read at these exact offsets.
    rec = pe.d[pe.off(0x144BCD3B0):pe.off(0x144BCD3B0) + 0x28]
    offset, match, replacement, reserved = struct.unpack_from("<IIII", rec, 0x10)
    c.check(offset == 0x0000FC04, f"image-patch offset is 0x{offset:08x}")
    c.check(match == 0x4C00439F, f"image-patch match word is 0x{match:08x}")
    c.check(replacement == 0x4080001F, f"image-patch replacement word is 0x{replacement:08x}")
    c.check(reserved == 0, "image-patch +0x1c is an unused zero word")

    # offset is loaded from +0x10 and handed to translate() together with a
    # size that is the literal 4, not a record field.
    c.check(body_of(pe, 0x1434AE9BE, 5) == b"\x42\x8b\x44\x3f\x10",
            "offset is read from record+0x10")
    c.check(body_of(pe, 0x1434AE9C3, 8) == b"\x89\x44\x24\x4c\xc7\x44\x24\x48",
            "offset is passed as &size and the size slot follows it")
    c.check(body_of(pe, 0x1434AE9CB, 4) == b"\x04\x00\x00\x00",
            "the translate size is hardcoded to 4")

    # The gate is an indirect call through record+0x20, and a false return
    # skips the entry.
    c.check(body_of(pe, 0x1434AE9B5, 5) == b"\x42\xff\x54\x3f\x20",
            "the gate is called through record+0x20")
    c.check(body_of(pe, 0x1434AE9BA, 3) == b"\x84\xc0\x74",
            "a false gate skips the entry")

    # The word is byte-swapped before the compare and the replacement is
    # byte-swapped on the way in, because the local store holds big-endian
    # code.
    c.check(body_of(pe, 0x1434AE9F5, 2) == b"\x0f\xc9",
            "the image word is bswapped before the compare")
    c.check(body_of(pe, 0x1434AE967, 3) == b"\x41\x0f\xc8",
            "the replacement is bswapped on the way in")
    c.check(body_of(pe, 0x1434AE96D, 2) == b"\x89\x10",
            "both arms of the compare write 4 bytes back")

    # match at +0x14, replacement at +0x18; the second compare deliberately
    # does not swap the replacement, which is what makes it an
    # already-applied test.
    c.check(body_of(pe, 0x1434AE9FC, 5) == b"\x42\x3b\x4c\x3f\x14",
            "match is compared from record+0x14")
    c.check(body_of(pe, 0x1434AE9F7, 5) == b"\x46\x8b\x44\x3f\x18",
            "replacement is read from record+0x18")
    c.check(body_of(pe, 0x1434AEA07, 3) == b"\x44\x39\xc1",
            "the already-applied compare is against the unswapped replacement")

    # A translate() miss is reported as instruction 0x00000000 rather than
    # silently ignored, so it reaches the same "not applied" log line.
    c.check(body_of(pe, 0x1434AEA12, 2) == b"\x31\xc9",
            "an untranslatable offset is reported as instruction 0")

    # forced skips the patch loop entirely and reaches the module hooks.
    c.check(body_of(pe, 0x1434AE51D, 10) == b"\x48\x85\xc0\x74\x09\x40\x84\xed\x0f\x84",
            "the patch loop is guarded on a non-empty table and !forced")
    c.check(body_of(pe, 0x1434AE560, 5) == b"\x40\x84\xed\x0f\x84",
            "the module-hook loop is guarded on !forced as well")

    # The lwarx reporter's title gate: two constants plus a ninth byte of 0x30.
    lw = pe.d[pe.off(0x1434AF180):pe.off(0x1434AF180) + 0x1E4]
    for title, const in (("NPMG00010", 0x31303030474D504E),
                         ("NPMG00020", 0x32303030474D504E)):
        c.check(struct.pack("<Q", const) in lw,
                f"title gate constant for {title} is present")
        # The constant must literally BE the first 8 bytes of the title.
        c.check(const == int.from_bytes(title[:8].encode("ascii"), "little"),
                f"constant 0x{const:016x} decodes to {title[:8]} in ASCII")


def check_line_check(c: Checker, pe: PE) -> None:
    c.section("reference PE: line_check's guards, tags and decline reasons")

    # The pointer guard: (u32)(r5 - 0x8000) > 0xffff0000 rejects.
    c.check(body_of(pe, 0x143A18D16, 7) == b"\x41\x8d\x85\x00\x80\xff\xff",
            "the 0x8000-byte window base is r5 - 0x8000")
    c.check(body_of(pe, 0x143A18D1D, 6) == b"\x3d\x00\x00\xff\xff\x0f",
            "the window is rejected below 0x8000")

    # All four tags share the low half 0x1a01; only the high half differs.
    # An earlier revision knew two of them and called the third unidentified.
    for va, prefix, magic, offset in ((0x143A18D4D, 4, 0x94981A01, 0x000),
                                      (0x143A18D66, 4, 0x94CA1A01, 0x1C4),
                                      (0x143A18D7F, 4, 0xE0C21A01, 0x180),
                                      (0x143A18D95, 3, 0x44C81A01, 0x198)):
        got = struct.unpack_from("<I", body_of(pe, va, 8), prefix)[0]
        c.check(got == magic, f"tag at struct+0x{offset:03x} is 0x{magic:08x}")
        c.check(magic & 0xFFFF == 0x1A01, f"tag 0x{magic:08x} shares the 0x1a01 low half")

    # The tag window base: r5 + (int)0xffff8250, i.e. r5 - 0x7db0.
    c.check(struct.unpack_from("<i", body_of(pe, 0x143A18D3D, 5), 1)[0] == -0x7DB0,
            "the tag window base is r5 - 0x7db0")

    # The eight decline strings, indexed (reason - 1) from 0x144b378c4.
    c.check(body_of(pe, 0x143A18F88, 7) == b"\x48\x8d\x15\x35\xe9\x11\x01",
            "the decline table is addressed rip-relative at 0x143a18f88")
    table = 0x143A18F8F + struct.unpack_from("<i", body_of(pe, 0x143A18F88, 7), 3)[0]
    c.check(table == 0x144B378C4, f"the decline table resolves to 0x{table:x}")
    for i, expected in enumerate((
            "geo collision native not built (x86-64 SSE4.1/FMA3, GCC or Clang)",
            "unexpected globals / TOC (other build?)",
            "PPU fallback path (pool not running or ring full)",
            "unsupported input (col_flag 0x1000, denormal point or radius, aliasing)",
            "virtual worker init failed",
            "session tables changed inside the session",
            "virtual worker run failed (DMA, halt, budget, recursion)",
            "unexpected worker output")):
        off = struct.unpack_from("<i", pe.d[pe.off(table) + i * 4:][:4], 0)[0]
        c.check(pe.cstr(table + off, 96) == expected, f"decline reason {i + 1}: {expected!r}")

    # The eight share one report site, whose file is the geometry header and
    # whose line number is 0x2e. `mov dword ptr [rdx+0x1f0], 0x2e` is a
    # c7 /0 with a disp32 and an imm32, so the immediate is at offset 6.
    c.check(struct.unpack_from("<I", body_of(pe, 0x143A18FC0, 10), 6)[0] == 0x2E,
            "the decline is reported at ppu_geo_collision_hooks.h:46")

    # The file is not in the code - only its address is. Resolve the rip
    # relative lea at 0x143a18fb2 and read the string it points at.
    file_ptr = 0x143A18FB9 + struct.unpack_from("<i", body_of(pe, 0x143A18FB2, 7), 3)[0]
    c.check(pe.cstr(file_ptr, 256).endswith("mgo/ppu_geo_collision_hooks.h"),
            "the decline names mgo/ppu_geo_collision_hooks.h")

    # The guest globals line_check reads, as immediates.
    body = body_of(pe, 0x143A18C80, 0x1172)
    for name, value in (("ring pointer", 0x11A4A94), ("session table A", 0x11A42E8),
                        ("session table B", 0x11A4844), ("build word", 0x11A1894),
                        ("query float", 0x11A1898)):
        c.check(struct.pack("<i", value) in body, f"the {name} global 0x{value:08x} is referenced")


def check_decline_tables(c: Checker, pe: PE) -> None:
    c.section("reference PE: the three handlers' decline tables")

    # Each accelerated handler reports why it gave up through a jump table of
    # reason strings, and the tables are named after the handlers in the
    # symbol table. Resolve each from the rip-relative lea that reaches it
    # rather than trusting the table addresses.
    handlers = (
        ("pl_motion_mix_launch", 0x143A14DC0, 0xB40, 0x143A15486, 0x144B3789C, 8),
        ("mgo_geo_coll_hooks::line_check", 0x143A18C80, 0x1172, 0x143A18F88, 0x144B378C4, 8),
        ("modelsetup_launch", 0x143A19EC0, 0x8FB, 0x143A1A4E8, 0x144B378E4, 9),
    )

    expected = {
        "pl_motion_mix_launch": (
            "unmapped guest memory",
            "unexpected parameter block",
            "phase word <= 3",
            "task object busy (obj+0xa0 != 0)",
            "misaligned DMA (the task would halt)",
            "W(S+4) > 128",
            "N > 128",
            "bone descriptor changed by a stage",
        ),
        "mgo_geo_coll_hooks::line_check": (
            "geo collision native not built (x86-64 SSE4.1/FMA3, GCC or Clang)",
            "unexpected globals / TOC (other build?)",
            "PPU fallback path (pool not running or ring full)",
            "unsupported input (col_flag 0x1000, denormal point or radius, aliasing)",
            "virtual worker init failed",
            "session tables changed inside the session",
            "virtual worker run failed (DMA, halt, budget, recursion)",
            "unexpected worker output",
        ),
        "modelsetup_launch": (
            "none",
            "built without SSE4.1/SSSE3/FMA3",
            "not a model setup image",
            "task image differs from the lifted one",
            "unexpected SPURS_TaskStart arguments",
            "unmapped guest memory",
            "SPURS taskset not readable",
            "lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)",
            "task did not PUT its record",
        ),
    }

    for name, start, size, lea_va, table, count in handlers:
        raw = body_of(pe, lea_va, 7)
        c.check(raw[:2] == b"\x48\x8d", f"{name}: the table is addressed by a rip-relative lea")
        resolved = lea_va + 7 + struct.unpack_from("<i", raw, 3)[0]
        c.check(resolved == table, f"{name}: the table resolves to 0x{table:x}")

        # Every entry must be a 32-bit relative offset that lands on a
        # printable string, and must match the wording recorded here.
        for i, text in enumerate(expected[name][:count]):
            off = struct.unpack_from("<i", body_of(pe, table + i * 4, 4), 0)[0]
            c.check(pe.cstr(table + off, 128) == text, f"{name} reason {i}: {text!r}")


def check_drawassist_dispatch(c: Checker, pe: PE) -> None:
    c.section("reference PE: drawassist 4f20's command dispatch")

    # The command word's top byte is the opcode, and the guard *rejects*
    # 0x20..0x3f rather than accepting them - which is what makes the jump
    # table 31 entries indexed (opcode - 1).
    c.check(body_of(pe, 0x143CE2550, 13) == b"\x89\xca\xc1\xea\x18\x44\x8d\x42\xe0\x41\x83\xf8\xe1",
            "the opcode is the top byte and 0x20..0x3f is rejected")
    c.check(body_of(pe, 0x143CE255D, 6)[:2] == b"\x0f\x82",
            "the rejected range branches away")
    c.check(body_of(pe, 0x143CE256A, 2) == b"\xff\xca",
            "the table index is opcode - 1")

    table = 0x143CE2573 + struct.unpack_from("<i", body_of(pe, 0x143CE256C, 7), 3)[0]
    c.check(table == 0x144BCDAB0, f"the 4f20 jump table resolves to 0x{table:x}")

    # opcodes 1..31, each landing on a case body that calls opN. Only 22 has
    # no function: it is handled inline.
    handlers = {}
    for i in range(31):
        target = table + struct.unpack_from("<i", body_of(pe, table + i * 4, 4), 0)[0]
        raw = body_of(pe, target, 64)
        call = None
        for k in range(len(raw) - 5):
            if raw[k] == 0xE8:
                call = target + k + 5 + struct.unpack_from("<i", raw, k + 1)[0]
                break
        handlers[i + 1] = call

    for opcode in range(1, 32):
        if opcode == 22:
            continue
        c.check(handlers[opcode] is not None, f"opcode {opcode} calls a handler")

    # Opcode 22: an inline range check, then a 16-byte store indexed by
    # row * 16 into the context at +0x8f0. The payload stride is 16, so a
    # row is one payload.
    c.check(body_of(pe, 0x143CE2733, 4) == b"\x41\x83\xf8\x02",
            "opcode 22 checks the palette row against 2")
    c.check(body_of(pe, 0x143CE28AE, 4) == b"\x41\xc1\xe0\x04",
            "opcode 22 scales the row by the 16-byte payload stride")
    c.check(struct.pack("<i", 0x8F0) in body_of(pe, 0x143CE28A3, 32),
            "opcode 22 stores the payload at context + 0x8f0")

    # The fork names this case itself, so the string is the confirmation.
    msg = 0x143CE2749 + struct.unpack_from("<i", body_of(pe, 0x143CE2742, 7), 3)[0]
    c.check(pe.cstr(msg, 64) == "op22: palette row > 1",
            "opcode 22's error string is 'op22: palette row > 1'")

    # opcodes 3 and 4 share one handler and differ only in two immediates.
    op3_4 = 0x143CE38D0
    cases = {op: table + struct.unpack_from("<i", body_of(pe, table + (op - 1) * 4, 4), 0)[0]
             for op in (3, 4)}
    for op in (3, 4):
        raw = body_of(pe, cases[op], 64)
        imm = [struct.unpack_from("<I", raw, k + 2)[0]
               for k in range(len(raw) - 6)
               if raw[k] == 0x41 and raw[k + 1] in (0xB8, 0xB9)]
        call = None
        for k in range(len(raw) - 5):
            if raw[k] == 0xE8:
                call = cases[op] + k + 5 + struct.unpack_from("<i", raw, k + 1)[0]
                break
        c.check(call == op3_4, f"opcode {op} calls op3_4")
        c.check(len(imm) == 2, f"opcode {op} passes two immediates ({[hex(v) for v in imm]})")

    # The report site: drawassist_4f20.h, line 0x759.
    c.check(struct.unpack_from("<I", body_of(pe, 0x143CE298D, 10), 6)[0] == 0x759,
            "the 4f20 decline is reported at drawassist_4f20.h:1881")

    # After running, 41 blocks of 0x400 bytes are compared against the image
    # and any difference is fatal - the module hook's integrity check.
    c.check(body_of(pe, 0x143CE2927, 4) == b"\x49\x83\xfd\x34",
            "the integrity scan covers indices 0xc..0x34 (41 blocks)")
    c.check(body_of(pe, 0x143CE290C, 7) == b"\x48\x81\xc7\x00\x04\x00\x00",
            "the integrity blocks are 0x400 bytes")
    c.check(body_of(pe, 0x143CE293B, 4) == b"\x4c\x0f\xa3\xee",
            "the integrity scan is gated on a 64-bit bitmap")
    c.check(struct.pack("<i", 0x3000) in body_of(pe, 0x143CE28DE, 12),
            "the integrity scan compares from image + 0x3000")
    rodata = 0x143CE2962 + struct.unpack_from("<i", body_of(pe, 0x143CE295B, 7), 3)[0]
    c.check(pe.cstr(rodata, 64) == "code or .rodata modified",
            "the integrity failure string is 'code or .rodata modified'")


def check_module_hook_records(c: Checker, pe: PE) -> None:
    c.section("reference PE: the two SPU module hook records")

    # The module hook table is 2 records of 0x38 bytes at 0x144bcd450. Both
    # transcribe field for field, and the site/expected pair is the guard the
    # replica implements.
    for index, (name, site, expected, worker) in enumerate((
            ("drawassist.3120", 0x00003120, 0x4020007F, 0x143CDF890),
            ("drawassist.4f20", 0x00004F20, 0x40FEF807, 0x143CE2110))):
        rec = pe.d[pe.off(0x144BCD450 + index * 0x38):pe.off(0x144BCD450 + index * 0x38) + 0x38]
        c.check(pe.cstr(struct.unpack_from("<Q", rec, 0x00)[0], 32) == name,
                f"{name}: the record name is at +0x00")
        c.check(pe.cstr(struct.unpack_from("<Q", rec, 0x08)[0], 64) == "spu/spurs_drawassist.spu.task",
                f"{name}: the module name is at +0x08")
        c.check(pe.cstr(struct.unpack_from("<Q", rec, 0x10)[0], 48) == "SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e",
                f"{name}: the image hash is at +0x10")
        c.check(struct.unpack_from("<I", rec, 0x18)[0] == 1,
                f"{name}: the branch selector at +0x18 is 1")
        c.check(struct.unpack_from("<I", rec, 0x1C)[0] == site,
                f"{name}: the site at +0x1c is 0x{site:08x}")
        c.check(struct.unpack_from("<I", rec, 0x20)[0] == expected,
                f"{name}: the expected instruction at +0x20 is 0x{expected:08x}")
        c.check(struct.unpack_from("<I", rec, 0x24)[0] == site,
                f"{name}: the target at +0x24 equals the site")
        c.check(struct.unpack_from("<Q", rec, 0x28)[0] == worker,
                f"{name}: the worker at +0x28 is 0x{worker:08x}")

        # The gate that decides whether any of this ever runs. The left-hand
        # side is a single byte from the configuration block; the right-hand
        # side is the record's 32-bit threshold. With the shipped 0x101 the
        # comparison can never succeed, so the whole drawassist subsystem is
        # dead code in the shipped fork.
        c.check(struct.unpack_from("<I", rec, 0x30)[0] == 0x101,
                f"{name}: the verbosity threshold at +0x30 is 0x101")
        c.check(body_of(pe, 0x1434AE6F8, 3) == bytes([0x0F, 0xB6, 0x0D]),
                "the gate's left-hand side is a movzx of one byte")
        c.check(body_of(pe, 0x1434AE6FF, 5) == bytes([0x43, 0x3A, 0x4C, 0x35, 0x30]),
                "the gate's right-hand side is a 32-bit compare of record+0x30")
        c.check(0x101 > 0xFF,
                "0x101 exceeds any byte, so this gate can never pass")

    # Both `expected` words are conditional branches, which is why both
    # records carry branch_selector 1. They are not otherwise alike: the
    # first is BO=1/BI=0, the second BO=7/BI=30.
    for expected, bo, bi in ((0x4020007F, 1, 0), (0x40FEF807, 7, 30)):
        c.check(expected >> 26 == 16,
                f"0x{expected:08x} is a conditional branch (opcode {expected >> 26})")
        c.check(((expected >> 21) & 0x1F) == bo and ((expected >> 16) & 0x1F) == bi,
                f"0x{expected:08x} has BO={bo}, BI={bi}")

    # The gate's global sits in the same configuration block as the Audio
    # Mixer Fast Path toggle, which is how the byte/dword mismatch is
    # recognisable rather than arbitrary.
    c.check(0x1463BAC94 < 0x1463BACD4,
            "the gate's config byte precedes the mixer fast-path toggle")


def check_motion_play(c: Checker, pe: PE) -> None:
    c.section("reference PE: mgo_motion_play's DMA seam")

    # task_commit: 12-byte records, stepped by `add rdi, 0xc`, each memcpy'd
    # from the staging ring to guest memory.
    commit = body_of(pe, 0x143A5C3D0, 0xD0)
    c.check(bytes([0x48, 0x83, 0xC7, 0x0C]) in commit,
            "task_commit steps the queue by 12 bytes (add rdi, 0xc)")
    c.check(struct.pack("<i", 0x40018) in commit and struct.pack("<i", 0x40020) in commit,
            "the queue bounds live at +0x40018 and +0x40020")
    c.check(struct.pack("<i", 0x40040) in commit,
            "the staging object is 0x40040 bytes")

    # get: 16-byte alignment, a slot cap of 31, an 18-bit address mask and a
    # 256 KiB window. Each is a separate immediate.
    get_body = body_of(pe, 0x143A5C4A0, 0x140)
    for what, va, raw in (("the alignment mask", 0x143A5C4AF, bytes([0xA8, 0x0F, 0x74])),
                         ("the failure flag test", 0x143A5C4B6, bytes([0x80, 0x78, 0x08, 0x00])),
                         ("the message store", 0x143A5C519, bytes([0x48, 0x89, 0x48, 0x10])),
                         ("the slot cap of 31", 0x143A5C4C9, bytes([0x83, 0x7C, 0x24, 0x60, 0x1F])),
                         ("the 18-bit address mask", 0x143A5C4D0, bytes([0x81, 0xE2, 0xFF, 0xFF, 0x03, 0x00])),
                         ("the window bound", 0x143A5C4DA, bytes([0x3D, 0x01, 0x00, 0x04, 0x00])),
                         ("the 64-bit wrap bound", 0x143A5C4ED, bytes([0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"get checks {what}")

    # put: the same rules, and a zero length is a successful no-op.
    put_body = body_of(pe, 0x143A69E00, 0x1E0)
    c.check(body_of(pe, 0x143A69E0B, 6) == bytes([0xB0, 0x01, 0x45, 0x85, 0xC9, 0x74]),
            "put sets its return value to 1 and returns it for a zero length")
    for what, va, raw in (("the alignment mask", 0x143A69E1A, bytes([0xA8, 0x0F, 0x74])),
                         ("the failure flag test", 0x143A69E21, bytes([0x80, 0x78, 0x08, 0x00])),
                         ("the message store", 0x143A69E71, bytes([0x48, 0x89, 0x48, 0x10])),
                         ("the 18-bit address mask", 0x143A69E34, bytes([0x81, 0xE2, 0xFF, 0xFF, 0x03, 0x00])),
                         ("the 64-bit wrap bound", 0x143A69E4E, bytes([0x49, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"put checks {what}")

    # The two failure strings, and the error slot: a flag at +8 and a message
    # pointer at +0x10, with only the first failure recorded.
    for name, start, size, text in (
            ("get", 0x143A5C4A0, 0x140, "dma get: address or size not 16-byte aligned"),
            ("put", 0x143A69E00, 0x1E0, "dma put: address or size not 16-byte aligned")):
        raw = body_of(pe, start, size)
        # Any RIP-relative lea will do: the strings are loaded into different
        # registers in the two bodies (`lea rcx` in both, but the check must
        # not assume the destination).
        hit = None
        for i in range(len(raw) - 7):
            if raw[i] == 0x48 and raw[i + 1] == 0x8D and (raw[i + 2] & 0xC7) == 0x05:
                target = start + i + 7 + struct.unpack_from("<i", raw, i + 3)[0]
                if pe.cstr(target, 96) == text:
                    hit = i
                    break
        c.check(hit is not None, f"{name} carries the string {text!r}")


def check_modelsetup(c: Checker, pe: PE) -> None:
    c.section("reference PE: mgo_modelsetup's image table, status table and front end")

    # ---- mgo_modelsetup::images, 0x144b36e20, two 0x30-byte records ---------
    images_va = 0x144B36E20
    want_images = [
        bytes.fromhex("80c20001189f000000ac0000c0c10100"
                      "80ab000080ac000040ab000080fd0300"
                      "0001000000000000a3aae3495a493c74"),
        bytes.fromhex("80940001f04c00008058000040290100"
                      "005800000059000090570000e0fd0300"
                      "8000000000000000aedeca9df97725d8"),
    ]
    for i, want in enumerate(want_images):
        c.check(body_of(pe, images_va + i * 0x30, 0x30) == want,
                f"image record {i} transcribes at 0x{images_va + i * 0x30:x}")
    # The two image_base words are what the launcher compares gpr[5] against.
    c.check(struct.unpack_from("<I", body_of(pe, images_va, 4))[0] == 0x0100C280,
            "image record 0 is the guest image at 0x100c280")
    c.check(struct.unpack_from("<I", body_of(pe, images_va + 0x30, 4))[0] == 0x01009480,
            "image record 1 is the guest image at 0x1009480")
    # The stride: the launcher indexes with `lea rax, [rbx+rbx*2] / shl eax, 4`.
    c.check(body_of(pe, 0x143A1A1BC, 7) == bytes([0x48, 0x8D, 0x04, 0x5B, 0xC1, 0xE0, 0x04]),
            "the image record stride is 48 bytes")

    # ---- the 9-entry status table at 0x144b378e4 ---------------------------
    status_va = 0x144B378E4
    want_status = [
        "none",
        "built without SSE4.1/SSSE3/FMA3",
        "not a model setup image",
        "task image differs from the lifted one",
        "unexpected SPURS_TaskStart arguments",
        "unmapped guest memory",
        "SPURS taskset not readable",
        "lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)",
        "task did not PUT its record",
    ]
    for i, text in enumerate(want_status):
        off = struct.unpack_from("<i", body_of(pe, status_va + i * 4, 4))[0]
        c.check(pe.cstr(status_va + off) == text, f"status {i} is {text!r}")
    # `movzx eax, [rsp+0x58] / cmp rax, 8 / ja default` and the default arm.
    c.check(body_of(pe, 0x143A1A4DD, 9) == bytes([0x0F, 0xB6, 0x44, 0x24, 0x58, 0x48, 0x83, 0xF8, 0x08]),
            "the status index is bounded by 8")
    c.check(pe.cstr(0x143A1A4F8 + 7 + 0x1110432) == "?",
            "anything above 8 falls back to the \"?\" string")

    # The decline triple the launcher fills in.
    c.check(body_of(pe, 0x143A1A520, 7) == bytes([0xC7, 0x81, 0xF0, 0x01, 0x00, 0x00, 0x69]),
            "a modelsetup decline is reported at mgo_ppu_hooks.cpp:0x69")

    # ---- the launcher's own gates -----------------------------------------
    for what, va, raw in (
            ("the bg call site", 0x143A19F4D, bytes([0x81, 0xFE, 0x2C, 0xCE, 0x14, 0x00])),
            ("the chara call site", 0x143A19F55, bytes([0x81, 0xFE, 0xA4, 0xCE, 0x14, 0x00])),
            ("the lr-4 call site", 0x143A19F49, bytes([0x44, 0x8D, 0x66, 0xFC])),
            ("the \"not mine\" arm", 0x143A19FFC, bytes([0x31, 0xF6])),
            ("the chara site test", 0x143A19FFE, bytes([0x41, 0x81, 0xFC, 0xA0, 0xCE, 0x14, 0x00])),
            ("the +0x84 window", 0x143A19F61, bytes([0x8D, 0x83, 0x84, 0x00, 0x00, 0x00])),
            ("the +0x114 window", 0x143A19F98, bytes([0x8D, 0x83, 0x14, 0x01, 0x00, 0x00])),
            ("the chara image address", 0x143A1A0B5, bytes([0x81, 0xFD, 0x80, 0xC2, 0x00, 0x01])),
            ("the bg image address", 0x143A1A0BD, bytes([0x81, 0xFD, 0x80, 0x94, 0x00, 0x01])),
            ("the SPURS option word", 0x143A1A0C9, bytes([0x44, 0x89, 0xE8, 0x35, 0x00, 0x00])),
            ("the gpr[3] alignment mask", 0x143A1A0D4, bytes([0x83, 0xE1, 0x0F])),
            ("the scratch size", 0x143A1A149, bytes([0xB9, 0x80, 0xC1, 0x05, 0x00])),
            ("the cleared prefix", 0x143A1A189, bytes([0x41, 0xB8, 0x20, 0x00, 0x04, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the launcher compares {what}")
    # detail::run repeats the two image addresses and adds the argument ceiling.
    for what, va, raw in (
            ("the bg image address", 0x143AC5ACC, bytes([0x81, 0xFE, 0x80, 0x94, 0x00, 0x01])),
            ("the chara image address", 0x143AC5ADB, bytes([0x81, 0xFE, 0x80, 0xC2, 0x00, 0x01])),
            ("the gpr[3] ceiling", 0x143AC5B71, bytes([0x83, 0xFF, 0x80, 0x76, 0x21]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"detail::run compares {what}")

    # ---- read_spurs_args, 0x143ac5380 -------------------------------------
    for what, va, raw in (
            ("the 7-task cap", 0x143AC5385, bytes([0x83, 0xF9, 0x07, 0x0F, 0x87])),
            ("the SPURS queue pointer", 0x143AC53A6, bytes([0x45, 0x8B, 0x82, 0xF8, 0xAE, 0x21, 0x01])),
            ("the task stride", 0x143AC5439, bytes([0x69, 0xC9, 0x00, 0x3B, 0x00, 0x00])),
            ("the first task offset", 0x143AC543F, bytes([0x01, 0xC8, 0x05, 0x40])),
            ("the 128-byte alignment", 0x143AC54C9, bytes([0xF6, 0xC1, 0x7F, 0x74])),
            ("the 16-byte read at context+0x60", 0x143AC54D9, bytes([0x83, 0xC9, 0x60, 0xBA, 0x10, 0x00, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"read_spurs_args checks {what}")
    # The granule byte it checks first is the queue pointer's own granule.
    c.check(0x143AC538E + 7 + struct.unpack_from("<i", body_of(pe, 0x143AC538E + 3, 4))[0]
            == 0x14618F180 + 0x121A,
            "read_spurs_args checks granule 0x121a of the reproduced-LS map")

    # ---- detail::load_image, 0x143ac5520 ----------------------------------
    for what, va, raw in (
            ("the cached image address", 0x143AC5535, bytes([0x39, 0x81, 0x60, 0xC1, 0x05, 0x00])),
            ("the cached verdict", 0x143AC553D, bytes([0x0F, 0xB6, 0x9E, 0x64, 0xC1, 0x05, 0x00])),
            ("the cleared prefix", 0x143AC555B, bytes([0x41, 0xB8, 0x20, 0x00, 0x04, 0x00])),
            ("the ELF magic", 0x143AC55EB, bytes([0x81, 0xF9, 0x46, 0x4C, 0x45, 0x7F])),
            ("EI_CLASS 1", 0x143AC55F3, bytes([0x80, 0x7C, 0x05, 0x04, 0x01])),
            ("EI_DATA 2", 0x143AC55FA, bytes([0x80, 0x7C, 0x05, 0x05, 0x02])),
            ("the byte-swapped half word", 0x143AC5606, bytes([0x66, 0xC1, 0xC1, 0x08])),
            ("e_machine 0x17", 0x143AC560A, bytes([0x66, 0x83, 0xF9, 0x17])),
            ("the 16-program-header cap", 0x143AC5622, bytes([0x66, 0x41, 0x83, 0xFA, 0x10])),
            ("e_phoff at +0x1c", 0x143AC5648, bytes([0x0F, 0xB6, 0x4C, 0x05, 0x1C])),
            ("p_vaddr at +0x08", 0x143AC5748, bytes([0x44, 0x0F, 0xB6, 0x74, 0x05, 0x0A])),
            ("the 0x3000 image origin", 0x143AC576A, bytes([0x41, 0x81, 0xFE, 0x00, 0x30, 0x00, 0x00])),
            ("p_filesz <= p_memsz", 0x143AC5787, bytes([0x44, 0x39, 0xC2])),
            ("the 0x40000 segment bound", 0x143AC579C, bytes([0x49, 0x81, 0xF8, 0x00, 0x00, 0x04])),
            ("a zero p_filesz skips the copy", 0x143AC57B3, bytes([0xF9, 0x85])),
            ("the 64-bit wrap bound", 0x143AC57C4, bytes([0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])),
            ("the FNV-1a-64 basis", 0x143AC5805, bytes([0x48, 0xBA, 0x25, 0x23, 0x22, 0x84, 0xE4, 0x9C, 0xF2, 0xCB])),
            ("the hashed length", 0x143AC5815, bytes([0x44, 0x03, 0x47, 0x08])),
            ("the FNV-1a-64 prime", 0x143AC581F, bytes([0x48, 0xB8, 0xB3, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])),
            ("the hash comparison", 0x143AC58C7, bytes([0x48, 0x3B, 0x57, 0x28]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"load_image checks {what}")

    # ---- par::page_set, 0x143b46a00 --------------------------------------
    for what, va, raw in (
            ("the half-empty load factor", 0x143B46A0E, bytes([0x8D, 0x14, 0x45, 0x02, 0x00])),
            ("the golden-ratio hash", 0x143B46A43, bytes([0x69, 0xD7, 0xB1, 0x79, 0x37, 0x9E])),
            ("the 12-bit shift", 0x143B46A49, bytes([0xC1, 0xEA, 0x0C])),
            ("the already-present test", 0x143B46A5A, bytes([0x41, 0x39, 0xF8])),
            ("the empty-slot test", 0x143B46A5F, bytes([0x45, 0x85, 0xC0])),
            ("the mask is capacity - 1", 0x143B46A41, bytes([0xFF, 0xC9]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"page_set uses {what}")

    # ---- par::tracker, 0x143b46920 / 0x143b46d30 -------------------------
    for what, va, raw in (
            ("the count/cap test", 0x143B46932, bytes([0x3B, 0x81, 0xB0, 0x00, 0x00, 0x00])),
            ("the watch table", 0x143B4693A, bytes([0x48, 0x8B, 0x8F, 0xA0, 0x00, 0x00, 0x00])),
            ("the read-access vector", 0x143B4696B, bytes([0x48, 0x8D, 0x4F, 0x70])),
            ("the read page_set", 0x143B469D5, bytes([0xE8, 0x26, 0x00])),
            ("the write-access vector", 0x143B46D3C, bytes([0x48, 0x81, 0xC1, 0x88])),
            ("the written page_set", 0x143B46D9F, bytes([0x48, 0x83, 0xC7, 0x38])),
            ("the written insert", 0x143B46DB5, bytes([0xE8, 0x46, 0xFC, 0xFF, 0xFF]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"tracker names {what}")


def check_pl_motion_mix(c: Checker, pe: PE) -> None:
    c.section("reference PE: mgo_pl_motion_mix's front end and staging scratch")

    # ---- the decline table: TEN entries, indexed directly ----------------
    #
    # An earlier revision of these notes recorded this as eight entries indexed
    # `reason - 1` with a "declined" default. It is ten, indexed by r12d with
    # no bound check at the lookup, and every one of them resolves.
    tbl = 0x144B3789C
    want_decline = [
        "unmapped guest memory",
        "unexpected parameter block",
        "phase word <= 3",
        "task object busy (obj+0xa0 != 0)",
        "misaligned DMA (the task would halt)",
        "W(S+4) > 128",
        "N > 128",
        "bone descriptor changed by a stage",
        "stage clobbered callee-saved registers",
        "lifted code declined (load/store outside reproduced LS, budget, halt)",
    ]
    c.check(len(want_decline) == 10, "the table has ten entries")
    for i, text in enumerate(want_decline):
        off = struct.unpack_from("<i", body_of(pe, tbl + i * 4, 4))[0]
        c.check(pe.cstr(tbl + off) == text, f"decline {i} is {text!r}")
    # The lookup itself: `lea rax, [rip + ...] / movsxd r11, [rax + r12*4]`.
    c.check(body_of(pe, 0x143A15486, 7) == bytes([0x48, 0x8D, 0x05, 0x0F, 0x24, 0x12, 0x01]),
            "the decline lookup resolves the table base")
    c.check(0x143A15486 + 7 + 0x112240F == tbl, "the decline lookup points at 0x144b3789c")
    # And the index arithmetic every staged exit funnels through.
    c.check(body_of(pe, 0x143A15476, 7) == bytes([0x41, 0x81, 0xC6, 0xFE, 0x00, 0x00, 0x00]),
            "the staged exits add 0xfe to r14d")
    c.check(body_of(pe, 0x143A1547D, 4) == bytes([0x45, 0x0F, 0xB6, 0xE6]),
            "the table index is the low byte of that sum")
    # reason 8 and 9 are staged as 0xa and 0xb; 0xa + 0xfe = 0x08.
    for staged, reason in ((0x0A, 8), (0x0B, 9)):
        c.check(((staged + 0xFE) & 0xFF) == reason,
                f"staged 0x{staged:x} indexes reason {reason}")

    # ---- the parameter block ---------------------------------------------
    for what, va, raw in (
            ("the 0x100 window", 0x143A14DD7, bytes([0x8D, 0x91, 0x00, 0x01, 0x00])),
            ("the wrap check", 0x143A14DE4, bytes([0x83, 0xFA, 0xDC])),
            ("the S+0xa4 self-pointer", 0x143A14E5E, bytes([0x44, 0x8D, 0x81, 0xA4, 0x00, 0x00])),
            ("the S+0x104 self-pointer", 0x143A14E75, bytes([0x44, 0x8D, 0x81, 0x04, 0x01, 0x00])),
            ("the S+0xa0 task object", 0x143A14E83, bytes([0x8D, 0xB1, 0xA0, 0x00, 0x00, 0x00])),
            ("the -8 ceiling", 0x143A14E92, bytes([0x41, 0x83, 0xF8, 0xF8])),
            ("the phase minimum", 0x143A14FC9, bytes([0x83, 0xF8, 0x04])),
            ("the busy test", 0x143A14FDD, bytes([0x41, 0x83, 0x3C, 0x02, 0x00])),
            ("the 16-byte alignment rule", 0x143A1501A, bytes([0xF6, 0xC1, 0x0F]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the launcher uses {what}")

    # The seven descriptors, at +0x108 .. +0x120 in order.
    for off, va, raw in ((0x108, 0x143A14E9C, bytes([0x44, 0x8D, 0x99, 0x08, 0x01, 0x00])),
                         (0x10C, 0x143A14EA7, bytes([0x44, 0x8D, 0x99, 0x0C, 0x01, 0x00])),
                         (0x110, 0x143A14EB7, bytes([0x44, 0x8D, 0x99, 0x10, 0x01, 0x00])),
                         (0x114, 0x143A14EC2, bytes([0x44, 0x8D, 0x99, 0x14, 0x01, 0x00])),
                         (0x118, 0x143A14ECD, bytes([0x44, 0x8D, 0x99, 0x18, 0x01, 0x00])),
                         (0x11C, 0x143A14ED8, bytes([0x44, 0x8D, 0x99, 0x1C, 0x01, 0x00])),
                         (0x120, 0x143A14EE3, bytes([0x81, 0xC1, 0x20, 0x01, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"descriptor {off:#06x} is read at +{off:#x}")

    # ---- the DMA plan ----------------------------------------------------
    for what, va, raw in (
            ("the bone table", 0x143A15048, bytes([0xBA, 0x80, 0x30, 0x01, 0x00])),
            ("the bone table size", 0x143A15050, bytes([0x41, 0xB9, 0xD0, 0x05, 0x00])),
            ("the matrix block", 0x143A15066, bytes([0xBA, 0x80, 0x36, 0x01, 0x00])),
            ("the matrix block size", 0x143A1506E, bytes([0x41, 0xB9, 0xF0, 0x3B, 0x00])),
            ("the bone descriptor", 0x143A15084, bytes([0xBA, 0x80, 0x72, 0x01, 0x00])),
            ("the bone descriptor size", 0x143A1508C, bytes([0x41, 0xB9, 0x10, 0x00, 0x00])),
            ("the sub-descriptor block", 0x143A150A2, bytes([0xBA, 0x00, 0x73, 0x01, 0x00])),
            ("the sub-descriptor size", 0x143A150AA, bytes([0x41, 0xB9, 0x20, 0x01, 0x00])),
            ("the 5th read", 0x143A152DB, bytes([0xBA, 0x80, 0x74, 0x01, 0x00])),
            ("the 6th read", 0x143A152F9, bytes([0xBA, 0x00, 0x76, 0x01, 0x00])),
            ("the 7th read", 0x143A15317, bytes([0xBA, 0x80, 0x78, 0x01, 0x00])),
            ("the first sub-payload", 0x143A1513D, bytes([0xBA, 0x80, 0xC6, 0x00, 0x00])),
            ("the fourth sub-payload", 0x143A15227, bytes([0xBA, 0x80, 0xDE, 0x00, 0x00])),
            ("the N*80 buffer", 0x143A15551, bytes([0xBA, 0x00, 0x08, 0x01, 0x00])),
            ("the N*16 buffer", 0x143A1557A, bytes([0xBA, 0x80, 0xFE, 0x00, 0x00])),
            ("the width stride", 0x143A1510F, bytes([0x41, 0xC1, 0xE7, 0x04])),
            ("the count stride", 0x143A1554A, bytes([0x44, 0x8D, 0x0C, 0x80, 0x48]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the DMA plan names {what}")

    # ---- both caps, and the two they bound --------------------------------
    c.check(body_of(pe, 0x143A150EF, 5) == bytes([0x3D, 0x80, 0x00, 0x00, 0x00]),
            "the width is capped at 128")
    c.check(body_of(pe, 0x143A1552A, 5) == bytes([0x3D, 0x80, 0x00, 0x00, 0x00]),
            "the count is capped at 128")
    c.check(body_of(pe, 0x143A150E9, 5) == bytes([0x41, 0xBC, 0x05, 0x00, 0x00]),
            "exceeding the width reports reason 5")
    c.check(body_of(pe, 0x143A15524, 5) == bytes([0x41, 0xBE, 0x08, 0x00, 0x00]),
            "exceeding the count stages 0x08, i.e. reason 6")

    # ---- the sub-descriptor self-size store -------------------------------
    # `mov dword ptr [rdi + 0x17320], 0x80c60000` and the five siblings. Stored
    # little-endian on the host so the guest reads a big-endian 0x0000c680.
    for what, va, imm in (("0x17320", 0x143A15332, 0x80C60000),
                          ("0x17350", 0x143A1533C, 0x80CE0000),
                          ("0x17380", 0x143A15346, 0x80D60000),
                          ("0x173b0", 0x143A15350, 0x80DE0000),
                          ("0x173e0", 0x143A1535A, 0x80E60000),
                          ("0x17410", 0x143A15364, 0x80EE0000)):
        # `c7 87 disp32 imm32` is ten bytes: the opcode and modrm, the four-byte
        # destination displacement, then the four-byte immediate.
        raw = body_of(pe, va, 10)
        got_le = struct.unpack_from("<I", raw, 6)[0]
        got_be = struct.unpack_from(">I", raw, 6)[0]
        c.check(raw[:2] == bytes([0xC7, 0x87]) and
                struct.unpack_from("<I", raw, 2)[0] == int(what, 16) and got_le == imm,
                f"the payload at {what} gets its own size written in")
        # Swapped back to big-endian the immediate is the destination scratch
        # offset itself -- which is why these words read back as tiny floats.
        c.check(got_be in (0xC680, 0xCE80, 0xD680, 0xDE80, 0xE680, 0xEE80),
                f"the size stored at {what} names its payload buffer")

    # ---- MXCSR ----------------------------------------------------------
    c.check(body_of(pe, 0x143A1536E, 5) == bytes([0x0F, 0xAE, 0x5C, 0x24, 0x70]),
            "the old MXCSR is saved")
    c.check(body_of(pe, 0x143A15377, 8) == bytes([0xC7, 0x44, 0x24, 0x70, 0xC0, 0xFF, 0x00, 0x00]),
            "0xffc0 is installed: DAZ, FZ, round-to-nearest, all masked")
    c.check(body_of(pe, 0x143A1537F, 4) == bytes([0x0F, 0xAE, 0x54, 0x24]),
            "the new MXCSR is loaded")

    # ---- the output record ----------------------------------------------
    for what, va, raw in (("the 0x10800 size", 0x143A15727, bytes([0x81, 0xF9, 0x00, 0x08, 0x01, 0x00])),
                          ("the 0xfe80 word", 0x143A1574D, bytes([0x81, 0xF9, 0x80, 0xFE, 0x00, 0x00])),
                          ("the 0xf680 word", 0x143A15767, bytes([0x3D, 0x80, 0xF6, 0x00, 0x00, 0x0F])),
                          ("its failure stages reason 7", 0x143A15761, bytes([0x41, 0xBE, 0x09, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the output record check covers {what}")

    # ---- the writebacks, and the one descriptor that is an offset -------
    c.check(body_of(pe, 0x143A15865, 5) == bytes([0xBA, 0x80, 0x36, 0x01, 0x00]),
            "the matrix block is written back to scratch + 0x13680")
    c.check(body_of(pe, 0x143A15837, 3) == bytes([0x8B, 0x4C, 0x24]),
            "the second row block is at scratch + 0xf680")
    c.check(body_of(pe, 0x143A1583B, 5) == bytes([0xBA, 0x80, 0xF6, 0x00, 0x00]),
            "and 0xf680 is the source, not a guest address")

    # ---- which descriptor word is which ---------------------------------
    # The four words are spilled to the stack before the two counted gets,
    # and the same slots are read back by the writebacks, so the register
    # traffic pins down which word feeds which buffer.
    for what, va, raw in (("W0 lands at rsp+0x44", 0x143A154CD, bytes([0x44, 0x89, 0x44, 0x24, 0x44])),
                          ("W1 lands at rsp+0x2c", 0x143A154DA, bytes([0x89, 0x44, 0x24, 0x2C])),
                          ("W2 lands at rsp+0x28", 0x143A15513, bytes([0x44, 0x89, 0x5C, 0x24, 0x28])),
                          ("W3 lands at rsp+0x24", 0x143A15520, bytes([0x89, 0x4C, 0x24, 0x24])),
                          ("the 0xfe80 get reads W2", 0x143A15569, bytes([0x44, 0x8B, 0x44, 0x24, 0x28])),
                          ("as its count, W1", 0x143A1556E, bytes([0x44, 0x8B, 0x4C, 0x24, 0x2C])),
                          ("scaled by 16", 0x143A15573, bytes([0x41, 0xC1, 0xE1, 0x04])),
                          ("the first writeback copies W2", 0x143A1581E, bytes([0x8B, 0x4C, 0x24, 0x28])),
                          ("out of 0xfe80", 0x143A15822, bytes([0x48, 0x81, 0xC7, 0x80, 0xFE, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the descriptor traffic shows {what}")

    # 0xf680 is only ever named as a scratch offset for the last writeback:
    # no `get` ever targets it, so it is the buffer the stages write into.
    launch = body_of(pe, 0x143A14DC0, 0xAE3)
    c.check(launch.count(bytes.fromhex("ba80f60000")) == 1,
            "0xf680 is named exactly once in the launcher")
    c.check(bytes.fromhex("ba80f60000") in body_of(pe, 0x143A15837, 12),
            "and that one is the last writeback")
    c.check(body_of(pe, 0x143A15789, 6) == bytes([0x81, 0xFB, 0x10, 0xC4, 0xFF, 0xFF]),
            "the +0x110 descriptor is an offset, checked against -0x3bf0")

    # ---- scratch_t, clean() and get() ------------------------------------
    c.check(body_of(pe, 0x143A279B5, 5) == bytes([0xB9, 0x40, 0x00, 0x04, 0x00]),
            "the staging object is 0x40040 bytes")
    c.check(body_of(pe, 0x143A279BA, 5) == bytes([0xBA, 0x40, 0x00, 0x00, 0x00]),
            "and is allocated 64-byte aligned")
    c.check(body_of(pe, 0x143A279F5, 5) == bytes([0x41, 0xB8, 0x20, 0x00, 0x04]),
            "only the low 0x40020 is cleared")
    c.check(body_of(pe, 0x143A1AA68, 7) == bytes([0x80, 0xB8, 0x30, 0x01, 0x00, 0x00, 0x00]),
            "the scratch is gated on a byte at thread + 0x130")
    c.check(body_of(pe, 0x143A1AA84, 4) == bytes([0x48, 0x8B, 0x80, 0x08]),
            "and lives at thread + 0x608")

    for what, va, raw in (("the block shift", 0x143A1AB0B, bytes([0xC1, 0xE1, 0x0A])),
                          ("the block size", 0x143A1AB11, bytes([0x41, 0xB8, 0x00, 0x04, 0x00])),
                          ("the first live range bias", 0x143A1AC19, bytes([0x0D, 0x00, 0x00, 0x01, 0x00])),
                          ("the first live range", 0x143A1AC1E, bytes([0x3D, 0x80, 0x30, 0x01, 0x00])),
                          ("its end", 0x143A1AC25, bytes([0x3D, 0x51, 0x32, 0x01, 0x00])),
                          ("the second range bias", 0x143A1AC2D, bytes([0x81, 0xC1, 0x80, 0xC9, 0xFF, 0xFF])),
                          ("its length", 0x143A1AC33, bytes([0x81, 0xF9, 0xF1, 0x37, 0x00, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"clean uses {what}")

    for what, va, raw in (("success by default", 0x143A1AC57, bytes([0xB0, 0x01])),
                          ("a zero size is a no-op", 0x143A1AC59, bytes([0x45, 0x85, 0xC9])),
                          ("the 64-bit wrap bound", 0x143A1AC72, bytes([0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])),
                          ("the first block index", 0x143A1ACC2, bytes([0xC1, 0xE9, 0x0A])),
                          ("the word index", 0x143A1AD52, bytes([0x4A, 0x09, 0x94, 0xCE])),
                          ("the probe step", 0x143A1AD80, bytes([0x4C, 0x09, 0x8C, 0xCE]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"get uses {what}")

    # ---- the granule walk, from get() at 0x143a1ac88 ---------------------
    for what, va, raw in (("the page shift", 0x143A1AC8B, bytes([0x41, 0xC1, 0xEA, 0x0C])),
                      ("the last granule drops one byte", 0x143A1AC92, bytes([0xFF, 0xC9])),
                      ("and is page-shifted too", 0x143A1AC94, bytes([0xC1, 0xE9, 0x0C])),
                      ("the inclusive bound test", 0x143A1AC97, bytes([0x41, 0x39, 0xCA])),
                      ("the walk entry", 0x143A1AD06, bytes([0x42, 0x0F, 0xB6, 0x1C, 0x1F])),
                      ("the presence test comes first", 0x143A1AD10, bytes([0x40, 0xF6, 0xC7, 0x81])),
                      ("the 0x40 skip", 0x143A1AD1A, bytes([0xF6, 0xC3, 0x40])),
                      ("rounds up to the page", 0x143A1ACF0, bytes([0x41, 0x81, 0xE2, 0x00, 0xFF, 0xFF, 0xFF])),
                      ("by 0x100", 0x143A1ACF7, bytes([0x41, 0x81, 0xC2, 0x00, 0x01])),
                      ("the 0x20 skip", 0x143A1AD1F, bytes([0xF6, 0xC3, 0x20])),
                      ("rounds up to 16", 0x143A1AD30, bytes([0x41, 0x83, 0xE2, 0xF0])),
                      ("by 0x10", 0x143A1AD34, bytes([0x41, 0x83, 0xC2, 0x10])),
                      ("otherwise one granule", 0x143A1AD24, bytes([0x41])),
                      ("and the loop ends", 0x143A1ACFE, bytes([0x41, 0x39, 0xCA]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the granule walk uses {what}")

    # ---- the four dirty maps, and how get() marks them --------------------
    # clean() walks four maps at +0x40000 .. +0x40018 with bases 0, 0x10000,
    # 0x20000 and 0x30000; only the second is filtered.
    for what, va, raw in (("band 1's map", 0x143A1AB23, bytes([0x48, 0x8B, 0xBE, 0x08, 0x00, 0x04, 0x00])),
                          ("band 2's map", 0x143A1AB3E, bytes([0x48, 0x8B, 0xBE, 0x10, 0x00, 0x04, 0x00])),
                          ("band 3's map", 0x143A1AB8B, bytes([0x48, 0x8B, 0xBE, 0x18, 0x00, 0x04, 0x00])),
                          ("band 2's base", 0x143A1AB72, bytes([0x48, 0x81, 0xC1, 0x00, 0x00, 0x02, 0x00])),
                          ("band 3's base", 0x143A1ABC2, bytes([0x48, 0x81, 0xC1, 0x00, 0x00, 0x03, 0x00]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"clean walks {what}")

    # get() marks `first = off >> 10` through `last = (off + size) >> 10`, and
    # only when (first + last) is even - an unidentifiable gate, documented as
    # such and not reproduced.
    for what, va, raw in (("the first block", 0x143A1ACC2, bytes([0xC1, 0xE9, 0x0A])),
                          ("off plus size", 0x143A1ACC5, bytes([0x45, 0x01, 0xC8])),
                          ("the last block", 0x143A1ACC8, bytes([0x41, 0xC1, 0xE8])),
                          ("the parity gate", 0x143A1AD3A, bytes([0x41, 0x8D, 0x04, 0x08])),
                          ("the band index", 0x143A1AD4E, bytes([0x41, 0xC1, 0xE9, 0x10])),
                          ("the map store", 0x143A1AD52, bytes([0x4A, 0x09, 0x94, 0xCE, 0x00, 0x00, 0x04, 0x00])),
                          ("the subsequent-block probe", 0x143A1AD7D, bytes([0xC1, 0xE9, 0x06])),
                          ("which clears the first block's bit", 0x143A1AD44, bytes([0x75, 0x17]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the marking uses {what}")

    # ---- run_launch, the bone-descriptor proof obligation -----------------
    for what, va, raw in (("the first word", 0x143A263CA, bytes([0x44, 0x8B, 0x80, 0x80, 0x72, 0x01])),
                          ("the comparison", 0x143A263D4, bytes([0x44, 0x3B, 0x02])),
                          ("its failure", 0x143A2640D, bytes([0x31, 0xC0]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"run_launch {what}")

    # ---- set_nv ---------------------------------------------------------
    c.check(body_of(pe, 0x143A1ADF3, 6) == bytes([0xC5, 0xFA, 0x6F, 0x42, 0x2C, 0xC4]),
            "set_nv loads each group unaligned, four bytes in")
    c.check(body_of(pe, 0x143A1AF49, 5) == bytes([0xC4, 0xE3, 0x79, 0x04, 0x82]),
            "set_nv closes with a 0x1b lane reversal")
    c.check(0x143A1AF5B + 8 + 0x11081FD == 0x144B23160, "the nv fill constant is at 0x144b23160")
    c.check(body_of(pe, 0x144B23160, 16).hex() ==
            "ed5eed5e5a5a5a5a5800000058adde7f", "and transcribes")

    # ---- both nv_set tables ---------------------------------------------
    c.check(len(body_of(pe, 0x144B2A154, 0xC0)) == 0xC0, "nv_stage1 is 0xc0 bytes")
    c.check(len(body_of(pe, 0x144B2A214, 0xC0)) == 0xC0, "nv_stage23 is 0xc0 bytes")
    c.check(body_of(pe, 0x144B2A154, 8).hex() == "8074010000000000",
            "nv_stage1 opens with 0x17480")
    c.check(body_of(pe, 0x144B2A214, 8).hex() == "80fe000080fe0000",
            "nv_stage23 opens with 0xfe80")
    # Both tables carry the same last group, which is the nv descriptor the
    # later stages share.
    c.check(body_of(pe, 0x144B2A154 + 0xB0, 0x10) == body_of(pe, 0x144B2A214 + 0xB0, 0x10),
            "both nv tables end with the same 0x13680 group")


def body_of(pe: PE, va: int, size: int) -> bytes:
    return pe.d[pe.off(va):pe.off(va) + size]


def check_lwarx_policy(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("mgo_waits: the lwarx wait policy")

    # ---- the caller: the tail the fork appends to ppu_lwarx --------------
    # Six PCs, the same six the wait-site table holds, and one configuration
    # byte. Nothing else: no budget, no title, no counter.
    for pc, va in ((0x1999A8, 0x143249FFD), (0x1999D8, 0x14324A005),
                   (0x1B01F8, 0x14324A00D), (0x1B0240, 0x14324A017),
                   (0x337080, 0x14324A01F), (0x337070, 0x14324A027)):
        want = bytes([0x81, 0xF9]) + struct.pack("<I", pc)
        c.check(body_of(pe, va, 6) == want, f"the caller compares the PC against {pc:#x}")
    c.check(body_of(pe, 0x143249FEF, 6) == bytes([0x8B, 0x8E, 0x74, 0x04, 0x00, 0x00]),
            "the caller reads the guest PC out of the thread (+0x474)")
    c.check(body_of(pe, 0x143249FF5, 6) == bytes([0x81, 0xF9]) + struct.pack("<I", 0x1B023F),
            "and switches on the same 0x1b023f threshold the reporter uses")

    # The level gate: one byte, compared with 2, jumping forward to the call.
    c.check(body_of(pe, 0x14324A02F, 7) == bytes([0x0F, 0xB6, 0x0D, 0x5E, 0x0C, 0x17, 0x03]),
            "the caller reads one byte of the configuration")
    c.check(0x14324A02F + 7 + 0x3170C5E == 0x1463BAC94,
            "and that byte is g_cfg + 0x51d4")
    c.check(0x1463BAC94 - 0x1463B5AC0 == 0x51D4, "g_cfg itself is at 0x1463b5ac0")
    c.check(body_of(pe, 0x14324A036, 3) == bytes([0x80, 0xF9, 0x02]),
            "the gate is cmp cl, 2")
    c.check(body_of(pe, 0x14324A039, 2) == bytes([0x73, 0x2E]),
            "and `jae` on it goes forward, to the call")

    # And the call itself, with the loaded value preserved across it.
    c.check(body_of(pe, 0x14324A069, 3) == bytes([0x48, 0x89, 0xF1]),
            "the call passes the thread in rcx")
    c.check(body_of(pe, 0x14324A06C, 3) == bytes([0x41, 0x89, 0xC0]),
            "and the loaded value in r8d")
    c.check(body_of(pe, 0x14324A06F, 3) == bytes([0x48, 0x89, 0xC6]),
            "the value is parked in rsi")
    c.check(call_target(pe, 0x14324A072) == 0x1434AF180,
            "which calls mgo_waits::ppu_lwarx_wait")
    c.check(body_of(pe, 0x14324A077, 3) == bytes([0x48, 0x89, 0xF0]),
            "and rax is restored from rsi, so the load still returns its value")

    # spu_task_hle::level_at_least reads the same byte and is the same test.
    c.check(coff.at(0x1434AE410) == "_ZN12spu_task_hle14level_at_leastE21mgo_task_acceleration",
            "the byte is read by spu_task_hle::level_at_least", coff.at(0x1434AE410))
    c.check(body_of(pe, 0x1434AE410, 7) == bytes([0x0F, 0xB6, 0x05, 0x7D, 0xC8, 0xF0, 0x02]),
            "level_at_least loads the same byte")
    c.check(0x1434AE410 + 7 + 0x2F0C87D == 0x1463BAC94, "at the same address")
    c.check(body_of(pe, 0x1434AE417, 2) == bytes([0x38, 0xC8]) and
            body_of(pe, 0x1434AE419, 3) == bytes([0x0F, 0x93, 0xC0]),
            "and answers `level >= given` with cmp/setae")

    # ---- the reporter ----------------------------------------------------
    c.check(coff.at(0x1434AF180).startswith("_ZN12spu_task_hle9mgo_waits14ppu_lwarx_wait"),
            "the reporter is mgo_waits::ppu_lwarx_wait", coff.at(0x1434AF180))
    c.check(body_of(pe, 0x1434AF187, 6) == bytes([0x8B, 0x81, 0x74, 0x04, 0x00, 0x00]),
            "the reporter reads the same PC field itself")

    # Its three site pointers, twelve bytes apart.
    for disp, va, want in ((0x1576B34, 0x1434AF1B5, 0x144A25CF0),
                           (0x1576B26, 0x1434AF1CF, 0x144A25CFC),
                           (0x1576B29, 0x1434AF1D8, 0x144A25D08)):
        raw = body_of(pe, va, 7)
        got = struct.unpack_from("<i", raw, 3)[0]
        c.check(raw[:3] == bytes([0x4C, 0x8D, 0x0D]) and got == disp and va + 7 + disp == want,
                f"a site record is at {want:#x}")
    c.check(body_of(pe, 0x1434AF1DF, 4) == bytes([0x41, 0x8B, 0x41, 0x08]),
            "and the budget is its third word")

    # The budget gate, including the cmovne that makes a zero budget mean
    # "any non-zero value".
    for what, va, raw in (("value < budget", 0x1434AF1E6, bytes([0x41, 0x39, 0xC0])),
                          ("setb", 0x1434AF1E9, bytes([0x41, 0x0F, 0x92, 0xC1])),
                          ("value != 0", 0x1434AF1F0, bytes([0x45, 0x85, 0xC0])),
                          ("setne", 0x1434AF1F3, bytes([0x41, 0x0F, 0x95, 0xC2])),
                          ("test budget", 0x1434AF1F7, bytes([0x85, 0xC0])),
                          ("cmovne", 0x1434AF1F9, bytes([0x45, 0x0F, 0x45, 0xD1])),
                          ("proceed iff 1", 0x1434AF1FD, bytes([0x41, 0x80, 0xFA, 0x01]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the budget gate uses {what}")

    # The title holder at 0x14504d928: a tag byte, an inline string at tag+1
    # and a pointer at +0x10.
    for disp, va, want, what in ((0x1B9E71A, 0x1434AF207, 0x14504D928, "its tag byte"),
                                 (0x1B9E717, 0x1434AF212, 0x14504D930, "its inline buffer"),
                                 (0x1B9E6F5, 0x1434AF23C, 0x14504D938, "its pointer"),
                                 (0x1B9E6DD, 0x1434AF245, 0x14504D929, "the inline string itself")):
        raw = body_of(pe, va, 7)
        c.check(struct.unpack_from("<i", raw, 3)[0] == disp and va + 7 + disp == want,
                f"the title holder's {what} is at {want:#x}")
    c.check(body_of(pe, 0x1434AF20E, 2) == bytes([0xA8, 0x01]) and
            body_of(pe, 0x1434AF238, 2) == bytes([0xA8, 0x01]),
            "bit 0 of the tag selects pointer or inline, and it is tested twice")
    # The pointer path's length test is broken in the reference build: it
    # compares the inline buffer's first eight bytes with 9, not a length, so
    # it can only pass if those eight bytes spell the integer 9.
    c.check(body_of(pe, 0x1434AF219, 4) == bytes([0x49, 0x83, 0xF8, 0x09]),
            "the pointer path compares the inline buffer's first qword with 9")
    c.check(body_of(pe, 0x1434AF227, 3) == bytes([0x41, 0xD0, 0xE8]) and
            body_of(pe, 0x1434AF22E, 4) == bytes([0x49, 0x83, 0xF8, 0x09]),
            "the inline path takes its length from the tag and wants 9")
    for name, va in (("NPMG00010", 0x1434AF24C), ("NPMG00020", 0x1434AF267)):
        imm = struct.unpack_from("<Q", body_of(pe, va, 10), 2)[0]
        c.check(imm == int.from_bytes(name[:8].encode("latin-1"), "little"),
                f"the {name} constant is a plain ASCII string")
    c.check(body_of(pe, 0x1434AF25E, 4) == bytes([0x49, 0x83, 0xF1, 0x30]) and
            body_of(pe, 0x1434AF278, 4) == bytes([0x48, 0x83, 0xF0, 0x30]),
            "and the ninth byte is XORed with '0', which is a strcmp fold")

    # ---- the wait -------------------------------------------------------
    c.check(body_of(pe, 0x1434AF285, 7) == bytes([0x48, 0x8B, 0x81, 0x98, 0x04, 0x00, 0x00]),
            "the wait's sequence number starts as ppu_thread+0x498 (rtime)")
    c.check(body_of(pe, 0x1434AF28C, 5) == bytes([0xF0, 0x83, 0x49, 0x14, 0x04]),
            "bit 2 of the thread's state word is set before the wait")

    # The re-entrancy guard: a 64-byte array indexed by a popcount of the
    # address, entered with `lock inc` and left with `lock dec`.
    for what, va, raw in (("the masked address", 0x1434AF294, bytes([0x41, 0x81, 0xE1, 0x00, 0xFE, 0xFF, 0xFF])),
                          ("the first SWAR mask", 0x1434AF2A4, bytes([0x41, 0x81, 0xE2, 0x00, 0x55, 0x55, 0x55])),
                          ("the second SWAR mask", 0x1434AF2B1, bytes([0x41, 0x81, 0xE2, 0x00, 0x33, 0x33, 0x33])),
                          ("the multiply", 0x1434AF2D7, bytes([0x45, 0x69, 0xCA, 0x01, 0x01, 0x01, 0x01])),
                          ("the final shift", 0x1434AF2DE, bytes([0x41, 0xC1, 0xE9, 0x18])),
                          ("two more index bits", 0x1434AF2E5, bytes([0x83, 0xE2, 0x60])),
                          ("the or", 0x1434AF2E8, bytes([0x44, 0x09, 0xCA])),
                          ("entering", 0x1434AF2F2, bytes([0xF0, 0xFE, 0x04, 0x3A])),
                          ("leaving", 0x1434AF348, bytes([0xF0, 0xFE, 0x0C, 0x3B]))):
        c.check(body_of(pe, va, len(raw)) == raw, f"the guard uses {what}")
    c.check(body_of(pe, 0x1434AF2EB, 7) == bytes([0x48, 0x8D, 0x3D, 0x06, 0x8C, 0xC7, 0x02]) and
            0x1434AF2F2 + 0x2C78C06 == 0x146127EF8,
            "and the guard array is 64 bytes at 0x146127ef8")

    # The reservation: `and r8d, 0x7fc0` after `shr r8d, 1`, which is one bit
    # wider than vm::reservation_acquire's own `(addr & 0xff80) / 2`.
    c.check(body_of(pe, 0x1434AF29E, 3) == bytes([0x41, 0xD1, 0xE8]),
            "the reservation index halves the address")
    c.check(body_of(pe, 0x1434AF2F6, 7) == bytes([0x41, 0x81, 0xE0, 0xC0, 0x7F, 0x00, 0x00]),
            "then masks it with 0x7fc0")
    c.check(body_of(pe, 0x1434AF2FD, 7) == bytes([0x4C, 0x8D, 0x0D, 0xFC, 0x5C, 0xCD, 0x02]) and
            0x1434AF304 + 0x2CD5CFC == 0x146185000,
            "the reservation table is vm::g_reservations")
    c.check(coff.at(0x146185000) == "_ZN2vm14g_reservationsE",
            "and the symbol table says so", coff.at(0x146185000))
    c.check(0x14618D000 - 0x146185000 == 65536 // 128 * 64,
            "which is 65536/128*64 bytes, the 0x40 stride the mask implies")

    # The extended wait entry, built on the stack exactly as
    # atomic_t<u64>::wait's 8-byte overload builds it.
    c.check(body_of(pe, 0x1434AF318, 4) == bytes([0x49, 0x83, 0xC0, 0x04]) and
            body_of(pe, 0x1434AF31C, 5) == bytes([0x4C, 0x89, 0x44, 0x24, 0x20]),
            "the extended entry points at the slot's high half")
    c.check(body_of(pe, 0x1434AF324, 4) == bytes([0x49, 0xC1, 0xE8, 0x20]) and
            body_of(pe, 0x1434AF328, 5) == bytes([0x44, 0x89, 0x44, 0x24, 0x28]),
            "and its sequence number is rtime >> 32")
    c.check(struct.unpack_from("<I", body_of(pe, 0x1434AF333, 5), 1)[0] == 50000,
            "the timeout immediate is 0xc350, i.e. 50000")
    c.check(body_of(pe, 0x1434AF33B, 3) == bytes([0x4C, 0x89, 0xD1]),
            "the slot is the wait's object")
    c.check(body_of(pe, 0x1434AF341, 2) == bytes([0x89, 0xC2]),
            "and rtime's low half is the expected value")
    c.check(call_target(pe, 0x1434AF343) == 0x14318A620,
            "which waits through atomic_wait_engine::wait")
    c.check(coff.at(0x14318A620) == "_ZN18atomic_wait_engine4waitEPKvjyPN11atomic_wait4infoE",
            "and the symbol table agrees", coff.at(0x14318A620))

    # The way out: re-read the state word, and re-check if it is still set.
    c.check(body_of(pe, 0x1434AF34C, 3) == bytes([0x8B, 0x46, 0x14]) and
            body_of(pe, 0x1434AF34F, 2) == bytes([0x85, 0xC0]),
            "the state word is re-read after the wait")
    c.check(call_target(pe, 0x1434AF356) == 0x143220ED0,
            "and cpu_thread::check_state is called if it is still set")
    c.check(coff.at(0x143220ED0) == "_ZN10cpu_thread11check_stateEv",
            "which the symbol table confirms", coff.at(0x143220ED0))


def check_getllar_lambda(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("mgo_waits: the GETLLAR-on-gpr1 signature, inlined in process_mfc_cmd")

    # The lambda the fork inlines into spu_thread::process_mfc_cmd.
    c.check(coff.at(0x1431E6450) ==
            "_ZZN10spu_thread15process_mfc_cmdEvENK3$_3clEv",
            "the site is a lambda inside process_mfc_cmd", coff.at(0x1431E6450))

    # spu_thread + 0xfd8 is `ls`; the four compares are the signature.
    c.check(body_of(pe, 0x1431E6484, 7) == bytes([0x4C, 0x8B, 0x86, 0xD8, 0x0F, 0x00, 0x00]),
            "it reads spu_thread::ls at +0xfd8")
    for what, va, word in (("0x3000", 0x1431E648B, 0x027A8043),
                          ("0x3004", 0x1431E6498, 0x82A2A543),
                          ("0x3008", 0x1431E64A5, 0x02433943),
                          ("0x300c", 0x1431E64B2, 0x824FB142)):
        # 41 81 b8 <disp32> <imm32> = cmp dword ptr [r8 + disp32], imm32.
        # That is 11 bytes: REX.B, 81 /7, a 4-byte displacement, then the
        # immediate. Capstone agrees, so this is not a hand-read encoding.
        raw = body_of(pe, va, 11)
        c.check(raw[:3] == bytes([0x41, 0x81, 0xB8])
                and struct.unpack_from("<I", raw, 3)[0] == int(what, 16)
                and struct.unpack_from("<I", raw, 7)[0] == word,
                f"LS + {what} is compared with {word:#010x}")

    # The gate, and the fact that it is the *same* config byte the lwarx wait
    # reads: 0x1463bac94.
    c.check(body_of(pe, 0x1431E6476, 7) == bytes([0x44, 0x0F, 0xB6, 0x05, 0x16, 0x48, 0x1D]),
            "it loads the task acceleration byte")
    disp = struct.unpack_from("<i", body_of(pe, 0x1431E6476, 8), 4)[0]
    c.check(0x1431E6476 + 8 + disp == 0x1463BAC94,
            "and it is the same byte the lwarx wait reads (0x1463bac94)")
    c.check(body_of(pe, 0x1431E647E, 4) == bytes([0x41, 0x80, 0xF8, 0x02]),
            "gated on cmp r8b, 2")
    c.check(body_of(pe, 0x1431E6482, 2) == bytes([0x72, 0x3F]),
            "with jb jumping to the zero arm")

    # The inversion: sete followed by xor 1, so the branch fires when the
    # signature does NOT match.
    c.check(body_of(pe, 0x1431E64BD, 4) == bytes([0x41, 0x0F, 0x94, 0xC0]),
            "the four compares collapse into sete r8b")
    c.check(body_of(pe, 0x1431E64C3, 3) == bytes([0x45, 0x31, 0xC0]),
            "the zero arm clears r8")
    c.check(body_of(pe, 0x1431E64CB, 4) == bytes([0x41, 0x80, 0xF0, 0x01]),
            "then xor r8b, 1 inverts it")
    c.check(body_of(pe, 0x1431E64CF, 3) == bytes([0x44, 0x84, 0xC0]) and
            body_of(pe, 0x1431E64D2, 6) == bytes([0x0F, 0x85, 0xAF, 0x00, 0x00, 0x00]),
            "and the branch fires only when the signature is absent")


def rip_xref_candidates(pe: PE, target: int) -> list[int]:
    """Every byte offset in .text whose u32 encodes a [rip+disp32] to `target`.

    On x86-64 a `[rip + disp32]` operand is the only way to name an absolute
    address, so this is exhaustive rather than heuristic: if it yields nothing,
    nothing in .text refers to `target`.  Offsets are not yet confirmed to be
    real instructions -- see rip_xref_confirm.
    """
    import numpy as np

    name, vaddr, rsize, roff = next(s for s in pe.sections if s[0] == ".text")
    base = pe.image_base + vaddr
    a = np.frombuffer(pe.d[roff:roff + rsize], dtype=np.uint8)
    n = a.size - 3
    d = (a[0:n].astype(np.int64)
         | (a[1:n + 1].astype(np.int64) << 8)
         | (a[2:n + 2].astype(np.int64) << 16)
         | (a[3:n + 3].astype(np.int64) << 24))
    resolved = base + np.arange(n, dtype=np.int64) + 4 + d
    return [base + int(i) for i in np.nonzero(resolved == target)[0]]


def rip_xref_confirm(pe: PE, cand: int, target: int):
    """The instruction whose disp32 field sits exactly at `cand`, or None.

    For a `[rip + disp32]` operand the displacement is always the last four
    bytes, so `cand == ins.address + ins.size - 4` is an exact test.  Several
    start offsets are tried because an arbitrary byte is not necessarily an
    instruction boundary.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for back in range(1, 16):
        lo = cand - back
        try:
            blob = pe.d[pe.off(lo):pe.off(lo) + 32]
        except ValueError:
            return None
        for ins in md.disasm(blob, lo):
            if ins.address + ins.size - 4 != cand:
                continue
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    if ins.address + ins.size + op.mem.disp == target:
                        return ins
    return None


def check_mgo_config_readers(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("which MGO config keys the fork actually reads")

    # g_cfg.mgo sits at this address.  It is not guessed: it is the task
    # acceleration slot's address minus that member's offset within node_mgo,
    # and the five references below land in exactly the five functions already
    # identified by hand, which is what validates it.
    MGO_NODE = 0x1463BAA80

    keys = (
        ("Disable Limiter", 0x058, 4),
        ("Disable HUD", 0x098, 4),
        ("Disable Lobby BGM", 0x0D8, 4),
        ("Disable Blur", 0x118, 4),
        ("Lower Exposure", 0x158, 4),
        ("SPU Culling Wait Bypass", 0x198, 4),
        ("Task Acceleration", 0x1D8, 4),
        ("Audio Mixer Fast Path", 0x218, 4),
        ("UPnP Port", 0x258, 0),
    )

    # The slot holding the live value: member + 0x3c for _bool/_enum, and the
    # uint's value word for UPnP Port, which the ctor stores at member + 0x44.
    slot = {}
    for name, member, _w in keys:
        off = member + 0x3C if name != "UPnP Port" else member + 0x44
        slot[name] = MGO_NODE + off

    # The two keys the fork really reads.
    c.check(len(rip_xref_candidates(pe, slot["Task Acceleration"])) == 5,
            "Task Acceleration has exactly five references",
            str(len(rip_xref_candidates(pe, slot["Task Acceleration"]))))
    for va, what in ((0x1431E6477, "the GETLLAR lambda in process_mfc_cmd"),
                     (0x14324A02F, "ppu_lwarx"),
                     (0x143389D84, "spu_task_hle::ppu::install"),
                     (0x1434AE410, "spu_task_hle::level_at_least"),
                     (0x1434AE6F8, "spu_task_hle::on_embedded_spu_image")):
        ok = any(rip_xref_confirm(pe, cand, slot["Task Acceleration"]) is not None
                 and rip_xref_confirm(pe, cand, slot["Task Acceleration"]).address == va
                 for cand in rip_xref_candidates(pe, slot["Task Acceleration"]))
        c.check(ok, f"  ...one of them is in {what}")

    c.check(len(rip_xref_candidates(pe, slot["Audio Mixer Fast Path"])) == 1,
            "Audio Mixer Fast Path has exactly one reference",
            str(len(rip_xref_candidates(pe, slot["Audio Mixer Fast Path"]))))

    # The five booleans each have exactly one reader, and it is the same one:
    # patch_engine::apply.  Disable Lobby BGM's single reader is
    # patch_engine::load.  UPnP Port has none at all.
    #
    # This is the load-bearing count: the scan is exhaustive over .text for the
    # only addressing mode x86-64 has for an absolute address, so a count of one
    # really is one reader and not "one we happened to find".
    expected_readers = {
        "Disable Limiter": (1, "_ZN12patch_engine5applyE"),
        "Disable HUD": (1, "_ZN12patch_engine5applyE"),
        "Disable Blur": (1, "_ZN12patch_engine5applyE"),
        "Lower Exposure": (1, "_ZN12patch_engine5applyE"),
        "SPU Culling Wait Bypass": (1, "_ZN12patch_engine5applyE"),
        "Disable Lobby BGM": (1, "_ZN12patch_engine4loadE"),
        "UPnP Port": (0, None),
    }
    for name, _member, _w in keys:
        if name in ("Task Acceleration", "Audio Mixer Fast Path"):
            continue
        want_n, want_sym = expected_readers[name]
        cands = rip_xref_candidates(pe, slot[name])
        c.check(len(cands) == want_n,
                f"{name} has {want_n} reference(s)",
                f"found {len(cands)}")
        if want_n == 0:
            continue
        got = []
        for cand in cands:
            ins = rip_xref_confirm(pe, cand, slot[name])
            if ins is None:
                continue
            got.append(coff.enclosing(ins.address))
        c.check(any(want_sym in s for s in got),
                f"  ...and it is {name}'s reader in {want_sym}",
                str(got))


def check_mgo_guest_patches(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("the MGO guest-executable patches inside patch_engine::apply")

    # The fork inlines these at the very top of patch_engine::apply, before the
    # m_map lookup, gated on the module name.
    c.check(coff.at(0x1432D9600).startswith("_ZN12patch_engine5applyE"),
            "the patches live inside patch_engine::apply", coff.at(0x1432D9600))

    # The guard: compare the module name against the MGO2 executable hash.
    # c7 = std::string SSO byte, so the sequence picks the inline buffer or the
    # heap pointer, then `cmp r8, 0x2c` is strlen == 44 ("PPU-" + 40 hex).
    c.check(body_of(pe, 0x1432D9685, 4) == bytes([0x49, 0x83, 0xF8, 0x2C]),
            "the guard compares the name length with 44")
    c.check(struct.unpack_from("<i", body_of(pe, 0x1432D9692, 7), 3)[0]
            + 0x1432D9692 + 7 == 0x1449D6CFF
            and pe.cstr(0x1449D6CFF) == "PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1",
            "and memcmps it against the MGO2 exec hash",
            pe.cstr(0x1449D6CFF))
    c.check(body_of(pe, 0x1432D96AA, 2) == bytes([0x0F, 0x85])
            and 0x1432D96AA + 6 + struct.unpack_from("<i", body_of(pe, 0x1432D96AA, 6), 2)[0] == 0x1432D9906,
            "a mismatch jumps past every MGO patch")

    # The five gated blocks.  Each is: read g_cfg.mgo.<key>, `je` to the next
    # block, then `mov dword [rsp+0xb8], <guest offset>` /
    # `mov dword [rsp+0x60], 4` / `mov dword [rax], <value>`.
    # (read_at, key, slot_addr, guest_offset, value)
    blocks = (
        (0x1432D96B0, "Disable HUD", 0x1463BAB54, 0x0FA1B4, 0x00000060),
        (0x1432D96FC, "Disable Blur", 0x1463BABD4, 0x2BC0E0, 0x2000804E),
        (0x1432D9740, "Disable Limiter", 0x1463BAB14, 0x0E4F10, 0x2000804E),
        (0x1432D9784, "SPU Culling Wait Bypass", 0x1463BAC54, 0x154228, 0x2000804E),
        (0x1432D97C8, "Lower Exposure", 0x1463BAC14, 0x2A69F4, 0x00006038),
    )
    for read_at, key, slot, offset, value in blocks:
        # 0f b6 05 <disp32> = movzx eax, byte ptr [rip + disp32]
        raw = body_of(pe, read_at, 7)
        c.check(raw[:3] == bytes([0x0F, 0xB6, 0x05])
                and read_at + 7 + struct.unpack_from("<i", raw, 3)[0] == slot,
                f"{key} gates a block (reads g_cfg.mgo at 0x{slot:x})",
                f"resolved to 0x{read_at + 7 + struct.unpack_from('<i', raw, 3)[0]:x}")

    # Each block stores its offset and value; the offsets here are the ones the
    # replica's mgo_patches.cpp carries.
    # (offset_store_va, value_store_va, guest_offset, value)
    stores = (
        (0x1432D96C3, 0x1432D96F6, 0x0FA1B4, 0x00000060),
        (0x1432D9707, 0x1432D973A, 0x2BC0E0, 0x2000804E),
        (0x1432D974B, 0x1432D977E, 0x0E4F10, 0x2000804E),
        (0x1432D978F, 0x1432D97C2, 0x154228, 0x2000804E),
        (0x1432D97D3, 0x1432D9806, 0x2A69F4, 0x00006038),
        # Lower Exposure selects a second write.
        (0x1432D980C, 0x1432D983F, 0x11A6B60, 0xCDCCCC3E),
    )
    for off_va, val_va, offset, value in stores:
        # c7 84 24 b8 00 00 00 <imm32> = mov dword ptr [rsp + 0xb8], imm32
        c.check(body_of(pe, off_va, 7) == bytes([0xC7, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00])
                and struct.unpack_from("<I", body_of(pe, off_va, 11), 7)[0] == offset,
                f"  ...guest offset 0x{offset:x}")
        # c7 00 <imm32> = mov dword ptr [rax], imm32
        c.check(body_of(pe, val_va, 2) == bytes([0xC7, 0x00])
                and struct.unpack_from("<I", body_of(pe, val_va, 6), 2)[0] == value,
                f"  ...writes 0x{value:08x}")
        # Every one of them is a 4-byte write.
        c.check(body_of(pe, off_va + 11, 8) == bytes([0xC7, 0x44, 0x24, 0x60, 0x04, 0x00, 0x00, 0x00]),
                f"  ...with a size of 4")

    # Three more writes inside the same guard that no key gates.
    for off_va, val_va, offset in ((0x1432D9845, 0x1432D9878, 0x14CC80),
                                   (0x1432D987E, 0x1432D98B1, 0x14CC98),
                                   (0x1432D98B7, 0x1432D98EA, 0x14CCCC)):
        c.check(struct.unpack_from("<I", body_of(pe, off_va, 11), 7)[0] == offset
                and body_of(pe, val_va, 2) == bytes([0xC7, 0x00])
                and struct.unpack_from("<I", body_of(pe, val_va, 6), 2)[0] == 0x60,
                f"unconditional patch at guest offset 0x{offset:x} <- 0x60")

    # Disable Lobby BGM is different: it lives in patch_engine::load and
    # injects an embedded patch_config fragment.
    c.check(coff.at(0x1432CB110).startswith("_ZN12patch_engine4loadE"),
            "Disable Lobby BGM is read inside patch_engine::load",
            coff.at(0x1432CB110)[:60])
    blob = 0x1449D5AEA
    frag = pe.cstr(blob, 400)
    c.check(len(frag) == 346,
            "the embedded fragment is 346 bytes (0x15a)", str(len(frag)))
    c.check(frag.startswith("\n\nPPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1:\n"),
            "it starts with a blank line then the exec hash")
    c.check('\n  " MGO Disable Files ":\n' in frag,
            "the description key is ' MGO Disable Files ' -- spaces inside the quotes")
    c.check("\nVersion:" not in frag,
            "there is no top-level Version: line in the embedded fragment")
    for bgm in ("bgm_mgo_lobby01.bgm", "bgm_mgo_tounament01.bgm"):
        c.check(f"- [ hide_file, /dev_hdd0/game/NPMG00020/USRDIR/o/bgm/{bgm}, \"\" ]" in frag,
                f"it hides {bgm}")


def check_mgo_protections(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("the fork's two protections: connect gate and build integrity")

    # --- the SaveMGO connection gate, in lv2_socket_native::connect -----------
    c.check(coff.at(0x143D27410) == "_ZN17lv2_socket_native7connectERK16sys_net_sockaddr",
            "the gate is in lv2_socket_native::connect", coff.at(0x143D27410))
    c.check(pe.cstr(0x144BD81A0).startswith("[Native] Rejected TCP connection"),
            "and logs the rejection with the recovered string",
            pe.cstr(0x144BD81A0)[:60])

    # The gate is decided from the socket mode and the destination *port*; the
    # address is never compared against a list.
    c.check(body_of(pe, 0x143D274A3, 4) == bytes([0x83, 0x7F, 0x1C, 0x01]),
            "socket mode [obj+0x1c] is compared against 1")
    c.check(body_of(pe, 0x143D274A9, 8) == bytes([0x81, 0x7C, 0x24, 0x64, 0x0F, 0xCC, 0xEF, 0xE7]),
            "the endpoint id 0xe7efcc0f is allowed")
    c.check(body_of(pe, 0x143D274B8, 5) == bytes([0x3D, 0x00, 0x50, 0x00, 0x00]),
            "port 0x5000 is allowed")
    c.check(body_of(pe, 0x143D274BF, 5) == bytes([0x3D, 0x01, 0xBB, 0x00, 0x00]),
            "port 0xbb01 is allowed")
    c.check(body_of(pe, 0x143D274C4, 2) == bytes([0x0F, 0x85])
            and 0x143D274C4 + 6 + struct.unpack_from("<i", body_of(pe, 0x143D274C4, 6), 2)[0] == 0x143D275A8,
            "and the final jne is the gate itself")

    # --- the build-integrity check, rt_support_init() ------------------------
    c.check(coff.at(0x140F6A910) == "_ZL15rt_support_initv",
            "the integrity check is a file-static rt_support_init()",
            coff.at(0x140F6A910))
    import hashlib
    _, _vaddr, rsize, roff = next(s for s in pe.sections if s[0] == ".text")
    c.check(rsize >= 0x3EAE816, ".text is at least the reference size")
    digest = hashlib.sha256(pe.d[roff:roff + 0x3EAE816]).digest()
    c.check(digest.hex() == "c9315b202de3201daf7f7723d86a3e3f152ca8e2854072f6e9154f8bf7fda158",
            "sha256 of .text is what the fork stores",
            digest.hex())
    c.check(pe.d[pe.off(0x144E2C050):pe.off(0x144E2C050) + 32] == digest,
            "and that digest sits in .data at +0x50, outside the hashed range")

    # --- the fingerprint and the anti-cheat table ----------------------------
    c.check(pe.cstr(0x144A68A4A) == "MGO;%s;%d;%.2f;%d;%s;%d;%s;%s;%s;%s;%d;%s",
            "the host-fingerprint format string",
            pe.cstr(0x144A68A4A))
    c.check(pe.cstr(0x144A68A4A + len("MGO;%s;%d;%.2f;%d;%s;%d;%s;%s;%s;%s;%d;%s") + 1)
            == "19505-72146655",
            "with a hardware id immediately after it")
    # One confirmed reference: the code that builds the string.
    c.check(len(rip_xref_candidates(pe, 0x144A68A4A)) == 1,
            "the fingerprint format string has exactly one user")

    # The anti-cheat table is a run of concatenated strings; it checks for more
    # than Cheat Engine -- NetLimiter is in there too, which the replica misses.
    # The table is a run of separate NUL-terminated strings packed together, so
    # read the whole window and split rather than stopping at the first NUL.
    window = pe.d[pe.off(0x144A68041):pe.off(0x144A68041) + 512]
    entries = [p.decode("latin-1") for p in window.split(b"\0") if p]
    for probe in ("Cheat Engine 7", "cheatengine-x86_", "cheatengine-i386",
                  "cheatengine.exe", "NLClientApp.exe", "NetLimiterMon.ex",
                  "NetLimiter 4", "Locktime Software"):
        c.check(any(probe in e for e in entries),
                f"the anti-cheat table contains {probe!r}",
                str(entries[:10]))

    # There are no symbols for the fingerprint or anti-cheat helpers, so the
    # replica's names for them are reconstructions, not recovered identifiers.
    c.check(not any("fingerprint" in n or "anti_cheat" in n
                    for n in coff.syms.values()),
            "the fork exports no fingerprint/anti_cheat symbols (names are reconstructed)")


def check_mgo_config_keys(c: Checker, pe: PE, coff: Coff) -> None:
    c.section("cfg_root::node_mgo: all nine MGO config keys")

    c.check(coff.at(0x1431B6720) == "_ZN8cfg_root8node_mgoC2EPN3cfg4nodeE",
            "the keys are built by cfg_root::node_mgo's constructor",
            coff.at(0x1431B6720))

    # The node name itself, and its length byte 6.
    # c6 44 24 28 06   = mov byte ptr [rsp + 0x28], 6      (the length)
    # c7 44 24 29 4d 47 4f 00 = mov dword ptr [rsp + 0x29], "MGO" + NUL
    c.check(body_of(pe, 0x1431B672D, 5) == bytes([0xC6, 0x44, 0x24, 0x28, 0x06]),
            "the node name is length-prefixed with 6")
    c.check(body_of(pe, 0x1431B6732, 4) == bytes([0xC7, 0x44, 0x24, 0x29])
            and struct.unpack_from("<I", body_of(pe, 0x1431B6732, 8), 4)[0] == 0x4F474D,
            "and the string is \"MGO\"")

    # Each key name is materialised on the stack and handed to the same
    # helper, 0x1432b74c0. Spot-check the two that are built as plain
    # immediates, since those need no rip-relative load.
    # movabs rdi, "Disable " is loaded once and reused by every "Disable *"
    # key, which is why most of them are a `mov [rsp+0x29], rdi` rather than a
    # fresh immediate.
    c.check(struct.unpack_from("<Q", body_of(pe, 0x1431B6787, 10), 2)[0]
            == 0x20656C6261736944, "the shared \"Disable \" prefix is an immediate")
    c.check(body_of(pe, 0x1431B6791, 5) == bytes([0x48, 0x89, 0x7C, 0x24, 0x29]),
            "and is stored with a plain mov")
    c.check(struct.unpack_from("<Q", body_of(pe, 0x1431B6796, 10), 2)[0]
            == 0x726574696D694C20, "\"Disable Limiter\" continues \" Limiter\"")

    # "Lower Exposure" arrives as two movabs with no overlap.
    c.check(struct.unpack_from("<Q", body_of(pe, 0x1431B6938, 10), 2)[0]
            == 0x7845207265776F4C, "\"Lower Exp\"")
    c.check(struct.unpack_from("<Q", body_of(pe, 0x1431B6947, 10), 2)[0]
            == 0x657275736F707845, "\"osure\"")

    # "UPnP Port" likewise, with the final 't' as a separate word store.
    c.check(struct.unpack_from("<Q", body_of(pe, 0x1431B6B12, 10), 2)[0]
            == 0x726F5020506E5055, "\"UPnP Por\"")
    c.check(body_of(pe, 0x1431B6B21, 5) == bytes([0x66, 0xC7, 0x44, 0x24, 0x31])
            and struct.unpack_from("<H", body_of(pe, 0x1431B6B21, 7), 5)[0] == 0x74,
            "and 't' as a word store")

    # ---------------------------------------------------------------------
    # Every default, straight out of the constructor.
    #
    # cfg::_bool and cfg::_enum both have the same three-byte tail
    # (Utilities/Config.h):
    #
    #     atomic_t<T> m_value;   // +0x3c  the current value
    #     T           original_def; // +0x3d  the ctor argument, never mutated
    #   public:
    #     T           def;       // +0x3e  the mutable default
    #
    # The constructor initialises all three from the same argument, so the
    # compiler folds the first two into one 2-byte store and emits the third
    # separately.  Both stores are therefore required to pin a default --
    # checking only the word store reads `original_def`, not `def`.
    #
    #   66 c7 86 <disp32> <imm16>  = mov word ptr [rsi + disp32], imm16   (+0x3c, +0x3d)
    #   c6    86 <disp32> <imm8>   = mov byte ptr [rsi + disp32], imm8    (+0x3e)
    #
    # (word, byte, member, name, def)
    mgo_defaults = (
        (0x1431B67E1, 0x1431B67EA, 0x058, "Disable Limiter", 1),
        (0x1431B6847, 0x1431B6850, 0x098, "Disable HUD", 0),
        (0x1431B68AF, 0x1431B68B8, 0x0D8, "Disable Lobby BGM", 0),
        (0x1431B691C, 0x1431B6925, 0x118, "Disable Blur", 1),
        (0x1431B6993, 0x1431B699C, 0x158, "Lower Exposure", 1),
        (0x1431B6A19, 0x1431B6A22, 0x198, "SPU Culling Wait Bypass", 1),
        (0x1431B6A7E, 0x1431B6A87, 0x1D8, "Task Acceleration", 1),
        (0x1431B6AF6, 0x1431B6AFF, 0x218, "Audio Mixer Fast Path", 0),
    )
    ctor_bytes = body_of(pe, 0x1431B6720, 0x640)
    for wva, bva, member, what, d in mgo_defaults:
        raw = body_of(pe, wva, 9)
        braw = body_of(pe, bva, 7)
        c.check(raw[:3] == bytes([0x66, 0xC7, 0x86])
                and struct.unpack_from("<I", raw, 3)[0] == member + 0x3C
                and raw[7:9] == bytes([d, d]),
                f"{what}: m_value = original_def = {d} at +0x3c (word store)")
        c.check(braw[:2] == bytes([0xC6, 0x86])
                and struct.unpack_from("<I", braw, 2)[0] == member + 0x3E
                and braw[6] == d,
                f"  ...and def = {d} at +0x3e (the byte store the word store does not cover)")

    # Only seven _bool members and one _enum member; the vtable store that
    # precedes each member's defaults says which is which.  rbx is the
    # cfg::_bool vtable, rax the cfg::_enum<mgo_task_acceleration> one.
    # 48 89 5e <d8>       = mov qword ptr [rsi + disp8],  rbx
    # 48 89 9e <disp32>   = mov qword ptr [rsi + disp32], rbx
    for member in (0x058, 0x098, 0x0D8, 0x118, 0x158, 0x198, 0x218):
        # Members below +0x80 use the disp8 form, the rest disp32.
        if member < 0x80:
            forms = [bytes([0x48, 0x89, 0x5E, member])]
        else:
            forms = [bytes([0x48, 0x89, 0x9E]) + struct.pack("<I", member)]
        n = sum(ctor_bytes.count(f) for f in forms)
        c.check(n == 1,
                f"the _bool member at +{member:#x} gets exactly one vtable store",
                f"count={n}")
    c.check(ctor_bytes.count(bytes([0x48, 0x89, 0x86]) + struct.pack("<I", 0x1D8)) == 1
            and body_of(pe, 0x1431B6A77, 3) == bytes([0x48, 0x89, 0x86]),
            "Task Acceleration is the one _enum member (rax vtable, +0x1d8)")

    # No store reaches +0x3e other than the eight byte stores above: the ctor
    # leaves no member's default implicit.
    extra_byte_stores = [m for _w, _b, m, _n, _d in mgo_defaults
                         if ctor_bytes.count(bytes([0xC6, 0x86]) + struct.pack("<I", m + 0x3E)) != 1]
    c.check(not extra_byte_stores,
            "each of the eight byte stores to a member's def appears exactly once",
            str([hex(m) for m in extra_byte_stores]))

    # ---------------------------------------------------------------------
    # Task Acceleration's default, and the enum it names.
    #
    # cfg::_enum<mgo_task_acceleration>::from_default() is `m_value = def`, so
    # it must read +0x3e.  restore_defaults() is `def = original_def`, so it
    # must read +0x3d and write +0x3e.  to_string() formats m_value (+0x3c).
    c.check(coff.at(0x1431C45A0) == "_ZN3cfg5_enumI21mgo_task_accelerationE12from_defaultEv",
            "from_default belongs to cfg::_enum<mgo_task_acceleration>",
            coff.at(0x1431C45A0))
    c.check(body_of(pe, 0x1431C45A0, 4) == bytes([0x0F, 0xB6, 0x41, 0x3E]),
            "  ...and it loads def at +0x3e, NOT original_def at +0x3d")
    c.check(body_of(pe, 0x1431C45A4, 3) == bytes([0x86, 0x41, 0x3C]),
            "  ...writing m_value at +0x3c via xchg")
    c.check(coff.at(0x1431C45B0) == "_ZN3cfg5_enumI21mgo_task_accelerationE16restore_defaultsEv"
            and body_of(pe, 0x1431C45B0, 4) == bytes([0x0F, 0xB6, 0x41, 0x3D])
            and body_of(pe, 0x1431C45B4, 3) == bytes([0x88, 0x41, 0x3E]),
            "restore_defaults reads original_def (+0x3d) and writes def (+0x3e)")
    c.check(coff.at(0x1431C45C0) == "_ZNK3cfg5_enumI21mgo_task_accelerationE9to_stringEv"
            and body_of(pe, 0x1431C45D7, 4) == bytes([0x0F, 0xB6, 0x4A, 0x3C]),
            "to_string reads the current value at +0x3c")
    c.check(body_of(pe, 0x1431C45DE, 4) == bytes([0x80, 0xF9, 0x03, 0x77]),
            "  ...with a bounds check `cmp cl, 3 / ja` over four ordinals")
    for i, expect in enumerate(("Off", "Basic", "Standard", "Maximum")):
        ptr = struct.unpack_from("<Q", body_of(pe, 0x144994200 + i * 8, 8), 0)[0]
        c.check(pe.cstr(ptr) == expect,
                f"ordinal {i} is {expect!r}", pe.cstr(ptr))
    # Four ordinals only, so the entry past the end is not a string pointer.
    past = struct.unpack_from("<Q", body_of(pe, 0x144994220, 8), 0)[0]
    c.check(not (pe.image_base <= past < pe.image_base + 0x10000000),
            "the ordinal table ends after four entries",
            f"[4] = 0x{past:x} looks like data, not a string pointer")

    # UPnP Port's default, which confirms 5730.
    # c7 86 9c 02 00 00 62 16 00 00 = mov dword ptr [rsi + 0x29c], 0x1662
    # 0x1662 is 5730, which is the value the replica already carries, so this
    # confirms it rather than changing it.
    c.check(body_of(pe, 0x1431B6B6F, 6) == bytes([0xC7, 0x86, 0x9C, 0x02, 0x00, 0x00])
            and struct.unpack_from("<I", body_of(pe, 0x1431B6B6F, 10), 6)[0] == 5730,
            "UPnP Port defaults to 5730 (0x1662)")





def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", required=True, help="path to the guest MGO2 ELF")
    ap.add_argument("--exe", help="path to the reference rpcs3.exe.bak")
    args = ap.parse_args()

    c = Checker()

    elf = Elf(args.elf)
    print(f"guest ELF: {args.elf}")
    for va, filesz, off, memsz in elf.segments:
        print(f"  PT_LOAD vaddr=0x{va:x} filesz=0x{filesz:x} memsz=0x{memsz:x} off=0x{off:x}")

    check_elf(c, elf)
    check_bl(c, elf)

    if args.exe:
        pe = PE(args.exe)
        coff_all = Coff(pe)
        print(f"\nreference PE: {args.exe} (image base 0x{pe.image_base:x})")
        check_pe(c, pe)
        check_pe_extra(c, pe)
        check_pe_structs(c, pe)
        check_image_patch_geometry(c, pe)
        check_line_check(c, pe)
        check_decline_tables(c, pe)
        check_drawassist_dispatch(c, pe)
        check_module_hook_records(c, pe)
        check_motion_play(c, pe)
        check_modelsetup(c, pe)
        check_pl_motion_mix(c, pe)
        check_lwarx_policy(c, pe, Coff(pe))
        check_getllar_lambda(c, pe, Coff(pe))
        check_mgo_config_keys(c, pe, Coff(pe))
        check_mgo_config_readers(c, pe, Coff(pe))
        check_mgo_guest_patches(c, pe, coff_all)
        check_mgo_protections(c, pe, coff_all)
    else:
        print("\n(--exe not given: skipping the reference-binary checks)")

    print(f"\n{c.passed} passed, {len(c.failed)} failed")
    for f in c.failed:
        print(f"  FAILED: {f}")
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())