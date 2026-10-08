"""Exhaustive rip-relative xref scan for absolute globals.

    python buildfiles/mgo_xref3.py 0x1463AAB14 0x1463BAC94

Why this instead of disassembling every function: on x86-64 the *only* way to
name an absolute address is `[rip + disp32]`.  So a reference to T from an
instruction whose ModRM+disp32 ends at byte offset j is simply

    T = (insn_end_va) + read_u32(j),  where insn_end_va = j + 4

which can be evaluated at every offset in the section with numpy, with no
disassembly and therefore no missed functions, no `ret`-boundary heuristics and
no dependence on the symbol table.  Every hit is then confirmed by decoding the
instruction it actually sits in.

Caveat, stated rather than hidden: a hit can still be a false positive, because
any four consecutive bytes that happen to encode the right displacement match.
Confirmation by decode is what separates the two.  Accesses through a register
holding a pointer are not rip-relative and are out of scope.
"""
import struct
import sys

import numpy as np

sys.path.insert(0, "buildfiles")
from mgo_verify_re import PE, Coff  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_MEM, X86_REG_RIP  # noqa: E402

EXE = r"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak"
pe = PE(EXE)
coff = Coff(pe)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def text_span():
    name, vaddr, rsize, roff = next(s for s in pe.sections if s[0] == ".text")
    return pe.image_base + vaddr, pe.d[roff:roff + rsize]


def scan(targets):
    base, buf = text_span()
    a = np.frombuffer(buf, dtype=np.uint8)
    n = a.size - 3
    d = (a[0:n].astype(np.int64)
         | (a[1:n + 1].astype(np.int64) << 8)
         | (a[2:n + 2].astype(np.int64) << 16)
         | (a[3:n + 3].astype(np.int64) << 24))
    insn_end = base + np.arange(n, dtype=np.int64) + 4
    resolved = insn_end + d
    out = {}
    for t in targets:
        idx = np.nonzero(resolved == t)[0]
        out[t] = [base + int(i) for i in idx]
    return out


def confirm(cand, target):
    """Return the real instruction whose disp32 field sits exactly at `cand`.

    For a `[rip + disp32]` operand the displacement is always the last four
    bytes of the instruction, so `cand == ins.address + ins.size - 4` is an exact
    test rather than a windowed guess.  Several start offsets are tried because
    an arbitrary byte is not necessarily an instruction boundary.
    """
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


if __name__ == "__main__":
    targets = [int(x, 0) for x in sys.argv[1:]]
    found = scan(targets)
    total = 0
    for t in targets:
        hits = found[t]
        real = []
        for cand in hits:
            ins = confirm(cand, t)
            if ins is not None:
                real.append((ins.address, coff.at(ins.address),
                             f"{ins.mnemonic} {ins.op_str}"))
        print(f"\n=== 0x{t:x}: {len(hits)} raw candidates, {len(real)} confirmed ===")
        for va, nm, txt in real:
            print(f"  0x{va:x} {nm}\n      {txt}")
        total += len(real)
    print(f"\n{total} confirmed references total")