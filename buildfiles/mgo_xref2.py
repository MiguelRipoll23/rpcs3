"""Find rip-relative xrefs to an absolute address, scanning only named function bodies.

    python buildfiles/mgo_xref2.py 0x1463AAB14

Decoding whole .text linearly is both slow and wrong at padding, so this walks
the COFF symbol table instead: every MGO/rpcs3 function has an exact start, and
rip-relative operands are essentially always inside one.  An address reached
only from a jump table or an unnamed thunk will be missed, which is stated in
the output rather than hidden.
"""
import struct
import sys
from collections import defaultdict

sys.path.insert(0, "buildfiles")
from mgo_verify_re import PE, Coff  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_MEM, X86_REG_RIP  # noqa: E402

EXE = r"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak"
pe = PE(EXE)
coff = Coff(pe)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Only .text, and only bodies that start on a symbol we know.
text = next(s for s in pe.sections if s[0] == ".text")
_, tvaddr, tsize, troff = text
lo = pe.image_base + tvaddr
hi = lo + tsize

syms = sorted((va for va in coff.syms if lo <= va < hi))
# drop symbols that land inside another symbol's range (labels, thunks)
starts = []
for va in syms:
    if not starts or va - starts[-1][0] >= 4:
        starts.append((va, 1))
    else:
        starts[-1] = (starts[-1][0], starts[-1][1] + 1)

CAP = 0x20000
buckets = defaultdict(list)

# NOTE: deliberately no `break` on `ret`.  Most x86 functions have several exit
# paths, and an early `ret` is usually not the last one, so stopping there would
# silently drop every instruction after the first branch and manufacture false
# "no readers" results.  Bodies are bounded by the next symbol instead.
for i, (va, _) in enumerate(starts):
    end = starts[i + 1][0] if i + 1 < len(starts) else lo + tsize
    end = min(end, va + CAP)
    try:
        off = pe.off(va)
    except ValueError:
        continue
    for ins in md.disasm(pe.d[off:off + (end - va)], va):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                buckets[tgt].append((va, coff.at(va), f"{ins.mnemonic} {ins.op_str}"))

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        t = int(arg, 0)
        print(f"\n=== xrefs to 0x{t:x} ===")
        hits = buckets.get(t, [])
        if not hits:
            print("  (none found inside a named function body)")
        for va, nm, txt in hits:
            print(f"  in 0x{va:x} {nm}\n      {txt}")
    print(f"\n(scanned {len(starts)} named bodies; {len(buckets)} distinct rip targets)")