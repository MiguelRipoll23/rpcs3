"""Resolve an MGO function by demangled name in the reference binary and dump it.

    python buildfiles/mgo_fn.py write_list::add16
    python buildfiles/mgo_fn.py --find root_track        # substring search
    python buildfiles/mgo_fn.py --raw 0x143ce3030 0x40    # hexdump at an address

Because the reference build is unstripped, every MGO function can be named, and
the address is exact -- there is no guessing about where a body starts or ends.
"""
import re
import struct
import subprocess
import sys

sys.path.insert(0, "buildfiles")
from mgo_verify_re import PE, Coff  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

EXE = r"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak"
_pe = PE(EXE)
_coff = Coff(_pe)
_md = Cs(CS_ARCH_X86, CS_MODE_64)


def _demangle(names):
    if not names:
        return []
    out = subprocess.run(["c++filt"], input="\n".join(names),
                         capture_output=True, text=True).stdout.split("\n")
    return out


def table():
    """All symbols as a list of (va, demangled_name), sorted by address."""
    items = sorted(_coff.syms.items())
    return list(zip((v for v, _ in items), _demangle([n for _, n in items])))


def find(substr):
    pat = re.compile(substr)
    return [(va, nm) for va, nm in table() if pat.search(nm)]


def resolve(name):
    """Exact demangled-name match, or the single unique substring match."""
    hits = find(re.escape(name) + r"\b")
    if len(hits) == 1:
        return hits[0]
    hits = find(name)
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise SystemExit(f"no symbol matching {name!r}")
    for va, nm in hits[:12]:
        print(f"  0x{va:x}  {nm}")
    raise SystemExit(f"{name!r} is ambiguous ({len(hits)} matches)")


def body_len(va, cap=0x4000):
    """Next symbol address in the same section, or `cap`."""
    for other, _ in table():
        if other > va:
            return min(other - va, cap)
    return cap


def disasm(va, length=None):
    n = length or body_len(va)
    off = _pe.off(va)
    out = []
    for ins in _md.disasm(_pe.d[off:off + n], va):
        out.append(ins)
        if ins.mnemonic.startswith("ret"):
            break
    return out


def show(va, length=None):
    print(f"=== 0x{va:x}  (body {body_len(va):#x} to next symbol) ===")
    for ins in disasm(va, length):
        print(f"  0x{ins.address:x}  {ins.bytes.hex():<30} {ins.mnemonic} {ins.op_str}")


def hexdump(va, n=64):
    off = _pe.off(va)
    for i in range(0, n, 16):
        chunk = _pe.d[off + i:off + i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        print(f"  0x{va+i:x}  {hx:<48} {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--find"]:
        for va, nm in find(args[1]):
            print(f"0x{va:x}  {nm}")
    elif args[:1] == ["--raw"]:
        hexdump(int(args[1], 0), int(args[2], 0) if len(args) > 2 else 64)
    elif args[:1] == ["--near"]:
        va = int(args[1], 0)
        for other, nm in table():
            if abs(other - va) <= 0x4000:
                print(f"  {'<<' if other == va else '  '} 0x{other:x}  {nm}")
    else:
        va, nm = resolve(args[0])
        print(f"--- {nm}")
        show(va)