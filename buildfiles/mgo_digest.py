"""Compute the expected .text SHA-256 for a built rpcs3 and re-stamp the source.

The integrity check in rpcs3/Emu/mgo/mgo_integrity.cpp compares the running image's
.text against a compile-time constant, exactly as the fork does.  That constant
is therefore a property of the *binary*, not of the source tree: any edit that
changes .text invalidates it and the build will abort at startup.

    python buildfiles/mgo_digest.py --exe build/bin/rpcs3.exe            # report
    python buildfiles/mgo_digest.py --exe build/bin/rpcs3.exe --stamp    # rewrite

The hashed range is min(VirtualSize, SizeOfRawData) of .text, which is what the
reference build does (there: VirtualSize 0x3eae816, SizeOfRawData 0x3eaea00,
so the VirtualSize wins).  --stamp rewrites the array in mgo_integrity.cpp in
place and prints a unified diff of what changed.
"""
import argparse
import hashlib
import re
import struct
import sys


def sections(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsz, = struct.unpack_from("<H", data, pe + 20)
    base = pe + 24 + optsz
    out = {}
    for i in range(nsec):
        h = base + i * 40
        name = data[h:h + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, h + 8)
        out[name] = (vsize, vaddr, rsize, roff)
    return out


def digest_of(path):
    data = open(path, "rb").read()
    secs = sections(data)
    if ".text" not in secs:
        raise SystemExit(f"{path}: no .text section")
    vsize, _vaddr, rsize, roff = secs[".text"]
    length = min(vsize, rsize)
    return hashlib.sha256(data[roff:roff + length]).digest(), length, vsize, rsize


ARR = re.compile(
    r"(const u8 mgo_integrity::expected_digest\[32\] = \{\n)(.*?)(\n\};)",
    re.S)


def stamp(src_path, digest):
    src = open(src_path, encoding="utf-8").read()
    m = ARR.search(src)
    if not m:
        raise SystemExit(f"{src_path}: expected_digest array not found")
    body = ""
    for i in range(0, 32, 8):
        row = ", ".join(f"0x{b:02x}" for b in digest[i:i + 8])
        body += "\n\t" + row + ("," if i + 8 < 32 else "")
    new = m.group(1) + body + m.group(3)
    print(f"--- {src_path}\n+++ {src_path}\n-old:\n{m.group(2)}\n+new:\n{body}")
    open(src_path, "w", encoding="utf-8").write(src[:m.start()] + new + src[m.end():])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", required=True, help="the rpcs3.exe that was just built")
    ap.add_argument("--stamp", action="store_true",
                    help="rewrite expected_digest in mgo_integrity.cpp")
    ap.add_argument("--source", default="rpcs3/Emu/mgo/mgo_integrity.cpp")
    args = ap.parse_args()

    digest, length, vsize, rsize = digest_of(args.exe)
    print(f"{args.exe}")
    print(f"  .text VirtualSize     = 0x{vsize:x}")
    print(f"  .text SizeOfRawData   = 0x{rsize:x}")
    print(f"  hashed length        = 0x{length:x}  (min of the two)")
    print(f"  sha256(.text)        = {digest.hex()}")

    if args.stamp:
        stamp(args.source, digest)
        print("\nstamped.")
    else:
        print("\n(re-report only; pass --stamp to rewrite the constant)")


if __name__ == "__main__":
    sys.exit(main())