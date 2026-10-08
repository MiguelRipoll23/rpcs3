"""Audit the replica's MGO names against the reference binary's symbol table.

The rule this enforces: every MGO-scoped identifier the replica declares should
be a name the reference binary actually exports, and nothing should be declared
that the binary does not have.  Anything in the "extra" column is either a
reconstruction or an invention, and both need to be defensible in writing.

    python buildfiles/mgo_name_audit.py

Note the limits, because they are real:
  * The binary has symbols for what it *defines*; a name we add for our own
    plumbing (e.g. the integrity check's own file and types) can never match,
    because the fork has no equivalent.  Those are listed separately as
    "ours, not the fork's".
  * Absence of a symbol does not prove absence of the code: the fingerprint and
    anti-cheat helpers are real (their format string and scan table are in
    .rdata) but were inlined or local, so they export nothing.  Those are listed
    as "reconstructed".
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, "buildfiles")
from mgo_verify_re import PE, Coff  # noqa: E402

EXE = r"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak"
pe = PE(EXE)
coff = Coff(pe)

items = sorted(coff.syms.items())
dem = subprocess.run(["c++filt"], input="\n".join(n for _, n in items),
                     capture_output=True, text=True).stdout.split("\n")
BIN = [(va, d) for (va, _), d in zip(items, dem)]
BIN_NAMES = [d for _, d in BIN]

# The fork's own MGO-scoped symbols.
FORK = {d for _, d in BIN if "mgo" in d.lower() and "(" in d}

# ---------------------------------------------------------------------------
# Collect what the replica declares.
# ---------------------------------------------------------------------------
FILES = []
for root, _dirs, files in os.walk("rpcs3/Emu/mgo"):
    for f in sorted(files):
        if f.endswith((".h", ".cpp")):
            FILES.append(os.path.join(root, f))
for f in ["rpcs3/Emu/mgo/mgo_patches.h", "rpcs3/Emu/mgo_patches.cpp",
          "rpcs3/Emu/mgo/mgo_integrity.h", "rpcs3/Emu/mgo_integrity.cpp",
          "rpcs3/Emu/mgo/mgo_integrity_hash.h", "rpcs3/Emu/mgo_integrity_hash.cpp",
          "rpcs3/Emu/Cell/SPUTaskHLE/ppu_task_hle.h",
          "rpcs3/Emu/mgo/mgo_ppu_hooks.cpp",
          "rpcs3/Emu/Cell/SPUTaskHLE/ppu_task_hle.cpp"]:
    if os.path.exists(f):
        FILES.append(f)


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


# Identifier declarations we care about, and the scope each belongs to.
DECL = [
    (re.compile(r"^\s*namespace\s+([A-Za-z_]\w*)"), "namespace"),
    (re.compile(r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)"), "type"),
    (re.compile(r"^\s*(?:enum(?:\s+class)?)\s+([A-Za-z_]\w*)"), "enum"),
    # function/method declarations at namespace or class scope
    (re.compile(r"^[A-Za-z_][\w:<>,\s\*&]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:const\s*)?(?:noexcept\s*)?[;{]"),
     "function"),
]

declared = {}   # leaf name -> set of scopes
where = {}     # leaf name -> first file:line

for path in FILES:
    for lineno, raw in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
        line = strip_comments(raw).strip()
        if not line:
            continue
        for rx, kind in DECL:
            m = rx.match(line)
            if not m:
                continue
            name = m.group(1)
            if name in ("if", "for", "while", "switch", "return", "sizeof", "catch"):
                continue
            declared.setdefault(name, set()).add(kind)
            where.setdefault(name, f"{path}:{lineno}")
            break

MGO_SCOPED = {n for n in declared
              if n.startswith("mgo") or n in {
                  "ppu_lwarx_wait", "geo_getllar_ignore_gpr1", "level_at_least",
                  "ls_image", "vworker", "why", "why_text", "write_list"}}


def in_binary(name):
    """Is `name` the final component of some symbol in the binary?"""
    for d in BIN_NAMES:
        head = d.split("(", 1)[0].strip()
        for part in head.replace(">", " ").split("::"):
            if part.strip() == name:
                return True
    return False


print(f"reference binary : {EXE}")
print(f"fork MGO symbols : {len(FORK)}")
print(f"our MGO files    : {len(FILES)}")
print(f"our declarations : {len(MGO_SCOPED)} MGO-scoped\n")

matched, extra = [], []
for name in sorted(MGO_SCOPED):
    (matched if in_binary(name) else extra).append(name)

print(f"== declared AND present in the binary: {len(matched)} ==")
for n in matched:
    print(f"  ok    {n:<28} {sorted(declared[n])}  {where[n]}")

print(f"\n== declared but NOT in the binary: {len(extra)} ==")
print("   (each of these must be justified in MGO_FORK.md)")
for n in extra:
    print(f"  ??    {n:<28} {sorted(declared[n])}  {where[n]}")

# What the fork has that we do not declare, by leaf name.
our_leaves = {n.split("::")[-1].split("<")[0].strip()
              for d in FORK for n in [d.split("(", 1)[0]]}
missing = []
for d in sorted(FORK):
    head = d.split("(", 1)[0].strip()
    leaf = head.split("::")[-1].split("<")[0].strip()
    if leaf and leaf not in declared and not leaf.isupper():
        missing.append(leaf)
print(f"\n== fork leaf names we do not declare: {len(set(missing))} ==")
uniq = sorted(set(missing))
for i in range(0, len(uniq), 6):
    print("  " + "  ".join(f"{x:<26}" for x in uniq[i:i + 6]))