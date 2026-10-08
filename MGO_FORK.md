# MGO Fork — reverse-engineering notes

This fork (`mgo-fork`) reconstructs the settings and features of the closed
SaveMGO build of RPCS3 (`rpcs3-savemgo`). The SaveMGO fork ships **no public
source** (confirmed via the GitHub API — zero hits for `rpcs3-savemgo`), so
everything here was recovered from the compiled `rpcs3.exe` that ships in
`~/Desktop/research/MGO2`.

> **Some claims in this file are machine-checked.** Every fact derived from the
> reference binary rather than from RPCS3's own source tree is re-derived by
> `buildfiles/mgo_verify_re.py`, which reads `MGO2.ELF` and `rpcs3.exe.bak`
> directly and exits non-zero on any mismatch. Run it before trusting a number
> in here:
>
> ```
> python buildfiles/mgo_verify_re.py --elf MGO2.ELF --exe rpcs3.exe.bak
> ```
>
> It currently passes 117 checks. It has already caught two real errors — a
> sign-extension bug in its own `bl` decoder, and a wrong belief about where the
> third modelsetup call site's immediate appears — so it earns its keep.

Everything below is ported, including the parts that lock the build to the
SaveMGO server:

- the SaveMGO-server-only connection gate (`lv2_socket_native::connect`)
- host fingerprinting + anti-cheat detection (`sys_ss.cpp`)

Two corrections to earlier drafts of these notes, both forced by evidence
rather than choice:

- **The `.text` self-integrity check is not emulator code.** It is the MSVC
  CRT's `rt_support_init()`, enabled by the linker's `/INTEGRITYCHECK`: it
  SHA-256s `.text` both in memory and on disk, compares against a 32-byte
  digest in `.data`, and calls `TerminateProcess` on a mismatch, before
  `main()`. That is why patching a stock `rpcs3.exe` makes it exit silently
  in ~2 s, and why the digest lives outside the hashed range. See
  `~/Desktop/mgo2-spoofer/rpcs3/README.md` §6. Nothing equivalent is
  hand-written here — do not add one.
- **There are no config keys for any of it.** A string scan of the fork's
  `rpcs3.exe` for `Code Integrity`, `Host Fingerprint`, `Anti-Cheat
  Detection`, `Restrict Connections`, `Allowed Endpoints` and `Plugin SPRX`
  returns zero hits, while all nine real `MGO` keys are present. The gate and
  the fingerprinting are unconditional and hardcoded, with no opt-out.

## Base version

`v0.0.41`. The fork's `update_history.log` ends at `0.0.41-19505`, and its
`rpcs3_version` matches upstream `v0.0.41`. The fork's own build hash
(`d5f4c761`) is a commit that only exists in the closed repo, so upstream
`v0.0.41` is the closest reachable base.

## Confirmed config schema

Recovered from the fork's own `config/config.yml` and by disassembling its
`cfg` constructor (`cfg_root::node_mgo::node_mgo`, `0x1431b6720`). Each key's
type is fixed by the vtable register stored at its member base: `rbx` for the
seven `cfg::_bool` members, `rax` for the one `cfg::_enum` member. (`edx` does
*not* encode the node type — at `0x1431b674d` it is `xor edx, edx`, the length
argument to the `std::string` helper at `0x1432b74c0`.)

The `MGO` node (key names are byte-for-byte the fork's):

| Key | Type | Default |
|---|---|---|
| `Disable Limiter` | bool | true |
| `Disable HUD` | bool | false |
| `Disable Lobby BGM` | bool | false |
| `Disable Blur` | bool | true |
| `Lower Exposure` | bool | true |
| `SPU Culling Wait Bypass` | bool | true |
| `Task Acceleration` | enum | `Basic` |
| `Audio Mixer Fast Path` | bool | false |
| `UPnP Port` | uint | 5730 |

The fork's older config files also carry `LQ Stages` and
`Use PPU for Physics LCP`; those are absent from the current binary and were
treated as removed options rather than reintroduced.

`Task Acceleration` is `mgo_task_acceleration`: `Off`, `Basic`, `Standard`,
`Maximum`.

This table is the complete `MGO` node. Nothing else belongs in it — see the
corrections above.

## Connection gate

`lv2_socket_native::connect` (`rpcs3/Emu/Cell/lv2/sys_net/lv2_socket_native.cpp`).
Recovered from `sub_143d27410` in the fork's `rpcs3.exe`; the gate branch is at
`.text 0x143d274c4` and the rejection string is at `.rdata 0x144bd81a0`.

The upstream `!nph.get_net_status() && is_ip_public_address(...)` check is
untouched. The fork inserts one block after it:

```cpp
if (type == SYS_NET_SOCK_STREAM)
{
    const u16 port = std::bit_cast<u16, be_t<u16>>(native_addr.sin_port);

    if (native_addr.sin_addr.s_addr != 0xe7efcc0f && port != 0x5000 && port != 0xbb01)
    {
        sys_net.error("[Native] Rejected TCP connection to %s:%d (only the SaveMGO server is allowed)", native_addr.sin_addr, std::bit_cast<be_t<u16>, u16>(native_addr.sin_port));

        return -SYS_NET_ECONNREFUSED;
    }
}
```

Notes on the three constants, all read straight off the instructions:

| value | how | meaning |
|---|---|---|
| `type == SYS_NET_SOCK_STREAM` | `cmp dword [rdi+0x1c], 1` — `+0x1C` is `lv2_socket::type`, right after `native_socket` at `+0x10` | only TCP is gated; UDP is untouched |
| `0xe7efcc0f` | `cmp dword [rsp+0x64], 0xe7efcc0f` — `+0x64` is `native_addr.sin_addr.s_addr` compared raw, i.e. network order | the one allowed address |
| `0x5000` / `0xbb01` | `cmp eax, 0x5000` / `cmp eax, 0xbb01` on `movzx eax, word [rsp+0x62]`, which is `sin_port` after the `be_t` bit-cast | two allowed ports, on **any** address |

The return is `-61` = `-SYS_NET_ECONNREFUSED`; the nearby `-49` is the
upstream `-SYS_NET_EADDRNOTAVAIL` from the public-address filter.

This is why a hand-patched `rpcs3.exe` reports a rejection for an arbitrary
address: the gate never looks at a list, it only asks "is this the SaveMGO
endpoint, and if not, is it one of the two ports".

### Pointing at your own server

The three constants above are the whole surface. Editing them and rebuilding
is the intended route; there is deliberately no config option, because the
fork has none.

## Host fingerprint and anti-cheat

`rpcs3/Emu/Cell/lv2/sys_ss.cpp`, namespace `mgo`. Full field-by-field
attribution is in `~/Desktop/mgo2-plugin/analysis/FINGERPRINT.md`; the record
is `MGO;%s;%d;%.2f;%d;%s;%d;%s;%s;%s;%s;%d;%s` with 12 fields — CPU brand,
logical processors, RAM GiB, Windows build, renderer, protocol constant `341`,
a per-run Mersenne Twister token, `ComputerHardwareId` twice (under two
different fallbacks, `"(null)"` and `"Unknown"`), the build hash, the
detection mask, and `BaseBoardProduct`.

The twelve detection probes are Cheat Engine (process, window title containing
`Cheat`, install paths), NetLimiter (process, the `nlsvc` service, install
paths), clumsy, ArtMoney and Wireshark. Their target names are XOR'd with
`0x45` in the fork so a strings scan does not reveal them, and that scheme is
reproduced here.

Two deliberate deviations, both marked in the source:

- the fork reads field 4 from the undocumented `PEB+0x120`; this reads
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber`,
  which is the documented source of the same number
- the fork's 13 Cheat Engine and 5 NetLimiter install paths were not
  individually recovered (only their count and version range), so those sets
  are rebuilt from the product roots the analysis describes; the two verbatim
  NetLimiter paths are kept

Like the fork, the builder has no resolved caller in the binary — it is
reachable only indirectly. `mgo::report_host_fingerprint()` exists so there is
a place to log the record, but nothing calls it yet.

## Confirmed UI

A dedicated **Metal Gear Online** tab with two group boxes.

- Network Configuration — `Bind address`, `Enable UPNP`,
  `Derive ethernet address from PSID`
- Configuration — `Disable HUD`, `Disable Motion Blur`,
  `Disable Frame Limiter`, `Disable Lobby BGM`, `Reduce Sky Brightness`,
  `SPU Culling Wait Bypass`, `Audio Mixer Fast Path (lossy)`,
  `Task Acceleration`

Note the UI labels differ from the config keys (`Disable Motion Blur` is
stored as `Disable Blur`, `Reduce Sky Brightness` as `Lower Exposure`,
`Disable Frame Limiter` as `Disable Limiter`).

The three network options are **not** fork-specific: `Emu/system_config.h`
already defines `bind_address`, `upnp_enabled` and `derive_mac_from_psid`
under `Net`. The fork only surfaces them on the MGO tab, so this fork reuses
the existing `emu_settings_type::BindAddress` / `EnableUpnp` /
`DeriveMacFromPsid` entries rather than duplicating them (duplicates would
trip the "already exists" check in `emu_settings::FindSettingsType`).

## What "Task Acceleration" actually is

The binary retains ~150k Itanium-mangled symbols (the fork was built with
clang on WSL and not stripped), so the subsystem is visible by name. It is a
new directory the fork added, absent from upstream:

```
rpcs3/Emu/Cell/SPUTaskHLE/ppu_task_hle.cpp
rpcs3/Emu/Cell/SPUTaskHLE/spu_task_hle.cpp
rpcs3/Emu/Cell/SPUTaskHLE/mgo_ppu_hooks.cpp
rpcs3/Emu/Cell/SPUTaskHLE/mgo/ppu_geo_collision_hooks.h
rpcs3/Emu/Cell/SPUTaskHLE/mgo/drawassist_3120.h
rpcs3/Emu/Cell/SPUTaskHLE/mgo/drawassist_4f20.h
```

It is a PPU-hook framework that replaces selected MGO2 guest functions with
host implementations at load time, gated by
`spu_task_hle::level_at_least(mgo_task_acceleration)`:

- `spu_task_hle::ppu::install(u32 module_base, u32 module_size, bool)` — redirect callers
- `spu_task_hle::ppu::hooked_function_starts()`
- `spu_task_hle::ppu::dispatch(ppu_thread&, u32)`
- `spu_task_hle::ppu::get_executable_hash()` — identity gate for the target game
- `spu_task_hle::get_image_patches()` / `on_embedded_spu_image(...)`

Hooked subsystems: `mgo_geo_coll` (geometry collision / culling),
`mgo_da4f20` and `mgo_da3120` (draw assist), `mgo_modelsetup`,
`mgo_motion_play`, `mgo_pl_motion_mix`, `mgo_pmm_rt`.

`SPU Culling Wait Bypass` maps to `spu_task_hle::mgo_waits::ppu_lwarx_wait`
and `spu_task_hle::mgo_waits::geo_getllar_ignore_gpr1`.

## Disable Lobby BGM — recovered mechanism

The binary embeds a `patch_config.yml` and feeds it to RPCS3's **own** patch
engine (`Utilities/bin_patch.cpp`). "Disable Lobby BGM" is therefore not a
hand-written hook at all — it is two `hide_file` patches:

```yaml
Version: 1.2
PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1:
  "MGO Disable Files":
    Games:
      All:
        All: [ All ]
    Patch Version: 2.0
    Patch:
    - [ hide_file, /dev_hdd0/game/NPMG00020/USRDIR/o/bgm/bgm_mgo_lobby01.bgm, "" ]
    - [ hide_file, /dev_hdd0/game/NPMG00020/USRDIR/o/bgm/bgm_mgo_tounament01.bgm, "" ]
```

`hide_file` mounts `<config_dir>delete_this_dir.../delete_this...` over the
target path, so the game cannot open the BGM at all.

The key is the standard RPCS3 patch hash: `"PPU-" + hex(sha1(main ELF))`,
produced by `ppu_module_manager::load` in `PPUModule.cpp`, which also calls
`Emu.SetExecutableHash(hash)`. This is the same identity gate that
`spu_task_hle::ppu::get_executable_hash()` returns, so the built-in patches and
the PPU hook framework share one identity check.

Because it goes through the normal patch path, the patch only applies to the
matching NPMG00020 build. The hash is over the *loaded* image, not the raw
file on disk (it does not match `sha1sum` of `MGO2.ELF` / `EBOOT_decrypted.ELF`).

### Implementation

`patch_engine::apply()` skips any patch whose `config_values.enabled` is false,
and `enabled` normally comes from the user's `patch_config.yml`. Built-ins are
gated by an emulator setting instead, so `patch_engine` gained
`append_builtin_patches()`, which loads the embedded YAML with `importing=true`
(bypassing the user's enable filter) and force-enables every parsed
(title, serial, version) entry. `rpcs3/Emu/mgo_patches.cpp` then registers only
the patches the MGO settings ask for, called from `System.cpp` right after the
regular patches are loaded.

## The hook tables — what Task Acceleration actually hooks

The fork's binary is not stripped, so its COFF symbol table resolves every fork
symbol to a real address. Two of them are the tables:

| symbol | address | returns |
|---|---|---|
| `spu_task_hle::get_hook_table()` | `.text 0x143cdf850` | `std::span`, data `0x144bcd450`, **2 entries** |
| `spu_task_hle::get_image_patches()` | `.text 0x143cdf870` | `std::span`, data `0x144bcd3b0`, **1 entry** |

Both are 16-byte out-param span getters (`lea rcx,[rip+…]` / `mov [rax],rcx` /
`mov [rax+8],count` / `ret`). Reading the strings the tables point at:

| entry | kind | image |
|---|---|---|
| `drawassist.3120` | hook | `SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e` |
| `drawassist.4f20` | hook | `SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e` |
| `mixer.single_bus` | image patch | `SPU-ae8a758775740615382268346f1a9cc14d9966f9` |

with the neighbouring module name `spu/spurs_drawassist.spu.task` and, in
`.rdata` at `0x144bcd4c0`, the source path
`…/rpcs3-savemgo/rpcs3/Emu/Cell/SPUTaskHLE/mgo/drawassist_3120.h`.

Three consequences, one of which corrects this file:

1. **The table is keyed on SPU module entry points, not PPU guest addresses.**
   There is not a single guest address in it. An earlier revision here modelled
   it as `{name, guest_addr, …}` entries for `mgo_geo_coll.line_check` and
   friends, which could never have matched. Those subsystem names are real —
   they are the fork's own symbols and log channels — but they are the *handler
   bodies*, not the table keys.
2. **Task Acceleration is exactly two hooks**, into
   `spu/spurs_drawassist.spu.task` in the embedded SPU image
   `SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e`.
3. **The one image patch is the Audio Mixer Fast Path**, on
   `mixer.single_bus` in `SPU-ae8a758775740615382268346f1a9cc14d9966f9`.
   That is the recovered mechanism for `Audio Mixer Fast Path`, not a guess.

Other framework addresses, for reference:

```
spu_task_hle::level_at_least(mgo_task_acceleration)   0x1434ae410
spu_task_hle::on_embedded_spu_image(...)              0x1434ae4f0
spu_task_hle::mgo_waits::ppu_lwarx_wait(...)          0x1434af180
spu_task_hle::mgo_waits::geo_getllar_ignore_gpr1(...) 0x1434af140
spu_task_hle::ppu::install(...)                       0x143389c40
spu_task_hle::ppu::hooked_function_starts()              0x14338a400
spu_task_hle::ppu::dispatch(ppu_thread&, u32)         0x14338a4c0
spu_task_hle::ppu::get_hook_table()                   0x143a1aa10
spu_task_hle::ppu::get_executable_hash()              0x143a1aa30
mgo_geo_coll_hooks::line_check(...)                   0x143a18c80
mgo_geo_coll_hooks::pool_start(...)                   0x143a19e00
mgo_drawassist_3120(spu_task_hle::task_env&)          0x143cdf890
mgo_drawassist_4f20(spu_task_hle::task_env&)          0x143ce2110
```

A 16-byte blob at `0x144bcd42a`, immediately after the drawassist SPU hash, is
four little-endian words `ff114acc ff114c27 ff114bb3 ff114bed` — code-relative
displacements, so it is a branch template rather than data. It has not been
decoded.

`tools/coff_syms.py` (added alongside this) parses the PE's COFF symbol table
and resolves a symbol to `image_base + section_va + value`. It is far cheaper
than any disassembly pass and is the right first tool for this binary.

## The PPU hook registration table — recovered

`spu_task_hle::ppu::get_hook_table()` at `0x143a1aa10` computes
`(end - begin) >> 6`, i.e. the live install list is **64-byte records**. It also
explains why no static table could be read earlier: `begin`/`end` are loaded
from globals and are empty in the file, because the list is populated at
runtime.

The records themselves are in `.rdata` at **`0x144b29ec0`**. Searching for the
8-byte little-endian encoding of the handler addresses finds them, and the full
decoded layout — including the call-site lists and the true meaning of the field
formerly misread as a size — is in **The PPU hook table — 8 records, fully
decoded** below.

> **Correction.** An earlier version of this section recorded the table base as
> `0x144b29f60` and the layout as `u32 guest_addr, u32 3, u64 handler_ptr`. The
> base was 0xa0 too high and the layout was shifted with it. The correct base is
> `0x144b29ec0` and the record is
> `name, single, list, list_count, target, min_level, handler, …` — see below
> for the authoritative table. One handler still serves several targets
> (`line_check` at three, `pool_start` at two), which is unchanged.

Neither handler is reachable by a direct `call` or by having its address taken,
which is why a code-level xref search finds nothing — the only pointer to them
is these records, the same indirection that made the fingerprint builder
`sub_1412294d0` look uncalled.

### Searching for the tags does not work

`0x94981a01` and `0x94ca1a01` appear **zero** times in `MGO2.ELF` as PPC64
`lis` immediates. That is expected and worth recording: those magics belong to
the *emulator's* host code, where they were read from in the first place. They
are not guest-side constants, so the guest function cannot be found by looking
for them — the registration records are the only route, and that is what was
used.

## The PPU hook table — 8 records, fully decoded

Sweeping `.rdata` for the little-endian encoding of **all 236** HLE handler
symbols (`tools/recover_hook_addrs.py`) finds only **8 registrations, across 4
distinct handlers**. Every other symbol is a **callee reached through one of
these four launchers**, not a registration of its own; the `_GLOBAL__N_1*_launch`
names say so directly.

The table lives at **`0x144b29ec0`** — eight 64-byte records, which is the same
`>> 6` stride `get_hook_table()` computes. It is read directly by
`mgo_modelsetup`'s populate function at `0x143b4fbf0`, which `memcpy`s exactly
`0x200` bytes from it.

### Record layout

This layout was read out of `.rdata` and cross-checked against what
`install()` at `0x143389c40` actually indexes. It is a **separate table** from
the `call_regs` block the handlers are handed — see "`call_regs` — the layout is
confirmed" below, which corrects an earlier draft that conflated the two
because their displacements happen to overlap.

| offset | type | meaning |

| offset | type | meaning |
|---|---|---|
| `+0x00` | `const char*` | log channel name |
| `+0x08` | `u32` | one explicit call site, or 0 |
| `+0x10` | `const u32*` | array of call sites, or null |
| `+0x18` | `u64` | length of that array |
| `+0x20` | `u32` | **target** — guest address being redirected |
| `+0x24` | `u8` | **minimum verbosity**, compared against a global |
| `+0x28` | `u64` | handler pointer |
| `+0x30` | `u64` | reserved (nonzero only for modelsetup) |
| `+0x38` | `u64` | reserved (nonzero only for modelsetup) |

The eight records:

| # | name | target | +0x24 | call sites | handler |
|---|---|---|---|---|---|
| 0 | `ppu.pl_motion_mix` | `0x003370d8` | 255 | 1 @ `0x00331d68` | `0x143a14dc0` |
| 1 | `ppu.motion_play` | `0x001739c0` | 3 | 9 (see below) | `0x143a158b0` |
| 2 | `ppu.geo_line_region` | `0x000a28a8` | 3 | *text scan* | `0x143a18c80` |
| 3 | `ppu.geo_line_auto` | `0x000a15b0` | 3 | *text scan* | `0x143a18c80` |
| 4 | `ppu.geo_line` | `0x000a1f28` | 3 | *text scan* | `0x143a18c80` |
| 5 | `ppu.geo_pool_start` | `0x001b0c78` | 3 | 1 @ `0x0009e0ac` | `0x143a19e00` |
| 6 | `ppu.geo_pool_start2` | `0x001b03b0` | 3 | 1 @ `0x0009e0d4` | `0x143a19e00` |
| 7 | `ppu.modelsetup` | `0x00234a10` | 2 | 3 (see below) | `0x143a19ec0` |

`motion_play` call sites (array at `0x144b29e20`):
`0x60ac74 0x60ba50 0x60c72c 0x60d508 0x60e258 0x60ef34 0xd3f058 0xed69a8 0xd5ab38`

`modelsetup` call sites (array at `0x144b29eb0`):
`0x14cea0 0x14ce28 0x14cdb0`

Every target and call site falls inside MGO2.ELF's text LOAD
(`0x10000..0x118e348`).

### The +0x24 field is a verbosity threshold, not a size

An earlier revision of this file read those bytes as a redirect length and noted
they were "3/3/3/2/255 — not a uniform size". **Resolved**: `install()` loads a
global verbosity byte (`0x1466bab94`, read at `0x143389d84`), compares it against
`+0x24`, and **skips the record when the global is lower**
(`cmp al, [rbp+0x24] / jb skip`). So the small values are thresholds, and `255`
means `pl_motion_mix` is skipped at any realistic verbosity — it is effectively
disabled in the shipped fork.

The old `u32 guest; u32 field; u64 handler` layout came from reading the table
at a **0xa0 offset too high** (`0x144b29f60` instead of `0x144b29ec0`), which
slid every field by 8 bytes and turned a `u32 target` + `u8 level` pair into what
looked like two `u32`s. Note the trap: the wrong base still yielded plausible
values, because the misaligned read lands on neighbouring records' fields.

## The install mechanism: call-site patching, not entry-point hooks

This is the substantive correction. The records do **not** hook a function's
entry point. `spu_task_hle::ppu::install` (`0x143389c40`, 0x7b8 bytes) rewrites
the **`bl` instructions that call** each target, redirecting them to a stub the
fork registers as `MGO_PPU_HOOK_%02u`, where `%02u` is the record index.

The fork's own log line gives it away at `0x14338a253`:

```
Installed PPU hook %s: %u call site(s) of 0x%x -> MGO_PPU_HOOK_%02u (0x%x)
```

Call sites come from exactly one of three places, in this priority order:

1. `+0x08` nonzero — that single address (records 0, 5, 6)
2. `+0x18` nonzero — the `+0x10` array (records 1, 7)
3. neither — **scan the module text** for every `bl` whose computed target
   equals `+0x20` (records 2, 3, 4)

The third case is why the three `geo_line*` entries list no addresses at all:
they are installed by scanning. That scan is the loop at `0x14338a2a8`, which
walks `[module_base, module_base+size)` in 4-byte steps, and for each word
matching `bl` computes the target and compares it to `[rbp+0x20]`.

The replacement instruction is built at `0x14338a13e`:

```asm
and  ecx, 0x3fffffc      ; keep the 26-bit displacement field
or   ecx, 0x48000001     ; set opcode to `bl`
...
bswap ecx                ; PPC64 guest words are big-endian
mov  [rdx + rax], ecx    ; patch the call site
```

Before writing, `install` verifies each candidate really is a `bl` aimed at the
expected target, and refuses to patch otherwise, logging:

- `"%s: unexpected instruction 0x%08x at 0x%x (expected bl 0x%x); not installed there"`
- `"%s: call site 0x%x is not mapped"`
- `"%s: HLE entry 0x%x is out of branch range from 0x%x"`

That last one matters: PPC64 `bl` has a ±32 MB signed 26-bit displacement, so a
target too far from the call site cannot be redirected at all. `install` bounds
this with `lea rdx, [rcx - 0x2000000] / cmp rdx, -0x4000001 / ja reject`.

Other details confirmed in `install`:

- Table size is capped at `0x11` (`cmp rsi, 0x11` at `0x143389c85`); 8 is fine.
- It calls `get_executable_hash()` and refuses to proceed unless the loaded
  module's hash matches — the `PPU-0c7acb83…` identity.
- A `force` flag (arg 4, `r9b`) is threaded through the level check; when set,
  `install` patches without comparing instructions, which is a debug/dry-run path.
- It reads guest memory through a **big-endian** accessor (`bswap` after each
  load), so every guest instruction is byte-swapped into host order.

Because the stub-generation path is not reconstructed here, the current
implementation **observes** call sites rather than patching them: rewriting a
`bl` without a real stub behind it would send control somewhere undefined.

## Where the hook vector is built

`spu_task_hle::ppu::get_hook_table()` returns a span over two adjacent qword
globals in `.data` at **`0x1461778b8`** (begin) and **`0x1461778c0`** (end).
Their referrers in `.text`:

| address | instruction | role |
|---|---|---|
| `0x143a1aa14` | `mov rcx, [rip+…]` | the getter, reads begin |
| `0x143a1aa1e` | `mov rdx, [rip+…]` | the getter, reads end |
| `0x143b4fbf9` | `vmovups [rip+…], xmm0` | **clears** both at once (16 bytes) |
| `0x143b4fc17` | `mov [rip+…], rax` | writes begin |
| `0x143b4fc41` | `mov [rip+…], rsi` | writes end |

`0x143b4fbf0` is therefore a `clear_hook_table()` - a three-instruction function
that zeroes the vector - and the function that begins just after it populates
it. That populate function copies the static `.rdata` records verbatim; the
consumer that interprets them is `spu_task_hle::ppu::install`.

Both live in the `mgo_modelsetup::detail::task_io` neighbourhood
(`0x143b4f860` is a `for_each_put_bufs<…>` lambda), so **`mgo_modelsetup` is the
subsystem that registers the hooks**, which fits `modelsetup_launch` being one
of the four launchers.

### A tooling trap worth remembering

The first attempt to find these referrers reported **zero hits for everything**,
including for a reference visible in the disassembly two instructions away. The
scanner was fine; the target list was wrong - a hand-computed
`0x143a1aa1a + 0x275ce9e` was written down as `0x1460b78b8` when it is
`0x1461778b8`. A dropped hex digit.

The lesson: never add hex addresses by hand to build a target list. Compute them
in the same script that does the scan, or a single mistyped digit reads as
"this approach does not work" and gets abandoned.

### The populate path is a straight memcpy

`0x143b4fbf0` (0x68 bytes) is not a builder loop:

```
vmovups [rip+…], xmm0        ; zero the vector
mov    qword [rip+…], 0      ; zero capacity
mov    ecx, 0x200            ; 512
call   operator new(512)     -> rax
mov    [rip+…], rax          ; begin = buffer
lea    rsi, [rax + 0x200]
mov    [rip+…], rsi          ; end = begin + 512
lea    rdx, [rip + …]        ; static table
mov    r8d, 0x200            ; 512 bytes
mov    rcx, rax
call   memcpy
mov    [rip+…], rsi          ; capacity = end
jmp    <register the object>
```

512 bytes = **8 records of 64**, which matches the 8 registrations found
independently by sweeping for handler pointers, on a 64-byte grid based at
`0x144b29ec0`. Two independent routes agreeing on 8 is the strongest
confirmation yet that the hook table is complete.

The consequence: **this function reads no field at all.** It copies records
verbatim. The consumer is `spu_task_hle::ppu::install` at `0x143389c40`, which
has since been disassembled in full — that is where the `+0x24` verbosity byte
turned out to be used, and where the call-site patching described above comes
from. This question is now closed; see that section.

## Wiring the framework into the emulator

The hook code existed but nothing called it. Three call sites were needed; all
three are in upstream RPCS3 code, minimally touched.

### 1. Dispatch — the HLE entry path, **not** the instruction loop

**This corrects an earlier revision of this file**, which hooked
`ppu_thread::exec_task()`'s static-decoder loop with a `try_dispatch(*this, cia)`
call and described that as the fork's mechanism. It is not.

Recovered by scanning `.text` for `call` rel32 targeting `ppu::dispatch`
(`0x14338a4c0`): there are exactly **16 call sites, all inside
`ppu_module_manager` lambdas**, at `0x1439727f2` … `0x143973665`, spaced 0x150
apart, each in a function of 0x14b–0x14e bytes. The nearest COFF symbol is

```
_ZZNK18ppu_module_manager3$_2clEvENUlR10ppu_thread12ppu_opcode_tPN3stx4se_tIjLb1ELy4EEEP14ppu_intrp_funcE0_8__invokeES2_S3_S7_S9_
```

— a `ppu_module_manager` member lambda taking exactly
`(ppu_thread&, ppu_opcode_t, se_t<u32>&, ppu_intrp_func*)`, which is the
`ppu_intrp_func` signature. These are the generated HLE entry stubs. Sixteen of
them, one per registered hook slot.

Each stub starts by loading a hook name from a table of consecutive strings:

```
0x1439727a0  lea rax, [rip+0x119e132]   ; -> "MGO_PPU_HOOK_00"
```

and `0x1439727a0+0x119e132` is eight consecutive `MGO_PPU_HOOK_00` …
`MGO_PPU_HOOK_07` strings, then more. It stores that name into the thread at
`+0xa20`, copies the vector registers (`[rsi+0x30..0x60]` →
`[rsi+0x9e0..0xa10]`), and calls `dispatch(ppu, 0)` with `edx = 0`.

So the real chain is:

1. `install()` rewrites the call site's `bl` to the HLE slot address, exactly as
   recovered before.
2. The guest branches there.
3. **RPCS3's own HLE machinery dispatches it** — the stub registered by
   `ppu_register_function_at`, i.e. the same path every `RPCS3_HLE_LIBRARY`
   function uses.
4. That stub calls `spu_task_hle::ppu::dispatch`.

No emulator loop is involved, and none needed patching. The earlier
exec-loop hook was wrong twice over: it added a per-instruction cost to the
hottest loop in the emulator, and it only worked under the static decoder —
`ppu_gateway` (the dynamic path) is generated JIT assembly and could never have
carried the call. The HLE path is decoder-independent, because the stub is
looked up the same way in both.

**Consequence for `dispatch`:** its key cannot be the original call site. By the
time it runs, the `bl` has already been rewritten and execution is at the stub;
the original address is gone. The fork keys on the stub (`edx = 0` is the
function index it passes, and the 16 stubs are the 16 slots), and reads the
original call site back out of `lr - 4`. So `dispatch` now takes
`(ppu_thread&, u32 cia)` and looks `cia` up in a stub→entry map, mirroring the
fork.

### 2. Install — `ppu_initialize(void)`, after each `ppu_initialize(module)`

```cpp
if (!_main.segs.empty())
{
    ppu_initialize(_main);
    spu_task_hle::ppu::on_module_loaded(_main.segs[0].addr, _main.segs[0].size, false);
}
```

Called for the main ELF and again for each preloaded PRX. `on_module_loaded`
gates on the executable hash (`PPU-0c7acb83…`, the same identity the fork
checks) and on the segment actually being mapped executable, so it is a no-op for
any other game.

This is the correct seam: by this point the module is mapped and its functions
are registered, which is exactly when `bl` sites can be validated and rewritten.
It is also after `ppu_precompile`, so JIT'd functions are in place.

### 3. Teardown — `Emulator::Kill`'s `reset_emu_state()`

```cpp
const auto reset_emu_state = [this]()
{
    // MGO: drop the PPU hook table before the guest memory it patches goes
    // away, so no thread can look up a stale call site.
    spu_task_hle::reset();
    ...
```

`reset_emu_state` is the single point both the plain-stop and savestate paths
converge on, so one call covers both. Ordering matters: the hook table is
dropped before `m_ar.reset()`, so no PPU thread can resolve a call site into
memory that is about to be freed.

### 5. SPU thread stop — `spu_thread::cpu_on_stop()`

```cpp
spu_task_hle::on_stop(*this, 0);
```

The fork's `spu_task_hle::on_stop(spu_thread&, u32)` is a tail call from its
equivalent of `cpu_on_stop()`. It exists so the parallel modelsetup pool can
join work owned by a thread that has finished — otherwise a thread that aborts
mid-task leaks its job. Nothing here runs lifted work yet, so it is a no-op.

### 6. SPU image hooks — `sys_spu_image::deploy()`

```cpp
// after the two patch_engine::apply() calls
spu_task_hle::ppu::on_embedded_spu_image(hash, {}, false, loc, SPU_LS_SIZE);
```

`deploy()` is the only place where all three of these are simultaneously true:
the image is fully written to the local store, its `SPU-<sha1>` identity exists
as a string, and the bytes can still be rewritten. The stock YAML patch engine
runs just above it, so the fork's compiled-in table sits after it rather than
competing with it.

The `{}` is the module name, which the module hooks would match on. The SPU
image load path does not carry a module name — the fork keys its two
`drawassist` hooks on the image hash alone, and the module they live in
(`spu/spurs_drawassist.spu.task`) is only a comment in the recovered table. So
the module hooks currently match on identity and name; passing an empty name
means the hash matches and the name does not, i.e. nothing installs from this
call site. See "Still not wired" below.

## The framework's real signatures

Recovered from the COFF symbol table and demangled (`c++filt`). This is the
authoritative list; the replica matches it, including the parts that were
originally guesses:

```
spu_task_hle::level_at_least(mgo_task_acceleration)
spu_task_hle::get_image_patches()
spu_task_hle::on_embedded_spu_image(string_view, string_view,
                                    const function<u8*(u32,u32)>&, bool)
spu_task_hle::on_stop(spu_thread&, u32)
spu_task_hle::reset()
spu_task_hle::t_last_decline
spu_task_hle::ppu::get_hook_table()
spu_task_hle::ppu::get_executable_hash()
spu_task_hle::ppu::install(string_view, u32, u32, bool)
spu_task_hle::ppu::dispatch(ppu_thread&, u32)
spu_task_hle::ppu::hooked_function_starts()
spu_task_hle::ppu::guest_ptr(u32)
spu_task_hle::ppu::guest_valid(u32, u32, bool)
spu_task_hle::ppu::direct_mem::publish32(u32, u32)
spu_task_hle::ppu::on_emulation_stop()
spu_task_hle::ppu::reset()
```

Three of these changed what the replica does:

**`hooked_function_starts()`** was the reason to doubt the call-site model, so
it was worth decoding. It is 0xbc bytes at `0x14338a400` and it builds a
*vector* (it zeroes a 24-byte object in `rcx` and pushes into it), walking the
record table with a stride of **0x40** — the 64-byte record size — and collecting
each record's **+0x20 target**, skipping records whose flag byte is not 1. So it
returns the hooked guest function *entry points*, which is exactly what its name
says. It is a diagnostic ("which guest functions are these hooks standing in
for"), not a dispatch table, and the call-site model stands. The earlier doubt
was a naming coincidence.

**`install()` takes a `string_view` first.** The replica's version had no name
parameter at all. It is almost certainly the module or image being installed
for, and it is what the fork's install log line refers to.

**`on_embedded_spu_image` takes a `std::function<u8*(u32,u32)>`.** That is a
bounds-checked accessor for the deployed image — the same `mem_translate` lambda
`sys_spu.cpp` already builds for the stock patch engine. The replica originally
took a raw `(u8* image, u32 size)` pair and had to bounds-check twice; the
fork's shape puts the check in one place. Changed to match.

### Namespaces

The fork has 15 MGO namespaces; the replica has 3. Of those 3, `mgo_geo_coll_hooks`
matches exactly. The other two are replica-local names and are marked as such in
the source. The missing ones are the lifters, the parallel pool, and the SPU-side
opcodes listed above.

## `call_regs` — the layout is confirmed, not assumed

An earlier revision of this file described `call_regs` as a plausible guess. It
is not. The fork's handlers take it as their third argument (`rcx` = ppu_thread,
`rdx` = direct_mem, `r8` = call_regs, `r9` = call_result) and read it at fixed
displacements. Scanning the prologue of all five distinct handler bodies for
`[r8+disp]`:

| handler | record | `[r8+disp]` reads |
|---|---|---|
| `pl_motion_mix` | 0 | `+0x18` (r3) |
| `line_check` | 2–4 | `+0x10` (r2), `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0x108` |
| `modelsetup` | 7 | `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0xc0` (r24) |

`+0x18 / +0x20 / +0x28 / +0x30 / +0xc0` are `gpr[3] / gpr[4] / gpr[5] / gpr[6] /
gpr[24]`, and `line_check`'s `+0x108` is the link register. So the block is 32
GPRs at +0x00, `pc` at +0x100, `lr` at +0x108 — which is exactly
`std::array<u64,32> gpr; u64 pc; u64 lr;`. The replica's struct matches the
fork's field for field.

This also settles something the record layout never could: **`r8` is not the
hook record.** Reading `+0x18` as `list_count` and `+0x28` as `handler` was a
coincidence of the two layouts overlapping. The records are a separate table;
`call_regs` is what handlers are handed.

## Per-call-site dispatch: `lr - 4`

`modelsetup_launch` (0x143a19ec0, 0x8fb bytes) opens by recovering the call
site from the link register:

```
0x143a19f2d  mov  esi,  [rcx+0x460]   ; ppu_thread's saved LR
0x143a19f49  lea  r12d, [rsi-4]       ; the address of the `bl` that called
0x143a19f4d  cmp  esi, 0x14ce2c       ;   -> lr of site 0x14ce28
0x143a19f55  cmp  esi, 0x14cea4       ;   -> lr of site 0x14cea0
0x143a19ffc  xor  esi, esi            ;   neither: not this handler's
```

and later dispatches on the derived site address:

```
0x143a19ffe  cmp  r12d, 0x14cea0
0x143a1a092  cmp  r12d, 0x14ce28
```

Two of the three call sites are special-cased. `0x14cdb0` — whose LR would be
`0x14cdb4` — is **not** compared anywhere in the body and takes the default path.
Verified by byte search over the function: `2c ce 14 00` and `a4 ce 14 00` are
present, `b4 cd 14 00` is not. (`mgo_verify_re.py` asserts exactly this, scoped
to the function, because `0x14cdb0` *does* appear elsewhere in the image as a
`.rdata` call-site entry.)

So a handler reached through a `bl` knows which `bl` it was. The replica
reproduces this as `call_regs::call_site` (= `lr - 4`), populated in
`dispatch()`, with `hook_entry::by_site` available for a per-site override.
The fork does the selection inside its own body; the framework-side table is
the equivalent, and only `ppu.modelsetup` populates it.

### The two guards, and what they are guarding

`modelsetup_launch` does not go straight to work. Before committing, it checks
that a block pointed at by **r24** (`+0xc0`) has two sub-ranges that each fit
inside a single 4 KB page:

```
lea eax, [rbx+0x84]   / cmp eax,-4 / ja decline / shr ecx,12
lea edx, [rbx+0x87]   / shr edx,12 / cmp ecx,edx / jbe accept
```

and again at `+0x114 .. +0x117`. Site `0x14cea0` runs **both** checks; site
`0x14ce28` runs **only the second**. After each page check the code walks a
byte map testing bit 7 of each byte — the loop at 0x143a1a404 masks the counter
with `0xffffff00` and adds `0x100` for a set bit, aligning to 16 for `0x20` —
which is a per-4 KB-page "is this page live" bitmap. That map is not identified.

The `cmp eax, -4 / ja` is an unsigned wrap check against `0xfffffffc`, which is
how the code detects the wrap the guest's own 32-bit arithmetic would have
produced. The replica reproduces it as written rather than simplifying it to a
range test, because the two disagree exactly at the wrap.

### What the handler does after the guards

It is a **task-image lifter**. The strings the body references give the shape
outright:

```
'not a model setup image'
'task image differs from the lifted one'
'unexpected SPURS_TaskStart arguments'
'SPURS taskset not readable'
'lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)'
```

plus a status jump table at `0x144b378e4` with nine entries. The "declined"
wording is the key: the fork lifts the guest's SPURS task image to host code
and **verifies** the lift against the live state, falling back to the guest's
own code whenever it cannot prove the lift is safe. It is a speculative
optimiser with a proof obligation, not a reimplementation.

That is why the replica's `ppu_modelsetup_hook` reproduces the dispatch and the
guards and then stops. It reports and defers. A lift without the embedded model
data and a real SPURS task to stand in for would not be a slower version of
the fork's feature; it would be a different and much more dangerous one.

## The fork's real architecture, from its own symbol names

The reference image carries DWARF and is not stripped, so its C++ symbols
survive. They name the subsystems, which is far more informative than any amount
of disassembly of individual bodies:

| namespace | what it is |
|---|---|
| `mgo_modelsetup` | the `ppu.modelsetup` hook, with a `par` (parallel) subsystem: `pool`, `pool_instance`, `pending`, `tracker`, `page_set`, `page_bits`, `conflicts` |
| `mgo_motion_play` | the `ppu.motion_play` hook: `root_track`, `blend_pass`, `fetch_points`, `crossfade`, `mirror`, `owner_pass` |
| `mgo_geo_coll` / `mgo_geo_coll_rt` / `mgo_geo_lift_coll` | the three `geo_line*` hooks: `write_list`, `snap_rec`, `bad_point`, `vworker` |
| `mgo_pl_motion_mix` / `mgo_pl_motion_mix_lift` | the `pl_motion_mix` hook, with its own lifter |
| `mgo_da4f20_detail` | the `drawassist.4f20` SPU module hook: 31 numbered opcodes (`op2`..`op31`) |
| `mgo_modelsetup_chara_lift` / `mgo_modelsetup_bg_lift` | the two modelsetup lifters, for character and background rigs |
| `mgo_ms_rt` | the shared runtime: `vctx`, `xfer`, `wrch`, `region_cache` |
| `spu_task_hle::mgo_waits` | `ppu_lwarx_wait`, `geo_getllar_ignore_gpr1` — wait-primitive replacements |

Two things follow that were not previously known:

**The lifters are per-rig.** `mgo_modelsetup_chara_lift` and
`mgo_modelsetup_bg_lift` are separate namespaces with near-identical shape
(`*_core_driver`, `lod0`, `lod1`, `mats`, `bones`, `parts`, `tails`, `recs`).
So the fork does not have one modelsetup optimiser; it has at least two, one per
kind of skeleton, plus a third and fourth for the two drawassist entry points.
This is a substantial body of work, not one hook.

**The work is parallel.** `mgo_modelsetup::par::pool` has `start`, `stop`,
`loop`, `join`, `chunk_job`, `pending_job`, and a `thread_tracker` with a
`conflicts` pass that takes `read_pages` and `written` sets and decides what can
run concurrently. The hooks are not "faster inline replacements"; they are
work-stealing task schedulers that run lifted guest stages on host threads,
using a `tracker::on_get`/`on_put` shadow memory to prove the concurrent
accesses are safe.

That is the actual shape of the feature, and it is a much larger project than a
set of call-site patches.

### Source file names, recovered

The fork's own source paths are in the image (it is a Debug build, so they are
in the DWARF and in `__FILE__` for assertions):

```
rpcs3/Emu/Cell/SPUTaskHLE/mgo_ppu_hooks.cpp
rpcs3/Emu/Cell/SPUTaskHLE/mgo/ppu_geo_collision_hooks.h
rpcs3/Emu/Cell/SPUTaskHLE/mgo/drawassist_3120.h
rpcs3/Emu/Cell/SPUTaskHLE/mgo/drawassist_4f20.h
```

The build root is `/mnt/0E88FF7D88FF619F/Arch/ughhanotherrpcs3/rpcs3-savemgo/`
— an Arch Linux WSL mount, cross-compiled to `x86_64-w64-mingw32`. The replica
names its fourth file `mgo/ppu_modelsetup_hook.{h,cpp}`; the fork has no
separate file for it, which is consistent with `mgo_ppu_hooks.cpp` carrying it
inline.

## The image-patch table is a gate, not a worker

`get_image_patches()` returns one record, `mixer.single_bus` on
`SPU-ae8a75…16d9966f9`. The record is **0x28 (40) bytes**:

```
+0x00 name         "mixer.single_bus"
+0x08 image_hash   "SPU-ae8a75...16d9966f9"
+0x10 offset       0x0000fc04
+0x14 match        0x4c00439f
+0x18 replacement  0x4080001f
+0x1c unused       0
+0x20 fn           0x143ced610
```

and `fn` is two instructions:

```
0x143ced610  movzx eax, byte ptr [0x1463bacd4]
0x143ced617  test  al, al
0x143ced619  setne al
0x143ced61c  ret
```So unlike the module hooks — whose `fn` is a worker — an image patch's `fn` is a
**predicate**, and this one is exactly "is Audio Mixer Fast Path enabled".
That is the config key the patch is named after, so `Audio Mixer Fast Path` is
no longer one of the inert settings: it is wired, live, to the single image
patch in the fork.

## The patch geometry: a guarded four-byte store

The three u32s are now decoded. The patch loop of the same consumer function
does, per entry:

```
0x1434ae9be  mov  eax, dword ptr [rdi + r15 + 0x10]   ; offset
0x1434ae9c3  mov  dword ptr [rsp + 0x4c], eax        ; &offset
0x1434ae9c8  mov  dword ptr [rsp + 0x48], 4           ; &size, hardcoded 4
             ...  translate(&offset, &size) -> ptr
0x1434ae9b5  call [rdi + r15 + 0x20]                  ; the gate (before the read)
0x1434ae9f1  mov  edx, dword ptr [rax]                ; the 4 image bytes, native load
0x1434ae9f5  bswap ecx                                ; ... read as big-endian
0x1434ae9f7  mov  r8d, dword ptr [rdi + r15 + 0x18]   ; replacement
0x1434ae9fc  cmp  ecx, dword ptr [rdi + r15 + 0x14]   ; match?
0x1434aea01  je   apply
0x1434aea07  cmp  ecx, r8d                            ; already applied?
0x1434aea0a  je   rewrite
0x1434aea12  xor  ecx, ecx                            ; untranslatable -> report 0
```

and the two writing arms:

```
0x1434ae967  bswap r8d        ; 0x4080001f -> 0x1f008040 as stored bytes
0x1434ae96a  mov  edx, r8d
0x1434ae96d  mov  dword ptr [rax], edx    ; both arms store 4 bytes
```

So: read one big-endian word at `offset`, and if it equals `match`, write
`replacement` in its place. The store size is the literal `4`, never a record
field, so a patch is always exactly one instruction wide.

Two details worth keeping:

- The **byte swap is the point**. The local store holds big-endian PPC, and the
  fork's loads are native little-endian, so `match` and `replacement` are
  compared against the *big-endian reading* of the image and written back
  byte-swapped.
- The **already-applied test is a side effect of the byte order**. At
  `0x1434aea07` the fork compares the swapped image word against the
  *unswapped* replacement. After a successful patch the image reads back as
  `0x4080001f` big-endian, so that compare hits, and the "already" arm simply
  writes the same bytes again. Re-deploying an image is therefore idempotent —
  but note the asymmetry: the `already` arm is only reached because the compare
  uses the opposite convention to the `apply` arm.

Read as big-endian PPC64, both words are branches rather than data:

| word | primary opcode | fields |
|---|---|---|
| `0x4c00439f` | 19 (extended branch) | BO=0, BI=0, AA=1, LK=1, ext `0x1cf` — branch-conditional-indirect through CTR |
| `0x4080001f` | 16 (`bc`) | BO=4, BI=0, AA=1, LK=1, BD=+7 words |

So the patch retargets one control transfer — the mixer fast-path entry point —
rather than altering data. That reading is taken from the ISA field layout, not
from tracing the image, so the table entry is transcribed verbatim rather than
interpreted further.

**Correction:** an earlier revision said this record was 0x18 bytes. It read the
record's own bytes correctly but stopped counting at the first padding word.
The real strides come from the consumer, found by scanning for a `call` to
`get_image_patches` — one caller, at `0x1434ae513`, inside a 0x5d7-byte function
at `0x1434ae4f0`:

- the module-hook loop advances its index by **0x38** (56) per entry
  (`add r14, 0x38` at `0x1434ae683`), with the name pointer at +0x00, the
  image-hash pointer at +0x10, the site at +0x1c, the expected instruction at
  +0x20 and a minimum-verbosity byte at +0x30;
- the image-patch loop computes its end offset as `shl rax,3 /
  lea r14,[rax + rax*4]` at `0x1434ae628` — `count * 8 * 5` = `count * 40` —
  and advances by **0x28** (`add r15, 0x28` at `0x1434ae980`). The arithmetic
  and the literal agree, which is what confirms the 40-byte record.

Both strides, plus every byte sequence quoted above, are now asserted by
`mgo_verify_re.py`. A wrong stride is precisely the error class that yields a
plausible-looking table read from slightly wrong addresses — the same failure
that produced the earlier misaligned hook-record base.

That function also settles the `forced` flag: if the patch list is empty **or**
`forced` is set, it goes straight to the module-hook table and skips the image
patches entirely (`test rax,rax / je` then `test bpl,bpl / je` at
`0x1434ae51d`). So `forced` means "hooks only", which is not what the name
suggests and is worth knowing before wiring it up. In `forced` mode the
module-hook loop is also replaced by a validation pass that only checks each
hook's site is inside the image and warns if it is not — it installs nothing.

## The title gate: NPMG00010 and NPMG00020

Found inside `mgo_waits::ppu_lwarx_wait`, past its site lookup, as two
XOR-accumulate comparisons:

```
movabs r8, 0x31303030474d504e     ; xor against the stored id, then or-together
movzx  r9, byte ptr [rax + 8]
xor    r9, 0x30
or     r9, r8
je     accept
movabs r8, 0x32303030474d504e     ; second attempt, same shape
...
```

Those constants look like obfuscation and are not. They are plain ASCII:

```
0x31303030474d504e  =  "NPMG0001"
0x32303030474d504e  =  "NPMG0002"
```

and the ninth byte is compared against `0x30`, which is ASCII `'0'`. So the two
accepted strings are **NPMG00010** and **NPMG00020** — Metal Gear Online and
Metal Gear Online 2 — and the entire task-acceleration path is inert for any
other title.

This is a plain `strcmp` written as an XOR-accumulate. Worth saying outright,
because "XOR'd with 0x30" reads like a decode step and it is not one. The same
applies to the `0x45` masking noted elsewhere in these notes: that is
comparison, not encoding.

The replica applies this gate in `on_module_loaded` alongside the existing
executable-hash gate. For MGO2 the hash check is strictly stronger, so the title
gate changes nothing today; it is there because it is the gate that will start
mattering once other hooks stop being pinned to one executable hash.

## `mgo_waits::ppu_lwarx_wait` blocks the PPU thread for up to 50 seconds

An earlier draft of this file claimed the opposite — that the function only
*observes* which guest function is spinning and records it, and that the guest
still runs the loop. **That was wrong**, and getting it wrong is why this
section had to be rewritten. The recovered body at `0x1434af180` (0x1e4 bytes)
parks the thread:

```
0x1434af285  mov  rax, qword ptr [rcx + 0x498]   ; ppu_thread::rtime
0x1434af28c  lock or dword ptr [rcx + 0x14], 4    ; set cpu_flag::wait
0x1434af294  and  r9d, 0xfffffe00                 ; the waiter-count index...
0x1434af2f2  lock inc byte ptr [rdx + rdi]        ; ...entered
0x1434af2f6  and  r8d, 0x7fc0                     ; the reservation slot
0x1434af304  lea  r10, [vm::g_reservations + r8]
0x1434af318  add  r8, 4                           ; ext[0] = {&m_data + 4, ...}
0x1434af324  shr  r8, 0x20                        ; ...= rtime >> 32
0x1434af332  mov  r8d, 0xc350                     ; 50'000
0x1434af343  call atomic_wait_engine::wait        ; <-- blocks here
0x1434af348  lock dec byte ptr [rbx + rdi]        ; ...left
0x1434af34c  mov  eax, dword ptr [rsi + 0x14]
0x1434af356  call cpu_thread::check_state         ; if still set
```

That is `atomic_t<u64>::wait(rtime, atomic_wait_timeout{50'000})` on the VM
reservation covering the lwarx's address — byte for byte the 8-byte overload in
`rpcs3/util/atomic.hpp`, including the `old >> 32` extended entry it builds.
`0xc350` is 50000, the same timeout `SPUThread.cpp` uses for its own
reservation waits (100'000 and 200'000 elsewhere).

The real signature is `bool ppu_lwarx_wait(ppu_thread& ppu, u32 addr, u32 value)`,
not `(spu_thread&, u32 value, u32 spins)`.

### The gates, in order

1. **Site lookup** on the thread's guest PC (`ppu_thread::pc` at +0x474) against
   three 12-byte records at `0x144a25cf0`:

   ```
   { 0x00337070, 0x00337080, 0 }
   { 0x001b01f8, 0x001b0240, 2 }
   { 0x001999a8, 0x001999d8, 3 }
   ```

   Each record's own two PCs are exactly the two addresses its branch arms
   compare against, so the table is self-describing. `0x1b023f` appears in the
   body but is a *switch threshold*, not a site — it is one byte into the
   lwarx at `0x1b023c`.

2. **Configuration**, past the site: `cmp cl, 2 / jae` against the byte at
   `0x1463bac94` = `g_cfg + 0x51d4` = `g_cfg.mgo.task_acceleration`, so the
   wait requires **Task Acceleration ≥ standard**.
   `spu_task_hle::level_at_least` at `0x1434ae410` (COFF
   `_ZN12spu_task_hle14level_at_leastE21mgo_task_acceleration`) reads the same
   byte and is the same test.

3. **Budget gate**, reproduced exactly including the odd `cmovne`:

   ```
   r9b  = (value < budget)          cmp r8d, eax / setb r9b
   r10b = (value != 0)              test r8d, r8d / setne r10b
   if (budget != 0) r10b = r9b      test eax, eax / cmovne r10d, r9d
   proceed iff r10b == 1            cmp r10b, 1 / jne end
   ```

   The `cmovne` is what gives the third record (budget 0) its meaning: without
   it, `value < 0` is never true and that record could not fire at all. `value`
   is the word the lwarx just loaded, so the gate asks whether the spinner's
   idea of the data has converged yet. It is a threshold on how interesting a
   spin is, **not** a retry limit the host enforces — the only thing bounding
   the wait is the 50-second timeout.

4. **Title gate**, past the budget gate, through a 0x18-byte holder at
   `0x14504d928`: `+0x00` u8 tag (bit 0 = pointer valid, bits 1+ = length),
   `+0x08` inline `char[8]`, `+0x10` `const char*`. The length must be exactly 9
   (`cmp r8, 9`), then two XOR-accumulate compares against
   `0x31303030474d504e` / `0x32303030474d504e` with a ninth byte of `0x30`.
   Those constants are not obfuscation — they are plain ASCII:

   ```
   "NPMG0001" + '0'  =  NPMG00010   (Metal Gear Online)
   "NPMG0002" + '0'  =  NPMG00020   (Metal Gear Online 2)
   ```

   The whole reporter is therefore inert unless the running title is one of the
   two MGO games.

### The caller

`ppu_lwarx` at `0x143249d30` (COFF `_Z9ppu_lwarxR10ppu_threadj`) is upstream's
load with this appended to its tail:

```
0x143249fef  mov  ecx, dword ptr [rsi + 0x474]   ; the guest PC
0x143249ff5  cmp  ecx, 0x1b023f / jg  hi
0x143249ffd  cmp  ecx, 0x1999a8 / je  report     (and five more PCs)
0x14324a02f  movzx ecx, byte ptr [rip + ...]      ; task_acceleration
0x14324a036  cmp  cl, 2 / jae done
0x14324a069  mov  rcx, rsi / mov r8d, eax         ; thread, loaded value
0x14324a06f  mov  rsi, rax                         ; park the value
0x14324a072  call ppu_lwarx_wait
0x14324a077  mov  rax, rsi                         ; ...and restore it
```

i.e. exactly the six table PCs and a gate on one configuration byte. The
reporter then re-reads the PC and re-checks the site itself, so the six-way
switch in the caller is a fast path, not the only gate.

### The waiter's counter is `vm::g_resrv_waiters_count`, not a private guard

This is worth stating because it is easy to get backwards. The `lea` at
`0x1434af2eb` targets `0x146127ef8`, whose COFF symbol is
`_ZL21g_resrv_waiters_count.llvm.17337353629272204701` — the fork's renamed copy
of **`vm::g_resrv_waiters_count`**, the shared reservation-waiter table defined
in `SPUThread.cpp`. So the fork bumps a *byte* of that shared table to announce
the wait; it is a waiters count, not a re-entrancy flag on a private array.

Its index is the fork's own hash, and it is **not**
`vm::reservation_notifier()`'s:

```
((addr >> 2) & 0x60) | popcount(addr & 0xfffffe00)
```

Because the granule mask `0xfffffe00` is 23 bits, the popcount term alone
reaches 23 and the maximum over all `u32` is `23 | 0x60 == 119`. An earlier
draft called this "a 64-entry re-entrancy guard" and sized the replica's array
at 64 — which is out of bounds, and was caught by `buildfiles/mgo_waits_test.cpp`
walking the range. The replica now bumps the shared table directly.

### The reservation mask is *not* a bug

An earlier draft also claimed `and r8d, 0x7fc0` was one bit wider than
`vm::reservation_acquire`'s `(addr & 0xff80) / 2`, and that the fork therefore
waited on the wrong granule. Also wrong, and also caught by the unit test:

```
(addr & 0xff80) / 2  ==  (addr >> 1) & (0xff80 >> 1)  ==  (addr >> 1) & 0x7fc0
```

Dividing by two is a shift, and `0xff80 >> 1` *is* `0x7fc0`. The two
expressions are the same function; the fork and upstream agree on every address.

### Two real quirks worth keeping

- **The pointer path's length test is broken.** At `0x1434af219` the pointer
  branch compares the *inline buffer's first qword* with 9
  (`cmp r8, 9` on `0x14504d930`) rather than comparing a length, so that path
  can only pass if those eight bytes spell the integer 9. The inline branch at
  `0x1434af22e` takes its length from the tag correctly. Both are reproduced.
- **`geo_getllar_ignore_gpr1` is inlined into `process_mfc_cmd`** and is now
  wired. The inlined copy is not the standalone `0x1434af140` function but a
  lambda at `0x1431e6450` (`_ZZN10spu_thread15process_mfc_cmdEvENK3$_3clEv`),
  decoded in full:

  ```
  0x1431e6456  mov  rsi, qword ptr [rcx]           ; the spu_thread
  0x1431e6459  mov  eax, dword ptr [rsi + 0x108c]
  0x1431e645f  mov  edx, dword ptr [rsi + 0x5c]
  0x1431e6462  cmp  eax, edx / je  zero
  0x1431e6466  mov  r8d, dword ptr [rsi + 0x1090]
  0x1431e646d  mov  r9, qword ptr [rcx + 8]
  0x1431e6471  cmp  r8d, dword ptr [r9] / jne zero
  0x1431e6476  movzx r8d, byte ptr [rip + 0x31d4816]   ; task_acceleration
  0x1431e647e  cmp  r8b, 2 / jb  zero
  0x1431e6484  mov  r8, qword ptr [rsi + 0xfd8]     ; spu_thread::ls
  0x1431e648b  cmp  dword ptr [r8 + 0x3000], 0x027a8043 / jne zero
  0x1431e6498  cmp  dword ptr [r8 + 0x3004], 0x82a2a543 / jne zero
  0x1431e64a5  cmp  dword ptr [r8 + 0x3008], 0x02433943 / jne zero
  0x1431e64b2  cmp  dword ptr [r8 + 0x300c], 0x824fb142
  0x1431e64bd  sete r8b                              ; all four matched
  0x1431e64c3  xor  r8d, r8d                         ; zero:
  0x1431e64c6  cmp  eax, edx / setne al
  0x1431e64cb  xor  r8b, 1                           ; <-- the inversion
  0x1431e64cf  test al, r8b / jne 0x1431e6587
  ```

  Note the `sete r8b` immediately followed by `xor r8b, 1`: the branch is
  taken when the signature does **not** match, i.e. the four words are what
  keep the thread on the fall-through path. `spu_thread + 0xfd8` is `ls`, and
  the config byte resolves to `0x1431e6476 + 8 + 0x31d4816 = 0x1463bac94` —
  **the same byte** the lwarx wait reads, i.e. the same
  `g_cfg.mgo.task_acceleration`. Both MGO wait paths are gated on the same
  setting, which is why `level_at_least()` covers both.

  The replica calls `geo_getllar_ignore_gpr1(*this)` once at the top of the
  `MFC_GETLLAR_CMD` case and folds it into the spin-validation predicate:

  ```cpp
  if (last_getllar_addr != addr
      || (!mgo_ignores_gpr1 && last_getllar_gpr1 != gpr[1]._u32[3])
      || perf0.get() - last_gtsc >= 5'000
      || (interrupts_enabled && ch_events.load().mask))
  ```

  because when the signature is present the guest is not really load-linking,
  so `gpr[1]` is not an address; comparing it against the remembered value
  would look like a brand-new spin every iteration and reset
  `getllar_spin_count`, which is exactly what the fork's `ignore gpr1` name
  says.


### Build integration

Every MGO source is listed in both build systems, so neither build silently
drops the feature:

- `rpcs3/Emu/CMakeLists.txt` — the four SPUTaskHLE sources plus `mgo_patches.cpp`
- `rpcs3/emucore.vcxproj` — same files, as `ClCompile` / `ClInclude` entries

Neither project file was complete before this pass; the CMake list had the
hooks but not `mgo_patches.cpp`, and the vcxproj had none of them. A missing
entry is the quietest possible failure — the build succeeds and the feature is
simply absent — so it is worth stating that they are now checked.

## `mgo_modelsetup`, decoded

The biggest subsystem in the fork, and the one the recovered symbol names
describe most completely: 161 symbols, spanning a thread pool, a task-image
verifier, a page-ownership tracker, a cost model, a splitter, and two lifters.

### The image table is two records

`mgo_modelsetup::images` at `0x144b36e20`, two records of 0x30 bytes. The
stride is not a guess — the launcher indexes with

```
0x143a1a1bc  lea rax, [rbx + rbx*2]
0x143a1a1c0  shl eax, 4
```

i.e. `index * 48`. The third "record" is the string `thread construction
failed`, which is how the launcher aborts when the pool will not start.

```
+0x00  u32  image_base    0x0100c280   0x01009480
+0x04  u32  entry         0x00009f18   0x00004cf0
+0x08  u32  hash_bytes    0x0000ac00   0x00005880
+0x0c  u32                0x0001c1c0   0x00012940
+0x10  u32                0x0000ab80   0x00005800
+0x14  u32                0x0000ac80   0x00005900
+0x18  u32                0x0000ab40   0x00005790
+0x1c  u32                0x0003fd80   0x0003fde0
+0x20  u32  chunk_count   0x00000100   0x00000080
+0x24  u32                0            0
+0x28  u64  image_hash    0x743c495a49e3aaa3   0xf977d8259dcadeae
```

`image_base` is what `gpr[5]` is compared against, at `0x143a1a0b5`
(`cmp ebp, 0x100c280`) and `0x143a1a0bd` (`cmp ebp, 0x1009480`), and again
inside `detail::run` at `0x143ac5acc` / `0x143ac5adb`. So the guest is asking
to set up one of exactly two images.

### `read_spurs_args` is complete (0x143ac5380, 0x19a bytes)

Its symbol names a `direct_mem&` first parameter that the body never uses — it
reads guest memory through a process-wide base pointer at `0x1461845f8`. The
real first argument is the task count. Reproduced in this order, all of it
confirmed byte-for-byte by `mgo_verify_re.py`:

1. `cmp ecx, 7 / ja` — more than 7 tasks is out of range. Note this is *one
   short* of the eight the pool serves, so an eight-task launch is rejected by
   the fork too.
2. Granule `0x121a` of the reproduced-LS map must be mapped — that is exactly
   `0x121aef8 >> 8`, the guest word holding the SPURS task queue pointer.
3. `bswap` that word, then a **backwards** window guard (§ below).
4. The block header word at `queue - 0x8000`, byte-swapped.
5. `addr = header + tasks * 0x3b00 + 0x5c40`; reject on wrap.
6. Granules `addr >> 12 .. (addr + 3) >> 12` must be mapped.
7. `context = bswap32(guest[addr])`; `context & 0x7f` must be zero — a
   128-byte alignment requirement.
8. `guest_valid(context | 0x60, 0x10)` — the `or 0x60` looks odd until the
   alignment test above is accounted for: bits 5 and 6 are known clear.
9. Two byte-swapped qwords: `guest[context + 0x68]` → out `+0x08`, and
   `guest[context + 0x60]` → out `+0x10`.

### The images are ELFCLASS32, not ELFCLASS64

`detail::load_image` (`0x143ac5520`, 0x3ba bytes, complete) checks
`EI_CLASS == 1` and `EI_DATA == 2`, and reads `e_phoff` at `+0x1c` and
`e_phnum` at `+0x2c`. Both of those are **Elf32** offsets — in Elf64 they are
at `+0x20` and `+0x38`. So the images are big-endian 32-bit-class PowerPC64
images, which is the shape SPURS task images have. `e_machine` at `+0x12` is
`0x17` (EM_PPC64), and the program headers are 32 bytes each.

Per header: `p_type == 1` (PT_LOAD) only, `p_vaddr` must be ≥ `0x3000`,
`p_filesz <= p_memsz`, and `p_vaddr + p_memsz <= 0x40000`. The segment's bytes
are read from guest `image_base + p_offset` and land at `p_vaddr` in the
buffer.

The verification is FNV-1a-64 over `scratch[0x3000 .. hash_bytes)`, with the
published constants (`0xcbf29ce484222325` / `0x100000001b3`), compared against
the record's `+0x28`. The length is spelled `add r8d, 0xffffd000` — a
subtract of `0x3000` — which is why the hash starts at the image origin.

### The two window guards are different

The `lea eax, [X - 0x8000] / cmp eax, -4 / ja reject / shr 0xc / … / shr 0xc /
cmp / ja` sequence appears in a dozen places but in **two** shapes, and they do
not behave alike:

* **Forward** (`load_image` at `0x143ac5576`, the launcher's own guards at
  `0x143a19f61`): `lea ecx, [X + 0x33]`. The far end is ahead, so `first <=
  last` always and the map walk always runs.
* **Backwards** (`read_spurs_args` at `0x143ac53b0`): the far end is
  `add r8d, 0xffff8003`, i.e. a further `0x7ffd` *below* the near end. So
  `first > last` and the walk is skipped for every pointer from `0xfffd` up.
  The only gate that survives is `cmp eax, -4`, which rejects the three
  pointers `0x7ffd`, `0x7ffe` and `0x7fff` — exactly those whose window ends
  past `0xfffffffc`.

Both are reproduced verbatim in `mgo_modelsetup::{window_forward_ok,
window_backwards_ok}`; the unit test pins the asymmetry.

### `par::page_set::grow` doubles, it does not halve

`0x143b46c85` reads `sar rdx, 1` over `end - begin` and looks like a halving.
It is not: `end - begin` is a *byte* difference, so for a `vector<u32>` of N
elements it is `4N`, and the count that reaches `assign()` is `2N`. Read
literally as a halving the table shrinks under a full load and the probe loop
— `cmp r8d, edi / je` / `test r8d, r8d / je` / `inc edx` — never finds an empty
slot. The first version of the replica had this bug and hung the unit test;
the golden-ratio probe `((page * 0x9e3779b1) >> 12) & (capacity - 1)` with
`page + 1` stored so zero means empty is otherwise exactly as recovered.

### `par::tracker` is two page sets and two access lists

```
+0x00  page_set         read pages      (on_get inserts here)
+0x38  page_set         written pages   (on_put inserts here)
+0x70  vector<{u32,u32}> reads
+0x88  vector<{u32,u32}> writes
+0xa0  u32*             pages of interest
+0xa8  u64*             their timestamps
+0xb0  u32              capacity of those two arrays
+0xb4  u32              how many are filled
```

The `rdtsc` stamp at `0x143b46946` compares `esi` against `order_pages[count]`
*before* `esi` is shifted down to a page number at `0x143b469b5`, so the watched
value is the address, not the page. Reproduced as written.

### What is not recovered

The two lifters (`mgo_modelsetup_bg_lift`, `mgo_modelsetup_chara_lift`),
`detail::run`'s 0xc28-byte body, the two `task_io` DMA callbacks and the chunk
scheduler are compiled code. `detail::run` is where the interesting status
codes come from — it writes `2` for a non-model-setup image, `5` for unmapped
guest memory, `4` for unexpected SPURS arguments — and the replica reproduces
the checks that produce them, then reports `built without SSE4.1/SSSE3/FMA3`,
which is the fork's own wording for "this build has no native lift kernel".

## `mgo_pl_motion_mix`, decoded

28 symbols. The front end is `pl_motion_mix_launch` at `0x143a14dc0`, 0xae3
bytes, hooked as record 0 of the subsystem. The rest is scaffolding around it:

```
0x143a14dc0  pl_motion_mix_launch          the front end, 0xae3 bytes
0x143a1aa50  detail::scratch               the per-thread staging buffer
0x143a1aad0  detail::clean                the dirty-map walk
0x143a1ac50  detail::get                  thirteen call sites
0x143a1adb0  detail::set_nv               complete
0x143a263c0  mgo_pl_motion_mix::run_launch
0x143a279b0  detail::scratch()::{lambda}  the allocator
0x143a1b1c0  pm_082c0   stage 1      0x143a1dfb0  pm_0a7a8  stage 2
0x143a26410  pm_04780   stage 3
             pm_05b70 pm_07030 pm_074b8 pm_078d8 pm_0a328 pm_0bc28 pm_03f38
             pm_0bba0                    the instrumented lift's own probes
```

`pm_NNNNN` is a **guest function offset**, not a code address in this binary -
the fork lifts a whole guest function by where it starts in the guest image,
which is why the names survive and the bodies do not.

### The decline table has ten entries, indexed directly

`0x144b3789c`, ten int32 rel32 offsets, read by

```
0x143a15486  lea     rax, [rip + 0x112240f]   ; 0x144b3789c
0x143a1548d  movsxd r11, dword ptr [rax + r12*4]
0x143a15491  add     r11, rcx
```

with no bound check on `r12`. The COFF symbol
`switch.table._ZN12_GLOBAL__N_120pl_motion_mix_launch...` sits at the table.

**Correction to an earlier revision of these notes**, which recorded eight
entries indexed `reason - 1` behind a `"?"` default. Every staged exit funnels
through one pair:

```
0x143a15476  add    r14d, 0xfe
0x143a1547d  movzx  r12d, r14b
```

so the index is `(staged + 0xfe) & 0xff` - the staged value is two *above* the
reason it reports (`0xa` reports 8, `0xb` reports 9). Five early exits bypass
the table and load a string with a plain `lea`, so those five appear twice.

| # | text |
|---|---|
| 0 | `unmapped guest memory` |
| 1 | `unexpected parameter block` |
| 2 | `phase word <= 3` |
| 3 | `task object busy (obj+0xa0 != 0)` |
| 4 | `misaligned DMA (the task would halt)` |
| 5 | `W(S+4) > 128` |
| 6 | `N > 128` |
| 7 | `bone descriptor changed by a stage` |
| 8 | `stage clobbered callee-saved registers` |
| 9 | `lifted code declined (load/store outside reproduced LS, budget, halt)` |

Declines are reported at `mgo_ppu_hooks.cpp:0x24`.

### The parameter block

`gpr[3]`, 0x124 bytes, `[S, S + 0x100]` walked first (`lea edx, [rcx + 0x100]`
/ `cmp edx, -0x24`, then the page walk). Two self-pointers, read **raw, with no
byte swap** - they are the guest's own pointers compared with the guest's own
arithmetic:

```
0x143a14e5e  guest[S + 0x100] == S + 0xa4   and >= 4      (the phase gate)
0x143a14e75  guest[S + 0x104] == S + 0xa0   and <= -8
0x143a14fdd  guest[S + 0xa0]  == 0                          (not busy)
```

The +0x100 word is both a self-pointer and a phase word, which is why reason 2
exists and why the comparison is `>= 4` rather than a bounds test.

### Seven descriptors, and `get`'s real argument order

`detail::get` takes **rcx = the scratch, edx = the destination offset inside it,
r8d = the guest address, r9d = the size** - visible in all thirteen call sites,
e.g. `mov rcx, rdi / mov edx, 0x13080 / mov r8d, r12d / mov r9d, 0x5d0`. An
earlier revision of these notes wrote the guest address into `edx`, which put
every buffer in the wrong place.

| +S | size | scratch | what |
|---|---|---|---|
| `0x108` | `0x5d0` | `0x13080` | bone table; the width is byte 4 |
| `0x110` | `0x3bf0` | `0x13680` | matrix block, and the only one written back |
| `0x120` | `0x10` | `0x17280` | the 16-byte bone descriptor |
| `0x114` | `0x120` | `0x17300` | six sub-descriptors live here |
| `0x118` | `0x120` | `0x17480` | |
| `0x10c` | `0x280` | `0x17600` | |
| `0x11c` | `0xa0` | `0x17880` | |

All seven are read raw and byte-swapped as one group at
`0x143a14ff0`-`0x143a15003`, and **the OR of all seven must be 16-byte aligned**
(`test cl, 0xf`, reason 4) - a misaligned SPU DMA address faults the task, which
is what the decline text says.

Six sub-descriptors at `0x17320`/`0x17350`/`0x17380`/`0x173b0`/`0x173e0`/`0x17410`,
each a big-endian word assembled from four separate byte loads, each
`W * 16` bytes wide, landing at `0xc680`/`0xce80`/`0xd680`/`0xde80`/`0xe680`/`0xee80`.
Each payload then gets its own address written into its first word:

```
0x143a15332  mov dword ptr [rdi + 0x17320], 0x80c60000
0x143a1533c  mov dword ptr [rdi + 0x17350], 0x80ce0000
0x143a15346  mov dword ptr [rdi + 0x17380], 0x80d60000
0x143a15350  mov dword ptr [rdi + 0x173b0], 0x80de0000
0x143a1535a  mov dword ptr [rdi + 0x173e0], 0x80e60000
0x143a15364  mov dword ptr [rdi + 0x17410], 0x80ee0000
```

Those immediates are the *little-endian* image of big-endian `0x0000c680`,
`0x0000ce80`, ... - which is why they look like floats and are not.

### The bone descriptor, and which word is which

Four words at `0x17280`, two read as `bswap` dwords and two assembled out of
bytes. They are spilled to the stack before the two counted gets, and the same
slots are read back by the writebacks, so the register traffic pins each one
down:

```
0x143a154cd  mov dword ptr [rsp + 0x44], r8d    ; W0, from bytes 0x17280..3
0x143a154da  mov dword ptr [rsp + 0x2c], eax    ; W1, bswap of 0x17284  -> N
0x143a15513  mov dword ptr [rsp + 0x28], r11d   ; W2, from bytes 0x17288..b
0x143a15520  mov dword ptr [rsp + 0x24], ecx    ; W3, bswap of 0x1728c
```

```
0x143a15547  shl   eax, 4              ; N * 16
0x143a1554a  lea   r9d, [rax + rax*4]   ; N * 80
0x143a15551  get(s, 0x10800, W0, N * 80)
0x143a1557a  get(s, 0xfe80,  W2, N * 16)
```

Both caps are `cmp eax, 0x80 / ja` - `0x143a150ef` for the width (byte 4 of the
`+0x108` buffer, reason 5) and `0x143a1552a` for `N` (reason 6).

`0x10800 + 128 * 80 == 0x13000` exactly, and `0xfe80 + 128 * 16 == 0x10680`,
so both caps are exactly what keeps the counted buffers in their bands.

**`0xf680` is never DMA'd in.** It is named exactly once in the launcher, at the
last writeback (`0x143a1583b`), and it is 0x800 bytes below `0xfe80` - i.e.
immediately under the `W2` buffer. So it is where the three stages put their
result, and `W3` is the guest address they are written back to.

### `run_launch` is the proof obligation

Fifty bytes. Four bswapped words out of the 16-byte descriptor against four the
caller snapshotted before the stage ran; a mismatch is what reports
`bone descriptor changed by a stage`. The lift may read the descriptor, not
write it.

Separately, after every stage a 0x300-byte snapshot at `[rsp + 0x90 .. +0x390]`
is compared against `[rsp + 0x100 .. +0x400]` with
`vpcmpeqb / vpmovmskb / xor 0xffff`; a mismatch is reason 8. And after the
second `run_launch` the output record at scratch `+0x13000` must read
`0x10800`, the saved width, `0xfe80` and `0xf680`, or reason 7.

### `set_nv` reverses everything, then overwrites most of it

Eleven groups of sixteen bytes read **four bytes in**
(`vmovdqu xmm0, [rdx + 0xc]`, then `vpinsrd` at `+8`, `+4`, `+0` into lanes
1, 2, 3) and stored forwards from `ctx + 0x90`, so each group's four words come
out reversed. A twelfth group at `ctx + 0x140` comes out of
`vpermilps 0x1b`, reversed again. Then `ctx + 0x110 .. ctx + 0x300` is filled
with one 16-byte constant from `0x144b23160`
(`ed 5e ed 5e 5a 5a 5a 5a 58 00 00 00 58 ad de 7f`), which lands on top of
groups 8, 9, 10 *and* the twelfth.

The two tables are 0xc0 bytes each at `0x144b2a154` and `0x144b2a214`; they
differ only in their first four groups and share their last one.

### MXCSR

```
0x143a1536e  stmxcsr [rsp + 0x70]
0x143a15377  mov dword ptr [rsp + 0x70], 0xffc0
0x143a1537f  ldmxcsr [rsp + 0x70]
```

0xffc0 is DAZ, FZ, round-to-nearest, all masked - the SPU's denormal behaviour.
Saved and restored around the whole run, on every exit path.

### The staging buffer has **four** dirty maps, not three

**Correction.** `scratch_t` is 0x40020 bytes - 0x40000 of data and four 64-bit
maps at `+0x40000`, `+0x40008`, `+0x40010`, `+0x40018`. `clean()` walks all four
with bases `0x00000`, `0x10000`, `0x20000`, `0x30000`, and the `memset` of
0x40020 is exactly the object.

A bit covers a 0x400-byte block, the band is `addr >> 16`, and the bit within
the band is `(addr >> 10) & 63` - which the fork gets for free because x86 masks
the shift count in `shl rdx, cl`.

Only band 1 is filtered, and the filter compares each **block's start** against
two ranges:

```
0x143a1ac19  or   eax, 0x10000          ; | 0x10000, i.e. the absolute address
0x143a1ac1e  cmp  eax, 0x13080   / jb  clear
0x143a1ac25  cmp  eax, 0x13251   / setb
0x143a1ac2d  add  ecx, 0xffffc980        ; - 0x3680
0x143a1ac33  cmp  ecx, 0x37f1    / setb
```

which makes the effective ranges `[0x13080, 0x13251)` and `[0x13680, 0x16e71)`.
Because the comparison is on block starts, the first range protects *nothing*:
it lies entirely inside block 12 (`0x13000`), whose start is below it. The
second protects blocks `0x13800 .. 0x16c00` - the matrix block, minus its own
first partial block and minus the tail past `0x16e71`. The bone descriptor at
`0x17280` is past both ranges and *is* cleared, which is why the count-sized
gets re-read it rather than trusting what survived.

### The granule map is indexed by `addr >> 12`

**Correction**, and it applies to `mgo_modelsetup` too: the map byte is one
0x1000-byte **page**, not 0x100. Both walks compute `shr r10d, 0xc` and step
with `inc`, then read `byte ptr [rdi + r11]`.

The skip bits round **up**, which is what keeps them from stalling:

```
0x143a1ad06  movzx ebx, byte ptr [rdi + r11]
0x143a1ad0e  not  edi / test dil, 0x81 / jne reject   ; presence first
0x143a1ad1a  test bl, 0x40 / jne <and 0xffffff00 / add 0x100>
0x143a1ad1f  test bl, 0x20 / jne <and 0xfffffff0 / add 0x10>
0x143a1ad24  inc r10d
```

so a bare skip bit without 0x81 is rejected before the jump is taken, and
neither jump can fail to advance even at granule 0. (An earlier revision wrote
the jumps as `((g + 1) & ~0xff) >> 8`, which stalls forever at granule 0 - it
was found by a unit test that hung.)

### `get`'s parity gate

The marking computes `first = off >> 10` and `last = (off + size) >> 10`, and
marks `first` only when `(first + last)` is even:

```
0x143a1ad3a  lea  eax, [r8 + rcx]
0x143a1ad40  test al, 1
0x143a1ad44  jne  <skip>
```

When it skips, the loop that follows starts from `first + 1` in a register the
skip path never wrote. The condition's purpose is not identifiable, so the
replica marks the whole range, which can only ever clear more.

### What is not recovered

The three stages and `run_launch`'s inner work are compiled native code - the
arithmetic that blends bone matrices. The replica reproduces the entire front
end (DMA plan, both caps, the sub-descriptors, the MXCSR discipline, all three
stage/prove cycles, the output record check and all three writebacks) and then
declines with the fork's own reason 9, leaving `out.handled` false so the guest
blends for itself.

## Remaining work

Ordered by what unblocks the most, not by size.

### Done

| Item | State |
|---|---|
| Hook framework: 8 records, install, `bl` rewrite, HLE stub dispatch | complete, verified against `MGO2.ELF` |
| `call_regs` layout, `call_site` (`lr-4`) dispatch | complete, layout confirmed from handler reads |
| `pool_start` (hooks 5/6) | **complete** — the whole 0xba-byte body is recovered and implemented |
| `mgo_waits::ppu_lwarx_wait` | **complete** — it *blocks* the PPU thread on the VM reservation for up to 50 s, behind Task Acceleration ≥ standard and a 9-character `NPMG0001x` title gate |
| `mgo_waits::geo_getllar_ignore_gpr1` | complete — four-word LS signature at +0x3000 |
| `line_check` front end | **complete** — four tags, five guest globals, ring, records, all eight decline reasons; declines `native_not_built` since the native kernel is not reproducible |
| `drawassist_4f20` dispatch | **complete** — 31 opcodes, 16-byte records, inline `op22`, nine preconditions, 41-block integrity scan |
| `drawassist` module hooks | **complete** — both records transcribed field for field, and the gate is unsatisfiable, so neither installs (as in the reference build) |
| `drawassist_4f20` unit test | `buildfiles/mgo_drawassist_test.cpp`, 15 checks, no emulator needed |
| `mgo_modelsetup` front end | **complete** — image table, 9-entry status table, `read_spurs_args`, `load_image`, both window guards, `page_set`/`tracker`, SPURS argument gates; declines `built_without_sse` since the two lifters are not recoverable |
| `mgo_modelsetup` unit test | `buildfiles/mgo_modelsetup_test.cpp`, 94 checks, no emulator needed |
| `mgo_pl_motion_mix` front end | **complete** — 10-entry decline table, the parameter block, all 13 `get` calls, six sub-descriptors, both 128 caps, `set_nv`, `run_launch`'s descriptor proof, the four dirty maps and `clean()`'s live-range filter; declines `lifted_code_declined` since the three stages are not recoverable |
| `mgo_pl_motion_mix` unit test | `buildfiles/mgo_pl_motion_mix_test.cpp`, 203 checks, no emulator needed |
| Decline reporting (`note_decline` / `last_decline`) | complete — the fork's file/line/message triple |
| `mixer.single_bus` gate | gate reads `Audio Mixer Fast Path` |
| `mixer.single_bus` geometry | **complete** — guarded one-instruction store, byte-swapped, idempotent |
| SPU image hook seam, `on_stop`, `on_embedded_spu_image` | wired |

### Name audit against the binary

Every MGO symbol in `rpcs3.exe.bak` (352 of them, COFF, `c++filt`-demangled)
was diffed against the replica's identifiers. Three real divergences were found
and fixed; the rest already matched.

| binary symbol | was | now |
|---|---|---|
| `mgo_da4f20_detail::*` (36 symbols) | `mgo_drawassist::*` | `mgo_da4f20_detail::*` |
| `mgo_geo_coll::why` | `mgo_geo_coll_hooks::geo_decline_reason` | `mgo_geo_coll::why` |
| `mgo_geo_coll::ls_image` | `mgo_geo_coll_hooks::tag_probe` | `mgo_geo_coll::ls_image` |
| `mgo_geo_coll::range`, `g_counters`, `detail::vworker` | absent | added (all three verified present in the binary) |
| `mgo_motion_play::task_run` members | "7 passes" in the notes | nine passes, all nine names present |

Confirmed to match already: `mgo_pl_motion_mix::{detail::clean, detail::get,
detail::nv_set, detail::nv_stage1, detail::nv_stage23, detail::scratch,
detail::scratch_t, detail::set_nv, result, run_launch}`;
`mgo_modelsetup::{detail::read_spurs_args, detail::load_image, detail::run,
detail::task_io::*}`; `mgo_geo_coll_hooks::{line_check, pool_start}`;
`mgo_drawassist_{4f20,3120}`; `spu_task_hle::mgo_waits::{ppu_lwarx_wait,
geo_getllar_ignore_gpr1, level_at_least}`.

Nothing was invented: every identifier the replica now uses was checked against
the symbol table, and the only names that appear nowhere in the binary are the
two old ones this audit replaced (`geo_decline_reason`, `tag_probe`). The three
names added to `mgo_geo_coll` — `range`, `g_counters`, `detail::vworker` — were
each confirmed to exist (`mgo_geo_coll::range` ×3, `g_counters` ×1,
`detail::vworker::vworker()` at `0x143ac4f90`) *before* being added.

Namespaces the binary has that the replica deliberately does **not** declare are
`mgo_geo_lift_coll`, `mgo_modelsetup_bg_lift`, `mgo_modelsetup_chara_lift`,
`mgo_pl_motion_mix_lift`, `mgo_geo_coll_rt`, `mgo_geo_rt`, `mgo_ms_rt`,
`mgo_pmm_rt` — the lifted kernels and their runtimes, all shipped as compiled
code. See item 2 below.

One free function outside any namespace is in the same category:
`mgo_drawassist_detail::da_mat_combine(u8*, u32, u32, u32)` at `0x143ce3030`.
It is the vectorised 4×4 matrix product the drawassist kernel uses
(`vpshufb` to deinterleave, `vpcmpeqd` against a broadcast mask to select rows,
`vfmadd231ps` for the multiply-add chain, four 16-byte loads per operand from
`rcx + off`) and it is a compiled body with no symbols behind it, so it is not
attempted. Note the spelling: `mgo_drawassist_detail` is a *free function*,
distinct from both the `mgo_da4f20_detail` namespace and the
`mgo_drawassist_4f20` / `mgo_drawassist_3120` free functions.

### Next, in order

**1. ~~The lwarx wait policy.~~ Done.** The policy is recovered and
implemented: it blocks the PPU thread on the VM reservation for up to 50
seconds, gated on one of six guest PCs, Task Acceleration ≥ standard, the
budget comparison, and a nine-character MGO title id. Two errors in the earlier
write-up of it — that it did not wait at all, and that its `0x7fc0` mask was one
bit too wide — were both disproved by `buildfiles/mgo_waits_test.cpp`, and the
"64-entry guard" it was believed to use turned out to be
`vm::g_resrv_waiters_count`. The remaining list starts at the collision kernel.

**2. The native collision kernel itself.** `line_check`'s entire front end is
decoded and implemented (four tags, five guest globals, the ring, the two
12-byte records, `col_flag`, all eight decline reasons). What it hands off to is
a x86-64 reimplementation of the guest's collision routine that the fork ships
as compiled code. That is not recoverable from a symbol table — only its
observable contract is, and the replica declines with the fork's own
`native not built` reason instead.

**3. The 31 drawassist command bodies.** The dispatch, the wire format, the
inline `op22`, all nine `drawassist_4f20.h` preconditions, the 41-block
integrity scan and both module-hook records are decoded and implemented. What
remains is the body of each `opN` — 30 functions totalling roughly 0x7400 bytes
of x86-64 that reimplement SPURS drawassist commands, plus the 0x2880-byte
`3120` back end that references no strings at all. Since the gate that would
install either hook is unsatisfiable, none of it runs in the reference build
either, so this is the lowest-value item on the list.

**4. `motion_play`'s nine passes.** (An earlier draft said seven; the
symbol table has nine members of `mgo_motion_play::task_run` — `get`, `put`,
`root`, `mirror`, `crossfade`, `release_motion`, `fetch_points`, `owner_pass`,
`blend_pass` — and all nine names are reproduced in the replica.)
`pl_motion_mix`'s front end is now done
(see above); what is left there is the three stage bodies themselves, the same
class of item as item 2. `mgo_motion_play`'s nine passes are the same story.
Both name their lifts by *guest function offset* (`pm_03f38`, `pm_04780`,
`pm_05b70`, ...) - the fork lifts whole guest functions by address, not by
opcode - so nothing about them survives in a symbol table but the name.

**5. `modelsetup`'s lifters.** The front end is now done — the image table,
the nine-way status table, `read_spurs_args`, `load_image`, both window
guards, `par::page_set`/`par::tracker` and the SPURS_TaskStart argument gates
are all decoded and implemented. What remains is `detail::run`'s 0xc28-byte
body, the two `task_io` DMA callbacks, the chunk scheduler, the cost model and
the splitter (`plan_split` / `alias_ranges` / `chunk_slots`), plus the two
native lifters themselves. That is the bulk of the subsystem by volume and
none of it is describable from a symbol table.

**6. ~~Wire the 6 inert config keys.~~ Located; not yet wired.** All nine keys
are now read out of the reference build rather than guessed — they are the
string immediates in `cfg_root::node_mgo`'s constructor at `0x1431b6720`
(COFF `_ZN8cfg_root8node_mgoC2EPN3cfg4nodeE`), each built on the stack and
handed to `0x1432b74c0`. The member offsets and defaults:

| member | key | default | live reader |
|---|---|---|---|
| `+0x058` | `Disable Limiter` | **true** | `patch_engine::apply` |
| `+0x098` | `Disable HUD` | false | `patch_engine::apply` |
| `+0x0d8` | `Disable Lobby BGM` | false | `patch_engine::load` |
| `+0x118` | `Disable Blur` | **true** | `patch_engine::apply` |
| `+0x158` | `Lower Exposure` | **true** | `patch_engine::apply` |
| `+0x198` | `SPU Culling Wait Bypass` | **true** | `patch_engine::apply` |
| `+0x1d8` | `Task Acceleration` | **`basic`** (1) | `level_at_least` (×5) |
| `+0x218` | `Audio Mixer Fast Path` | false | image-patch gate |
| `+0x258` | `UPnP Port` | `0x1662` = 5730 | none |

Every one of the eight `_bool`/`_enum` members gets **two** stores, and both are
required to pin its default. `cfg::_bool` and `cfg::_enum` share the same
three-byte tail (`Utilities/Config.h`):

```cpp
class _enum : public _base
{
    atomic_t<T> m_value;   // +0x3c  the current value
    T original_def;        // +0x3d  the ctor argument, never mutated
  public:
    T def;                 // +0x3e  the mutable default
    _enum(node* owner, const std::string& name, T def = {}, bool dynamic = false)
        : _base(type::_enum, owner, name, dynamic)
        , m_value(def), original_def(def), def(def) {}
```

All three initialise from the same argument, so the compiler folds the first two
into one 2-byte store and emits the third separately:

```
66 c7 86 <disp32> <imm16>   mov word ptr [rsi + disp32], imm16   ; +0x3c, +0x3d
c6    86 <disp32> <imm8>    mov byte ptr [rsi + disp32], imm8    ; +0x3e
```

For `Task Acceleration` (`0x1431b6a7e`, member `+0x1d8`):

```
0x1431b6a77  mov qword ptr [rsi + 0x1d8], rax     ; cfg::_enum vtable
0x1431b6a7e  mov word  ptr [rsi + 0x214], 0x0101   ; m_value = original_def = 1
0x1431b6a87  mov byte  ptr [rsi + 0x216], 1        ; def = 1
```

Two earlier drafts of this table were wrong, both from scanning only the word
store. It was first read as a bool `true`, and then as "five keys have a store
and the rest keep their zero-initialised value" — the missing `c6 86` byte
stores are easy to miss because the scan pattern was anchored on `66 c7 86`.
All eight keys have both stores; only the *immediates* differ.

### `Task Acceleration` defaults to `basic`, settled

The three accessors pin the layout, and they agree with `Utilities/Config.h`:

```
0x1431c45a0  from_default():      movzx eax, byte ptr [rcx + 0x3e]
                                    xchg   byte ptr [rcx + 0x3c], al
0x1431c45b0  restore_defaults():  movzx eax, byte ptr [rcx + 0x3d]
                                    mov    byte ptr [rcx + 0x3e], al
0x1431c45d7  to_string():         movzx ecx, byte ptr [rdx + 0x3c]
```

`from_default()` is `m_value = def`, so it reads **`+0x3e`**, not `+0x3d`;
`restore_defaults()` is `def = original_def`, so it reads `+0x3d` and writes
`+0x3e`. (An earlier note here claimed `from_default()` read `+0x3d` and that
this was an "upstream `cfg::_bool` quirk" differing from `cfg::_enum` at
`0x1431b7850`. That was wrong on both counts: the offset is `+0x3e` because
that is where `def` lives, `cfg::_bool` and `cfg::_enum` have the *same* layout
and the same accessors, and the `xchg` is just the compiler's way of writing
one byte from a byte it already loaded.) So `+0x3c` is the current value,
`+0x3d` the pristine ctor argument, `+0x3e` the mutable default.

The member base is `+0x1d8` and the constructor writes `1` to all three, so the
default is `1`. `0x0101` means "`01`, `01`" byte for byte — **not** a boolean
`true` — which matters only for the seven `_bool` members, where the same
`0x0101` word store *is* a bool pair.

And `1` is `basic`. The ordinals are confirmed from `to_string`'s jump table at
`0x144994200` (a 4 × 8-byte table of `const char*`, indexed by the byte at
`+0x3c`, with `cmp cl, 3 / ja` as the bounds check):

```
case 0 -> 0x1449e7540 "Off"
case 1 -> 0x1449e72ce "Basic"
case 2 -> 0x1449e756d "Standard"
case 3 -> 0x1449e76f4 "Maximum"
```

So the fork starts on **`basic`**, which is what the replica already had, and
which is *below* the `>= standard` gate in `level_at_least()`. The consequence
is worth writing down: **on a fresh config with no saved value, none of the
MGO task hooks install**, because `ppu_lwarx_wait`, `geo_getllar_ignore_gpr1` and
the hook table's level gate all require at least `standard`. The user has to
raise `Task Acceleration` by hand for any of this code to run. Every MGO
behaviour in this fork is therefore off by default, which is consistent with it
being a compatibility fork rather than something the author expected people to
run with the hooks live.

Three of the names are assembled from pieces the disassembler shows as
unrelated stores, which is why they are worth spelling out:

```
0x1431b69b4  movabs rcx, 0x7373617079422074     ; "t Bypass" (reversed)
0x1431b69c2  movups xmm0, [rip + ...]           ; "SPU Culling Wai"
0x1431b69cc  mov  byte [rax + 0x17], 0          ; -> "SPU Culling Wait Bypass"

0x1431b6a35  movups xmm0, [rip + ...]           ; "Task Accelerati"
0x1431b6a41  mov  word  [rsp + 0x39], 0x6e     ; "o" + "n"
                                            -> "Task Acceleration"

0x1431b6b12  movabs rax, 0x726f5020506e5055     ; "UPnP Por"
0x1431b6b21  mov  word  [rsp + 0x31], 0x74      ; "t"
                                            -> "UPnP Port"
```

What remains is the reader side: six keys still have a Qt binding and no
consumer. (This paragraph used to claim `Disable Limiter` and `Disable HUD`
were "the cheapest real wins since both are plain booleans with obvious call
sites in the renderer and the frame limiter". That was speculation dressed as a
finding, and it was wrong — see "Every MGO setting is read" below. They are read
by the patch engine, not by the renderer.)

### One default was wrong in the replica

Re-deriving the table above from bytes rather than from the previous notes
turned up a real defect rather than just a documentation one:
`Disable Lobby BGM` was declared `true` in `system_config.h`, but the
constructor stores `0` to all three of its bytes:

```
0x1431b68af  mov word ptr [rsi + 0x114], 0      ; m_value = original_def = 0
0x1431b68b8  mov byte ptr [rsi + 0x116], 0       ; def = 0
```

so the fork's default is **false**, and the replica now matches. The earlier
`true` came from the same incomplete scan that produced the `edx` and `from_default`
errors above. All nine defaults are now pinned by `buildfiles/mgo_verify_re.py`,
which checks both stores for all eight typed members plus `UPnP Port`.

### Explicitly not planned

The connection gate and fingerprint/anti-cheat code is ported but called from
nowhere. It is written and correct; whether to *activate* it is a user decision,
since it exists to lock the build to one server.

### A note on estimates

4 and 5 are not weekend work. `mgo_modelsetup` alone is ~45 recovered symbols
across a namespace tree with a thread pool, and reconstructing a lifter from
disassembly is not the same as writing one — the fork's has a correctness proof
obligation that a from-scratch implementation must rediscover. Framing honestly:
1–3 tractable, 4 substantial, 5 a project.

## Still not wired

The SPU module hooks now match on the image hash alone, with the module name
treated as optional documentation — which is what the fork does, and what
`deploy()` can actually supply, since it has no module name to give. (The
recovered table's `spu/spurs_drawassist.spu.task` is a description of where
the hooks live, not a match field.) An earlier revision required both and so
never installed the two `drawassist` hooks.

The fingerprint and anti-cheat helpers in `sys_ss.{h,cpp}`
(`mgo::host_fingerprint`, `mgo::detect_anti_cheat`,
`mgo::report_host_fingerprint`) are still called from nowhere.

## Every MGO setting is read

An earlier revision of this document claimed six of the nine config keys were
inert — declared, serialised, shown in the GUI, and never read. **That was
wrong**, and so was the reasoning that produced it: an xref scan was run
against addresses computed wrong (`node_mgo` is at `0x1463BAA80`, so `Disable
Limiter`'s value slot is `0x1463BAB14`, not `0x1463AAB14` — one bad hex digit
produces a confident zero).

Redone correctly, the scan is exhaustive: on x86-64 the only way to name an
absolute address is `[rip + disp32]`, so evaluating that expression at every
byte offset in `.text` covers every possible reader. Seven of the nine keys are
read, and each has exactly one reader:

| key | references | reader |
|---|---|---|
| `Task Acceleration` | 5 | `level_at_least`, `ppu_lwarx`, `ppu::install`, `on_embedded_spu_image`, and the GETLLAR lambda |
| `Disable Limiter` | 1 | `patch_engine::apply` |
| `Disable HUD` | 1 | `patch_engine::apply` |
| `Disable Blur` | 1 | `patch_engine::apply` |
| `Lower Exposure` | 1 | `patch_engine::apply` |
| `SPU Culling Wait Bypass` | 1 | `patch_engine::apply` |
| `Disable Lobby BGM` | 1 | `patch_engine::load` |
| `Audio Mixer Fast Path` | 1 | the image-patch gate |
| `UPnP Port` | 0 | — genuinely inert |

`Disable Lobby BGM`'s reader was also previously misattributed to
`mgo_patches.cpp`; it is `patch_engine::load`.

## The five guest-executable patches

The five booleans are not `patch_config.yml` entries. The fork inlines them into
`patch_engine::apply` (`0x1432d9600`), at the very top, *before* the `m_map`
lookup, guarded only by a comparison of the module name against the MGO2
executable hash:

```
0x1432d9685  cmp  r8, 0x2c                       ; strlen == 44 ("PPU-" + 40 hex)
0x1432d9692  lea  rdx, [rip + 0x16fd666]         ; -> "PPU-0c7acb...fb5a1"
0x1432d969d  call memcmp
0x1432d96aa  jne  0x1432d9906                    ; mismatch: skip every MGO patch
```

Each block then has the same five-instruction shape, with the config key as the
gate:

```
movzx eax, byte ptr [rip + ...]   ; g_cfg.mgo.<key>
test al, al
je   <next block>                 ; the key gates the whole block
mov  dword ptr [rsp + 0xb8], <guest offset>
mov  dword ptr [rsp + 0x60], 4
...
call qword ptr [rax + 0x30]       ; mem_translate
mov  dword ptr [rax], <value>     ; the four bytes, verbatim
```

| key | guest offset | value | block |
|---|---|---|---|
| `Disable HUD` | `0x0fa1b4` | `0x00000060` | `0x1432d96b0` |
| `Disable Blur` | `0x2bc0e0` | `0x2000804e` | `0x1432d96fc` |
| `Disable Limiter` | `0x0e4f10` | `0x2000804e` | `0x1432d9740` |
| `SPU Culling Wait Bypass` | `0x154228` | `0x2000804e` | `0x1432d9784` |
| `Lower Exposure` | `0x2a69f4` | `0x00006038` | `0x1432d97c8` |
| `Lower Exposure` (2nd) | `0x11a6b60` | `0xcdcccc3e` | `0x1432d980c` |

`Lower Exposure` is the one key that selects **two** writes, not one.

Three more writes sit inside the same hash guard but that no key gates, so the
fork applies them to every load of the MGO2 executable: `0x14cc80`, `0x14cc98`
and `0x14cccc`, each `<- 0x00000060`.

All nine offsets are inside `MGO2.ELF` (19,615,992 bytes) and every one of them
decodes as a plausible PPC64 instruction when read big-endian, which is how the
guest ELF stores code.

**On byte order.** The store is a plain `mov dword` on x86, so the immediate
goes in little-endian and is *not* byte-swapped; the replica transcribes the
store verbatim rather than byte-swapping to match some intended guest
instruction. Reading the value big-endian instead makes `0x2000804e` a valid
`li r2, 78` where little-endian makes it a nonsensical `lwz r0, 32(r0)`, and
makes `0xcdcccc3e` a valid `fdivs` where little-endian makes it `0x3ecccccd`;
that is suggestive but not conclusive, and it is the one detail here that is
inferred rather than read off the instruction.

## `Disable Lobby BGM` injects an embedded patch_config fragment

Its single reader is `patch_engine::load` (`0x1432cb110`), and what it does is
allocate a 346-byte (`0x15a`) string from a blob at `0x1449d5aea` and feed it to
the patch loader. The blob is, byte for byte:

```yaml


PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1:
  " MGO Disable Files ":
    Games:
      All:
        All: [ All ]
    Author: ""
    Notes:
    Patch Version: 2.0
    Patch:
    - [ hide_file, /dev_hdd0/game/NPMG00020/USRDIR/o/bgm/bgm_mgo_lobby01.bgm, "" ]
    - [ hide_file, /dev_hdd0/game/NPMG00020/USRDIR/o/bgm/bgm_mgo_tounament01.bgm, "" ]
```

Three details are easy to get wrong and were wrong in the replica: the leading
blank line, the spaces **inside** the description key (`" MGO Disable Files "`,
not `"MGO Disable Files"`), and the absence of any top-level `Version:` line —
the replica had invented a `Version: 1.2` header that the fork does not emit.
`mgo_patches.cpp` now carries the fragment verbatim, with a `static_assert` on
its length so it cannot drift.

## The stub mechanism: no synthesis needed

The obvious next question was how the fork builds the `MGO_PPU_HOOK_%02u` stubs.
**It doesn't.** The names are ordinary entries in RPCS3's own HLE function table.

`ppu_function_manager` hands out 8-byte slots of real guest memory, filled once
during module load (`ppu_module_manager::load_game`, PPUModule.cpp:361):

```cpp
for (u32 addr = hle_funcs_addr, index = 0; index < hle_funcs.size(); addr += 8, index++)
{
    vm::write32(addr + 0, addr + 4);              // branch to the next word
    vm::write32(addr + 4, 0);                     // RTOC
    ppu_register_range(hle_funcs_addr, size);     // executable
    ppu_register_function_at(addr + 0, 4, nullptr);
    ppu_register_function_at(addr + 4, 4, hle_funcs[index]);
}
```

So redirecting a call site means branching to
`func_addr(index, is_code_addr = true)` — the same mechanism the fork's
`RPCS3_HLE_LIBRARY` module already uses for `WaitForSPUsToEmptySNRs`
(`HLE_PATCHES.cpp`). `hook_stub_addr()` in `mgo_ppu_hooks.cpp` registers the
eight entries and returns that address; `patch_branch()` does the write.

This also settles a question the record table raised: `register_static_function<>`
keys its static storage on a function's address, so each entry needs a distinct
identity symbol. Those bodies are never executed — the bound interpreter entry
is what runs — but they must exist.

### Branch range: all 15 sites are reachable

> **Retraction.** An earlier note in this file claimed nine of the fifteen known
> call sites were out of `bl` range and that `motion_play` "cannot be
> implemented by patching `bl` at all". **That was wrong** — it came from a
> throwaway script that compared an unsigned distance against a signed limit,
> so every backward branch looked out of range. Re-checked properly, all fifteen
> are in range. The numbers below replace it.

Signed byte distance from each call site to its target, against the ±32 MB limit:

| entry | call sites | distance | redirectable |
|---|---|---|---|
| `pl_motion_mix` | 1 @ `0x331d68` | +0.02 MB | yes |
| `modelsetup` | 3 | +0.91 MB | yes |
| `geo_pool_start` / `2` | 2 | +1.07 MB | yes |
| `motion_play` | 9 | −4.59 MB … −13.39 MB | yes |

All nine `motion_play` sites are *backward* branches, which is exactly what the
signed bug hid. Largest is 13.39 MB against a 32 MB limit, so nothing is
blocked on range. No entry is unreachable for this reason.

### Verified: the displacement is already in bytes

A textbook PPC64 `bl` puts a 26-bit *word* displacement in bits 6..31 and scales
it by 4. That is **not** what this is. Checked against the real ELF, all three
recovered modelsetup sites decode to `0x234a10` only with no shift:

```
0x14cea0: 0x480e7b71  field 0x000e7b70  0x14cea0 + 0xe7b70 = 0x234a10  OK
0x14ce28: 0x480e7be9  field 0x000e7be8  0x14ce28 + 0xe7be8 = 0x234a10  OK
0x14cdb0: 0x480e7c60  field 0x000e7c60  0x14cdb0 + 0xe7c60 = 0x234a10  OK
```

This matches the fork's decode — `shl r9d,6 / sar r9d,6 / and r9d,0xfffffffc /
add r9d,eax`. Shifting left by 6 and arithmetically right by 6 is exactly a
sign extension of bits 2..25, and the fork then adds without scaling.

All 15 recovered call sites were validated against real guest instructions: each
decodes to its recorded target, is 4-byte aligned, lies within ±32 MB, and
encode→decode round-trips. The four candidate decodings were compared directly
on `0x14cea0`:

```
insn 0x480e7b71, target 0x234a10, delta 0xe7b70
  shl6/sar6/and~3/add (the fork)  -> 0x234a10  MATCH
  bits 2..25 sign-extended        -> 0x234a10  MATCH   (same operation)
  textbook LI = insn>>6, *4       -> 0x495b654  no
  bits 6..29, 24-bit byte offset  -> 0x35088c  no
```

**Method note.** This correction, the misaligned table base, and the earlier
dropped hex digit were all caught the same way: a plausible number that nobody
checked against ground truth. Here the tell was that a *backward* branch
reported as unreachable — physically impossible for a real call site, since
callers sit after their callee. Verifying against the actual ELF bytes, rather
than a reimplementation of the arithmetic, is what settles these.

## Batch log — batch 0, `spu_task_hle::ppu::install` (the question that was open)

Started on the one open item from the previous session: what the `+0x04` field
meant, since it stood between the hook table and a safe install.

Disassembled `install` at `0x143389c40` (0x7b8 bytes, `sub_143389c40 .. 14338a3f8`)
end to end. That closed the question and overturned a second assumption.

**What the field is.** `+0x24` is a minimum verbosity byte, not a size. The
global it is compared against is at `0x1466bab94`, read by
`movzx eax, byte ptr [rip + 0x3030f09]` at `0x143389d84`, then
`cmp al, byte ptr [rbp + 0x24] / jb skip`. The `3/3/3/2/255` pattern is
therefore thresholds, and `255` means `ppu.pl_motion_mix` is skipped at any
realistic verbosity — a hook that is present in the table but never installs in
the shipped fork.

**What the layout really was.** The earlier base `0x144b29f60` was 0xa0 too
high; the memcpy source in the populate function is `lea rdx, [rip + 0xfda28e]`
at `0x143b4fc2b`, which resolves to `0x144b29ec0`. With the right base the
records line up on a clean 0x40 grid and every field decodes: the `u32 target`
and the `u8 min_level` had been read as two `u32`s, and the real name pointers
(`ppu.geo_line`, …) appeared one field to the left of where they were assumed.

**What the mechanism actually is.** Not entry-point hooks. `install` rewrites
the `bl` instructions that *call* each target, redirecting them to stubs named
`MGO_PPU_HOOK_%02u`. The fork's own log line at `0x14338a253` states it:

```
Installed PPU hook %s: %u call site(s) of 0x%x -> MGO_PPU_HOOK_%02u (0x%x)
```

Call sites come from `+0x08` (single), or the `+0x10`/`+0x18` array, or — when
neither is set — **a scan of the whole module text** for every `bl` aimed at
`+0x20`. That third mode is why the three `geo_line*` records carry no addresses
at all, and it is now implemented in `install()` here.

**Two things this changes in the port.** `hook_entry` is rebuilt around
`target`/`call_sites`/`min_level` rather than `addr`/`size`, and `install()` is
re-signatured to `(u32 module_base, u32 module_size, bool forced)` so it can do
the scan. The text scan uses `vm::read32` (big-endian) and a `branch_target()`
helper that reproduces the fork's own displacement decode:
`(insn << 6) >> 6`, scaled by 4, added to the branch address, masked to 4.

**Left undone deliberately.** The `bl` is still not written. The fork's
stub-generation path is not reconstructed, so patching a call site without a
real stub behind it would branch into nothing. `install()` therefore records
call sites and lets `dispatch()` find the handler, without redirecting control.

**Lesson, same shape as the earlier dropped-hex-digit one.** A misaligned base
produced *plausible* numbers, not garbage — `0xa28a8` really is in the table,
just at a different offset than claimed. A decode that yields sane values is not
evidence of a correct layout; cross-check the base against an independent
reference (here, the `memcpy` source) before building anything on the fields.

## The module hooks never install: the gate is unsatisfiable

The two `drawassist` records transcribe field for field at `0x144bcd450`, and
one field is the whole story:

```
+0x00  const char* name              "drawassist.3120"
+0x08  const char* module            "spu/spurs_drawassist.spu.task"
+0x10  const char* image_hash        "SPU-9aa78281...dd44e"
+0x18  u32         branch_selector   1
+0x1c  u32         site              0x00003120   (image offset)
+0x20  u32         expected          0x4020007f   (instruction there)
+0x24  u32         target            0x00003120
+0x28  hook_fn     fn                0x143cdf890   = mgo_drawassist_3120
+0x2c  u32         1
+0x30  u32         min_verbosity     0x00000101
+0x34  u32         0
```

and the consumer's gate for it is two instructions:

```
0x1434ae6f8  movzx ecx, byte ptr [rip + 0x2f0c595]     ; 0x1463bac94
0x1434ae6ff  cmp    ecx, dword ptr [r13 + rsi + 0x30]
0x1434ae704  jb     0x1434ae680                        ; skip
```

The left-hand side is a **single byte**, zero-extended, so `ecx` is at most
`0xff`. The right-hand side is a **32-bit** read of the record's threshold,
`0x101`. No byte is >= 257, so the branch is always taken and **neither module
hook installs in the shipped build.**

Two details make this a deliberate finding rather than a misreading. First, the
byte being compared lives at `0x1463bac94`, which is inside the same
configuration block as the Audio Mixer Fast Path toggle at `0x1463bacd4` — so it
is a settings byte, not a constant. Second, the capstone disassembly of the
`cmp` renders it as `cmp cl, byte ptr [...]`; the raw bytes are
`43 3a 4c 35 30`, which is `cmp ecx, dword ptr [r13+rsi+0x30]`. Trusting the
disassembler here inverts the conclusion, because a byte compare against a
record whose low byte is `0x01` passes trivially and the hooks install.

So in the reference binary the entire drawassist subsystem — 31 opcodes, a
0x2880-byte back end, a nine-string precondition list and a 41-block integrity
scan — is **dead code**. Whatever it was written for, it is switched off in the
build that shipped. That is worth stating plainly because it changes what
"replicating the fork" means here: there is no observable drawassist behaviour
to match, only a subsystem to reproduce faithfully in dormant form.

The replica reproduces the comparison exactly rather than repairing it, logs
the impossibility once, and leaves both hooks uninstalled.

## The three decline tables are the fork's own specification

Three of the accelerated handlers report why they gave up through a jump table
of reason strings, and the symbol table even names the tables:

```
switch.table...pl_motion_mix_launch....rel   0x144b3789c   8 entries
switch.table...line_check............rel   0x144b378c4   8 entries
switch.table...modelsetup_launch.....rel   0x144b378e4   9 entries
```

Each is indexed `reason - 1`, and anything else falls through to a shared
`"declined"`. Read together they are the clearest statement in the whole binary
of what the accelerated paths require, because every one of them is a
precondition:

**`pl_motion_mix_launch` — the motion mixer lift**

| # | string |
|---|---|
| 1 | `unmapped guest memory` |
| 2 | `unexpected parameter block` |
| 3 | `phase word <= 3` |
| 4 | `task object busy (obj+0xa0 != 0)` |
| 5 | `misaligned DMA (the task would halt)` |
| 6 | `W(S+4) > 128` |
| 7 | `N > 128` |
| 8 | `bone descriptor changed by a stage` |

Reasons 6 and 7 are bounds the lift refuses to exceed — 128 is the cap on both a
stage's work width and the item count. Reason 5 is the DMA-alignment
precondition: an unaligned DMA would fault on the PPU, so the lift declines
rather than lie. Reason 8 is the **proof obligation**: after every stage the
lift re-reads the bone descriptor and declines if a stage mutated it. A stage
that is not a pure function of its input cannot be replayed, and the fork knows
it.

**`line_check`** — the eight reasons in the section above.

**`modelsetup_launch`**

| # | string |
|---|---|
| 1 | `none` |
| 2 | `built without SSE4.1/SSSE3/FMA3` |
| 3 | `not a model setup image` |
| 4 | `task image differs from the lifted one` |
| 5 | `unexpected SPURS_TaskStart arguments` |
| 6 | `unmapped guest memory` |
| 7 | `SPURS taskset not readable` |
| 8 | `lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)` |
| 9 | `task did not PUT its record` |

Note that index 0 is `none`, i.e. this table is a *status* enum where 0 is
success, not a decline — which is why `modelsetup` needs nine entries and the
other two need eight.

Reasons 1 and 2 across the two tables settle a question that was open for a
while: `built without SSE4.1/SSSE3/FMA3` and `geo collision native not built
(x86-64 SSE4.1/FMA3, GCC or Clang)` are **compile-time** conditions. The
accelerated kernels are ordinary C++ compiled into the binary under those
preprocessor guards — not JIT, not generated at runtime. That matters twice
over: it means the kernels cannot be lifted out of the binary as data, and it
means the fork's own diagnostics are the specification of what those kernels
require.

## The recovered internal API

`coff_syms.py` on the mangled prefix `_ZN12spu_task_hle` returns 72 symbols and
demangles into the fork's internal structure. This is the single most
information-dense artefact in the reverse engineering, because it is the
fork's own source-level naming. The parts that were previously only
hypotheses:

**`mgo_geo_coll::detail`** — the collision front end has a named worker type and
five entry points:

```
bad_point<direct_mem>(u32, float)                    0x143a70b30
ensure_session<direct_mem>(vworker&, u32, u32, u32, why&)  0x143a70f30
run_handler<direct_mem>(vworker&, u32, const char*, u32, u32, why&)  0x143a72230
snapshot_current<direct_mem>(vworker&, u32&)          0x143a73820
get_thunk<direct_mem>(void*, u32, u8*, u32)           0x143a73a20
```

`bad_point` at `0x143a70b30` is the function `line_check` calls with
`(record, query_float)` — so it is **not** a memoisation probe, it is a
point-sanity check, which is what reason 4's "denormal point or radius" says.
`get_thunk` takes `(void*, u32, u8*, u32)`, which is the shape of a *dispatch
table lookup*, not code generation. `why&` as an out-parameter is how the
decline reason travels out of these helpers.

**`mgo_motion_play::task_run<direct_mem>`** — ten methods, and their names are
the algorithm:

```
task_commit(direct_mem&)                       0x143a5c3d0
task_run::get(u32,u32,u32,u32)                 0x143a5c4a0
task_run::blend_pass(u32,u32,bool)             0x143a60cc0
task_run::crossfade(u32)                       0x143a63e80
task_run::release_motion(u32)                  0x143a67580
task_run::fetch_points(u32)                    0x143a678d0
task_run::owner_pass(u32, mask128)             0x143a68090
task_run::mirror(u32)                          0x143a68cc0
task_run::root(u32)                            0x143a694c0
task_run::put(u32,u32,u32)                     0x143a69e00
```

So motion playback is: fetch the point tracks, walk the bone tree from `root`,
apply an `owner_pass` masked by a 128-bit `mask128`, `mirror` the symmetric
side, `crossfade` between clips, `blend_pass` the result, `release_motion` the
tracks, and commit. That is a complete outline of `mgo_motion_play` from names
alone.

**`mgo_modelsetup`** — the parallel machinery, with real signatures:

```
read_spurs_args<direct_mem>(u32&, spurs_args&)          0x143ac5380
detail::load_image<direct_mem>(scratch_t&, image_info&) 0x143ac5520
detail::run<direct_mem>(u32,u32,u32,u32, result*, bool,
                        vector<range>*, par_ctx*)       0x143ac5a80
detail::submit_chunk(void*, par_ctx&, chunk_task&, u32) 0x143ac6e40
detail::set_tracker(void*, par::tracker*)              0x143ac6ef0
detail::add_ext(void*, const chunk_task*)               0x143ac6f00
detail::put_count(void*, u32)                          0x143ac6f90
detail::task_io::get_cb(void*, u32, u8*, u32)           0x143ac6fc0
detail::task_io::put_cb(void*, u32, const u8*, u32)     0x143ac7620
par::pending_commit / pending_destroy / pending_job    0x143ac58e0ff
detail::chunk_job(void*)                               0x143ace660
```

`get_cb` and `put_cb` are the DMA callbacks the lifted code calls; `chunk_job`
and `pending_*` are the thread-pool side; `set_tracker`/`add_ext` are the
conflict detector's inputs. This confirms the earlier reading — a parallel pool
with a conflict detector — and replaces the guess with the actual API.

**`mgo_drawassist`** — two module hooks, both keyed on `spu_task_hle::task_env&`:

```
mgo_drawassist_3120(task_env&)   0x143cdf890   0x2880 bytes
mgo_drawassist_4f20(task_env&)   0x143ce2110   0xbb0  bytes
mgo_drawassist_detail::da_mat_combine(u8*, u32, u32, u32)   0x143ce3030
```

`task_env` is a type the fork defines and this binary never names elsewhere: it
is the per-task environment the SPU module hooks run against. `3120` is three
and a half times the size of `4f20`, and `4f20` calls into `3120`
(`mgo_da4f20_detail::call_3120`), so `4f20` is the command-stream front end and
`3120` is the shared back end.

**`mgo_da4f20_detail`** — the command stream itself, 31 opcodes:

```
scratch() / flush_cmdbuf(ctx&, u32) / call_3120(ctx&, u32)
ctx::put(u8, u32, u32, u32, u32)     0x143ceadc0
ctx::get(u8, u32, u32, u32, u32)     0x143ceced0
draw_indexed(ctx&, u32, u32, u32, u32)             0x143cec5d0
emit_index_chunks(ctx&, u32&, u32&, bool, ...)     0x143cec9b0
stream_flush_if_full(ctx&, u32&, u32&)             0x143cecc60
op2 .. op31(ctx&, const payload&)     0x143ce37d0 .. 0x143cead60
```

`put` and `get` have the same shape — an opcode byte plus four u32s — which is
the wire format. **`op22` does not exist**: the sequence runs `op21` then
`op23`, and there is no `op22` symbol anywhere. Either the command is unused, or
it was merged; the numbering gap is real either way and worth recording before
anyone tries to build a table from the symbol names.

The private `payload` type is in an anonymous namespace (`NS_7payload` in the
mangling), so it has no linkage name and its layout has to come from the
bodies. `op3_4`, `op9`, `op24` and `op27` take no `payload`, so they read their
arguments straight from the context.

## The 4f20 command stream, decoded

The dispatcher is at `0x143ce2538`, and it reads a **stream of 16-byte records**:

```
0x143ce2538  lea  rcx, [rax + r13]              ; the record array
0x143ce253c  mov  ecx, [rcx + rdi*4 - 4]        ; the command word
0x143ce2540  bswap ecx                         ; ... big-endian
0x143ce2542  vmovdqu xmm0, [rax + rbp]          ; the 16-byte payload
0x143ce2547  vmovdqa [rsp+0x90], xmm0
0x143ce2550  mov  edx, ecx
0x143ce2552  shr  edx, 0x18                     ; opcode = top byte
0x143ce2555  lea  r8d, [rdx - 0x20]
0x143ce2559  cmp  r8d, -0x1f
0x143ce255d  jb   0x143ce2845                  ; REJECT 0x20..0x3f
0x143ce2563  shr  ecx, 0x10                     ; row/arg = second byte
0x143ce2566  movzx r8d, cl
0x143ce256a  dec  edx                           ; index = opcode - 1
0x143ce256c  lea  r10, [rip + 0xeeb53d]         ; table at 0x144bcdab0
0x143ce2573  movsxd rcx, [r10 + rdx*4]
0x143ce257a  jmp  rcx
```

So: **31 opcodes, 1..31**, each with a 16-byte payload of four u32s, and a jump
table of 31 entries. Note the guard's direction — it *rejects* `0x20..0x3f`, so
anything at 0x20 and above is treated as an unknown future command rather than
dispatched. Indexing by `opcode - 1` rather than by the opcode itself is what
makes opcode 0 impossible.

### `op22` does not exist because opcode 22 is not a command handler

Every opcode 1..31 maps to a case body that does
`lea rcx,[rsp+0x28]` / `lea rdx,[rsp+0x90]` / `call opN`. With one exception.
Opcode 22's case body is:

```
0x143ce2733  cmp   r8d, 2
0x143ce2737  jb    0x143ce28a3
0x143ce273d  mov   byte [rsp + 0x58], 1        ; error pending
0x143ce2742  lea   rax, [rip + ...]            ; "op22: palette row > 1"
0x143ce2749  mov   [rsp + 0x60], rax

0x143ce28a3  lea   rcx, [rax + rbp]            ; the payload
0x143ce28ae  shl   r8d, 4                      ; row * 16
0x143ce28b2  vmovdqu xmm0, [rcx]
0x143ce28b6  vmovdqu [r8 + rdx + 0x8f0], xmm0  ; ctx + 0x8f0 + row*16
```

Opcode 22 is **"set palette row"**, handled inline with no function of its
own: it copies the 16-byte payload to `ctx + 0x8f0 + row*16`, and the row — the
second byte of the command word — must be below 2. So the context holds exactly
two 16-byte palette rows at `+0x8f0`, and the fork's own diagnostic for a third
is `op22: palette row > 1`.

This is worth stating plainly because the symbol names invite the opposite
conclusion. `op2 .. op31` reads like a 1:1 map onto 30 opcodes, and the missing
`op22` looks like a gap in the recovered symbol list — as though a function were
unaccounted for. It is not missing; there was never one. A scan that resolves
"which function does opcode 22 call" will silently run past the inline body and
report the *next* case's callee, which is how opcode 22 first looked like an
alias of `op14`. Only disassembling settles it.

One more oddity: **opcodes 3 and 4 share `op3_4`**, which takes two extra
immediates — `(0x940, 0x19)` and `(0x980, 0x1a)`. And `op9`, `op24` and `op27`
take no payload at all, reading their arguments from the context.

### The 4f20 header's nine error strings

`mgo_drawassist_4f20` is the only handler of the three that has its own error
strings, and they read as a list of preconditions:

| string | what it guards |
|---|---|
| `record count` | the record array is non-empty |
| `context misaligned or too high` | the SPU context pointer |
| `stack pointer` | the guest stack pointer |
| `context, stack and code overlap` | the three regions must be disjoint |
| `record arrays overlap the stack or code` | ditto for the records |
| `record arrays` | the record arrays are readable |
| `op22: palette row > 1` | the palette row index |
| `code or .rodata modified` | the post-run integrity scan |
| `PUT: ea_ptr failed` | writing the result back |

All nine are reported through the same `(file, line, message)` triple as every
other decline, at `mgo/drawassist_4f20.h:1881` — a header, matching the fork's
own file list. `mgo_drawassist_3120`, at 0x2880 bytes, references **no strings
at all** except its own `__FILE__`: it is the back-end kernel, and it either
works or takes the process down.

The replica implements all of this in `mgo/drawassist_hooks.{h,cpp}`, with the
nine strings verbatim and the record walk, the palette store and the integrity
scan as host logic over a plain buffer — which is why
`buildfiles/mgo_drawassist_test.cpp` can exercise it with no emulator. The test
found two real defects while being written, both now fixed: the overlap checks
were comparing a *guest* address against an *image offset*, and the integrity
scan turned out to be self-referential, because the block map it reads lives at
image `+0xcf4b` and therefore inside the very window it compares — so editing
the map is itself a code modification, and the scan catches it.

### The integrity scan is the proof obligation

`code or .rodata modified` is not a guess — it is the last thing `4f20` does.
After the command stream has run:

```
0x143ce28f6  mov  r13d, 0xc
0x143ce28fc  mov  ebp, 0x3000
0x143ce290c  add  rdi, 0x400        /  add rbx, 0x400   /  add ebp, 0x400
0x143ce2927  cmp  r13, 0x34         /  je   done
0x143ce293b  bt   rsi, r13          /  jae  skip
0x143ce294d  call strcmp
0x143ce2959  je   skip
0x143ce295b  "code or .rodata modified"
```

It walks indices 12..52 — **41 blocks of 0x400 bytes** — selected by a 64-bit
bitmap, comparing the image against a saved copy from `image + 0x3000` with
`strcmp`, and treats any difference as fatal. So the fork does not merely
translate the drawassist commands: it proves it did not perturb the module's
code or read-only data while doing so. That is the same discipline as
`bone descriptor changed by a stage` in `pl_motion_mix` — an accelerated path
that mutates state the guest still needs is not an optimisation, it is a
corruption, and both handlers check for it explicitly.

## Batch log — batch 1, `mgo_geo_coll_hooks::line_check`

Started on the geometry-collision entry point. `line_check` is at `0x143a18c80`
and is **0x1172 bytes** long, which is the first honest measure of what these
functions actually are: this is not a small accessor, it is a large dispatcher.

What the opening 0x100 bytes actually establish, all read off the
instructions:

| address | instruction | meaning |
|---|---|---|
| `0x143a18ca5` | `mov rdi, [rip+…]` then `xor rax, rsp` | `__security_cookie` — the function has a stack canary |
| `0x143a18cba`–`0x143a18cc6` | `mov r13/rbx/r14/r15/r12, [r8+0x10…0x30]` | pulls guest GPRs r5..r9 out of the `call_regs` argument; `r13` = **guest r5** is the hot value |
| `0x143a18cce` | `vmovsd xmm7, [r8+0x108]` | pulls one guest FPR as a `double` |
| `0x143a18ce2` | `mov rcx, qword gs:[0x58]` | Windows PEB, then indexed by a global → this is a **TLS slot** lookup, not a global |
| `0x143a18cef` | `cmp byte [rax+0xc8], 0` / `je 0x143a19011` | the first gate is a TLS-resident flag, not the acceleration level |
| `0x143a18d16`–`0x143a18d37` | `lea eax,[r13-0x8000]` / `cmp eax,0xffff0000` / `shr eax,0xc` / `lea ecx,[r13+0x7fff]` / `shr ecx,0xc` / `cmp eax,ecx` / `jbe` | rejects `r5 < 0x8000`, then walks a page map over the 0x8000-byte window (see below) |
| `0x143a18d3d`–`0x143a18d9c` | `mov eax,0xffff8250` / `lea r8d,[rax+r13]` / `cmp dword [rcx+r8],…` at +0, +0x180, +0x198, +0x1c4 | indexes a large global table at `base + (r5 - 0x7db0)` and requires **four magic tags** before proceeding, else bail |

So the function's first act is: reject anything that is not a guest pointer into
a mapped 0x8000-byte window, then require a **quadruply** magic-tagged structure
at a fixed negative offset from that pointer. That is a *guard*, and it is the
part that matters — the accelerated path only runs on pointers that survive it.

## line_check, decoded

The whole 0x1172 bytes have now been read. Two of the earlier conclusions were
wrong and are corrected here.

### The page test is not a "single 4 KB page" test

```
lea   eax, [r13 - 0x8000]
cmp   eax, 0xffff0000     / ja  reject
shr   eax, 0xc
lea   ecx, [r13 + 0x7fff]
shr   ecx, 0xc
cmp   eax, ecx            / jbe 0x143a18e99
```

The first comparison is the whole gate: it rejects `r5 < 0x8000`. The second
cannot reject anything — `first_page <= last_page` is true for every input — so
control *always* leaves through `jbe`, into the page walk at `0x143a18e99`.
That walk is not a page-boundary test either. It is a **page-map walk**: it
takes a static byte map (`lea r8, [rip+0x27762e0]`), steps through the 0x100-byte
granules of the window, and for each granule byte checks that `(~b) & 0x81 == 0`,
i.e. the byte must be `0x81`, with `0x40` meaning "skip a whole 0x100" and
`0x20` meaning "skip the next 0x10". That is the fork's own allocation tracker
for the local store it reproduces. There is no counterpart in the replica, so
only the range half is reproduced.

### There are four tags, not two

```
mov  eax, 0xffff8250              ; = r5 - 0x7db0
cmp  dword [rcx + r8], 0x94981a01 ; +0x000
cmp  dword [rcx + r8], 0x94ca1a01 ; +0x1c4
cmp  dword [rcx + r8], 0xe0c21a01 ; +0x180
cmp  dword [rcx + r8], 0x44c81a01 ; +0x198
```

All four share the low half `0x1a01` and differ only in the high half, so they
read as four sub-structure identities under one tag version. Earlier revisions
knew two and marked a third unidentified; there are four and none is
unidentified.

Note they are compared **without** a byte swap, while every guest pointer and
float the function reads is byte-swapped on the way in. So the guest stores
these four tags as little-endian `u32` and its other data big-endian — an
asymmetry worth preserving exactly, because getting it backwards inverts the
guard.

### What the function does with all that

`line_check` is the front end of a **native collision kernel**. It validates
the call, then hands the work to a x86-64 reimplementation of the guest's own
routine and checks the answer. The eight decline strings say so outright, and
they are the most informative thing in the function — an 8-entry jump table at
`0x144b378c4`, indexed `(reason - 1)`, all quoted from the image:

| # | string |
|---|---|
| 1 | `geo collision native not built (x86-64 SSE4.1/FMA3, GCC or Clang)` |
| 2 | `unexpected globals / TOC (other build?)` |
| 3 | `PPU fallback path (pool not running or ring full)` |
| 4 | `unsupported input (col_flag 0x1000, denormal point or radius, aliasing)` |
| 5 | `virtual worker init failed` |
| 6 | `session tables changed inside the session` |
| 7 | `virtual worker run failed (DMA, halt, budget, recursion)` |
| 8 | `unexpected worker output` |

Any other value falls through to a shared `"declined"`. All eight are reported
through the same `(file, line, message)` triple as every other decline — here
`mgo/ppu_geo_collision_hooks.h:46` — so the fork's own diagnostics are a
complete specification of its failure modes.

Putting the guards in order, with the reason each one reports:

1. **Pool.** The first gate is `cmp byte [rax+0xc8], 0` on the TLS thread. When
   clear it allocates the same `0x300`-byte `geo_pool` `pool_start` builds (same
   `operator new`, same constructor at `0x143ac4f90`), stores it at
   `thread+0x388`, sets `thread+0xc8`, and rejoins the main path.
2. **Window.** `r5 >= 0x8000`, plus the page-map walk.
3. **Tags.** Four magic words at `r5 - 0x7db0` + `{0, 0x180, 0x198, 0x1c4}`.
   → *unexpected globals / TOC (other build?)*
4. **Guest globals.** Five immediates inside the function, each a pointer-sized
   global read big-endian:

   | global | meaning | validation |
   |---|---|---|
   | `0x11a4a94` | ring region | `ptr + 0x40d40` must be readable |
   | `0x11a42e8` | session table A | `ptr + 0x30` readable |
   | `0x11a4844` | session table B | `ptr + 0x14` readable, then `*(ptr+0x10) + 0x50` readable |
   | `0x11a1894` | build word | **must read 0** — non-zero means another build |
   | `0x11a1898` | query float | used as the memoisation key |

5. **The build word.** `if (*(u32*)0x11a1894 != 0) decline;` — this is the whole
   of "other build?" and it is a property of the guest executable, so it is a
   cheap and very strong version check.
6. **Two 12-byte records** in gpr[5] and gpr[6]. Each must be readable, and each
   of its three big-endian words must pass `((v & 0x7f800000) == 0) &&
   ((v & 0x7fffff) != 0)` — that is, not zero, not denormal, not NaN/Inf. The
   seventh argument, read as a `double` from `+0x108`, must additionally survive
   a round trip through `float`.
   → *unsupported input (col_flag 0x1000, denormal point or radius, aliasing)*
7. **`col_flag`.** When `gpr[3] & 0x1000` and `pool+0x229` is clear, decline —
   which is precisely what reason 4's parenthetical names.
   → *unsupported input*
8. **The ring.** `+0x40d3c` must be non-zero and `head (+0x40d34) > tail
   (+0x40d2c)` as signed words, or the call is left to the PPU.
   → *PPU fallback path (pool not running or ring full)*
9. **A point-sanity probe.** Before any of the above is expensive, the fork calls
   `mgo_geo_coll::detail::bad_point(record, query_float)` for gpr[6] and then
   gpr[5]; either one reporting bad short-circuits to success with no work
   done.
10. **The session snapshot and the worker.** `thread+0xd0` gates a native
    worker. When it is set, the fork copies the session table pointers into a
    snapshot object at `thread+0x390` and then calls into it several times —
    which is what reason 6 (*session tables changed inside the session*) is
    watching for: the guest is not allowed to mutate the tables underneath a
    session in progress.

### Thread layout it implies

All offsets are from `gs:[0x58]`, the current `spu_thread`:

```
+0x0c8  byte    pool built
+0x0d0  byte    native worker enabled
+0x270  8 x u64 one counter per decline reason
+0x2d8  byte    the reason just reported
+0x388  geo_pool*
+0x390  session snapshot*
+0x1e8  const char* __FILE__   }  the decline triple, the same fields
+0x1f0  u32 __LINE__           }  pool_start writes
+0x1f8  const char* message    }
```

### What the replica implements

The entire front end — pool, window, four tags, five globals, both records,
`col_flag`, the ring — and then declines with **reason 1**, which is the fork's
own wording for a build with no native kernel. The guest therefore always runs
its original code. That is a real behavioural difference and it is deliberate:
the collision kernel is ordinary C++ compiled into the fork under a
`#if`-style guard (`built without SSE4.1/SSSE3/FMA3` and `x86-64 SSE4.1/FMA3,
GCC or Clang` are both compile-time conditions, and `get_thunk` looks up a
dispatch table rather than generating code). None of that source exists, so
"decline with the fork's own not-built reason" is the honest end state rather
than a plausible-looking approximation.

This is also the concrete answer to "can't it all just be decompiled": the
instruction stream is fully recoverable, and here 0x1172 bytes of it did resolve
— but what they resolve *to* is a second native implementation, and its absence
is a build-time property of the fork rather than a fact present in the binary.

## The remaining options are not patches

The fork embeds **exactly one** patch-engine YAML — the Disable Lobby BGM one.
`Patch Version:` and `MGO Disable Files` each occur once in the whole image, and
the other 25 `hide_file`/`Patch` hits are all inside `patch_engine`'s own error
strings. So `Disable HUD`, `Disable Blur`, `Lower Exposure`, `Disable Limiter`,
`Audio Mixer Fast Path` and `SPU Culling Wait Bypass` are not patch-engine
entries.

Two of them now have a recovered mechanism anyway:

- **Audio Mixer Fast Path** is the single image patch above, on
  `mixer.single_bus`.
- **Task Acceleration** is the two module hooks above.

For the rest, RPCS3 has no equivalent knob (`motion blur` and `sky brightness`
are not renderer features), which points at the settings being game-side or
server-driven rather than emulator-side. That has not been established either
way; the reader for each of those config members has not been traced.

## Log channels (subsystem breakdown)

Recovered from the binary; these are the fork's own `LOG_CHANNEL` names:

```
ppu.geo_line        ppu.geo_line_auto   ppu.geo_line_region
ppu.geo_pool_start  ppu.modelsetup      ppu.motion_play
ppu.pl_motion_mix
```

`ppu.geo_line*` / `ppu.geo_pool_start` correspond to the `mgo_geo_coll_hooks`
entry points (`line_check`, `pool_start`), i.e. the geometry-collision culling
work that `SPU Culling Wait Bypass` and Task Acceleration accelerate.

## RE tooling

`~/Desktop/mgo2-plugin/tools/mgo_xref.py` finds RIP-relative references
without disassembling the whole image. A RIP-relative operand is always
`mod=00, r/m=101` followed by a disp32, so

```
target = next_ip + disp        next_ip = va(disp_pos + 4)
=>  key[p] = (disp[p] + va(p) + 4) & 0xFFFFFFFF
```

so one numpy pass builds `key` and a hit for target `T` is `key[p] == T`.
Capstone is then used only on the individual functions of interest — a full
`md.disasm()` over the 66 MB `.text` needs far too much memory and takes the
machine down.

`mgo_dump.py` disassembles a bounded VA range with on-demand string/import
annotation.