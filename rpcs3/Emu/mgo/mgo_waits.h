#pragma once

// Metal Gear Online lwarx spin-loop handling.
//
// The fork calls this `spu_task_hle::mgo_waits::ppu_lwarx_wait`. The name is a
// misnomer that cost real time to decode, and the *policy* behind it took
// longer: it is not an observer, and it is not a spin-killer. It **blocks the
// PPU thread on the VM reservation that covers the lwarx's address**, for at
// most 50 seconds, when - and only when - the guest is one of the two MGO games,
// the user has asked for at least "standard" task acceleration, and the spin is
// one of six hardcoded addresses inside three known guest functions.
//
// ---------------------------------------------------------------------------
// Recovered body: 0x1434af180, 0x1e4 bytes
// ---------------------------------------------------------------------------
//
//   bool ppu_lwarx_wait(ppu_thread& ppu, u32 addr, u32 value)
//
// 1. **Site lookup.** Dispatches on the thread's guest PC (ppu_thread::pc, at
//    +0x474) against three 12-byte records at 0x144a25cf0:
//
//        { 0x00337070, 0x00337080, 0 }
//        { 0x001b01f8, 0x001b0240, 2 }
//        { 0x001999a8, 0x001999d8, 3 }
//
//    Each record is {pc_lo, pc_hi, budget} and each record's own two PCs are
//    exactly the two addresses its branch arms compare against, so the table is
//    self-describing. 0x1b023f appears in the body but is a *switch threshold*,
//    not a site - it is one byte into the lwarx at 0x1b023c.
//
// 2. **Budget gate.** Reproduced exactly, including the odd-looking cmovne:
//
//        r9b  = (value < budget)
//        r10b = (value != 0)
//        if (budget != 0) r10b = r9b
//        proceed iff r10b == 1
//
//    so a site with budget 0 proceeds whenever `value` is non-zero, and a site
//    with a non-zero budget proceeds only while `value` is under it. The value
//    is the word the lwarx just loaded, so the gate is "the spinner's idea of
//    the data has not converged yet".
//
// 3. **Title gate.** Reached only past the budget gate. The title id is read
//    through a 0x18-byte holder at 0x14504d928:
//
//        +0x00  u8   tag       bit 0 = the pointer is valid, bits 1+ = length
//        +0x08  char[8] inline buffer
//        +0x10  const char* pointer
//
//    and the length must be exactly 9 (`cmp r8, 9`). Then two XOR-accumulate
//    compares against 0x31303030474d504e and 0x32303030474d504e with a ninth
//    byte of 0x30. Those are not obfuscation - they are plain ASCII:
//
//        "NPMG0001" + '0'  =  NPMG00010   (Metal Gear Online)
//        "NPMG0002" + '0'  =  NPMG00020   (Metal Gear Online 2)
//
//    so the whole reporter is inert unless the running title is one of the two
//    MGO games.
//
// 4. **The wait itself**, and this is the part that is easy to get wrong:
//
//        0x1434af28c  lock or dword ptr [rcx + 0x14], 4   ; mark the thread
//        0x1434af285  mov  rax, qword ptr [rcx + 0x498]   ; ppu_thread::rtime
//        0x1434af2eb  lea  rdi, [rip + ...]                ; g_resrv_waiters_count
//        0x1434af2f2  lock inc byte ptr [rdx + rdi]       ; ... announce
//        0x1434af2f6  and  r8d, 0x7fc0                    ; the reservation slot
//        0x1434af304  lea  r10, [vm::g_reservations + r8]
//        0x1434af31c  mov  qword ptr [rsp + 0x20], r8+4   ; atomic_wait::info
//        0x1434af328  mov  dword ptr [rsp + 0x28], rtime >> 32
//        0x1434af332  mov  r8d, 0xc350                    ; 50'000
//        0x1434af343  call atomic_wait_engine::wait
//        0x1434af348  lock dec byte ptr [rbx + rdi]       ; ... left
//        0x1434af34c  mov  eax, dword ptr [rsi + 0x14]
//        0x1434af34f  test eax, eax / je  end
//        0x1434af356  call cpu_thread::check_state
//
//    That call is `atomic_t<u64>::wait(rtime, atomic_wait_timeout{50'000})` on
//    the reservation word - byte for byte the same shape as the 8-byte overload
//    in rpcs3/util/atomic.hpp, which builds `ext[0] = {&m_data + 4, old >> 32}`
//    and passes `ext` as the extended wait list. 0xc350 is 50000, the same
//    timeout SPUThread.cpp uses for its own reservation waits.
//
//    The array at 0x146127ef8 is `vm::g_resrv_waiters_count` (COFF:
//    `_ZL21g_resrv_waiters_count.llvm.1733...`), the shared reservation-waiter
//    table, indexed raw by
//
//        ((addr >> 2) & 0x60) | popcount(addr & 0xfffffe00)
//
//    Note that this is *not* vm::reservation_notifier()'s index, and not a
//    private guard: the fork bumps a byte of the shared waiter table to announce
//    the wait, and the index reaches 119.
//
// **The `budget` field is therefore not a retry limit the host enforces**: it is
// a threshold on how interesting the spin is, and the *only* thing that bounds
// the wait is the 50-second timeout.
//
// ---------------------------------------------------------------------------
// The caller: ppu_lwarx, 0x143249d30
// ---------------------------------------------------------------------------
//
// The fork's `ppu_lwarx` is upstream's load with this appended to its tail:
//
//        0x143249fef  mov  ecx, dword ptr [rsi + 0x474]    ; the guest PC
//        0x143249ff5  cmp  ecx, 0x1b023f / jg  hi
//        0x143249ffd  cmp  ecx, 0x1999a8 / je  report
//        0x14324a005  cmp  ecx, 0x1999d8 / je  report
//        0x14324a00d  cmp  ecx, 0x1b01f8 / je  report
//        0x14324a015  jmp  done
//        0x14324a017  cmp  ecx, 0x1b0240 / je  report
//        0x14324a01f  cmp  ecx, 0x337080 / je  report
//        0x14324a027  cmp  ecx, 0x337070 / jne done
//        0x14324a02f  movzx ecx, byte ptr [rip + ...]       ; task_acceleration
//        0x14324a036  cmp  cl, 2 / jae done
//        0x14324a069  mov  rcx, rsi / mov r8d, eax
//        0x14324a06f  mov  rsi, rax                          ; the loaded value
//        0x14324a072  call ppu_lwarx_wait
//        0x14324a077  mov  rax, rsi                          ; ... and back
//
// i.e. exactly the six table PCs, and a gate on one byte of the configuration.
// The reporter then re-reads the PC and re-checks the site itself, so the
// six-way switch in the caller is a fast path, not the only gate.

#include "util/types.hpp"
#include "Emu/system_config_types.h"

#include <bit>

class spu_thread;
class ppu_thread;

namespace spu_task_hle::mgo_waits
{
	// The `Task Acceleration` level the fork demands before it will do any of
	// this: `cmp cl, 2 / jae`, against the byte at 0x1463bac94, which is
	// `g_cfg.mgo.task_acceleration` - the `spu_task_hle::level_at_least` at
	// 0x1434ae410 reads the same byte and is the same test.
	constexpr mgo_task_acceleration min_level = mgo_task_acceleration::standard;

	// How long the wait may last: `mov r8d, 0xc350`.
	constexpr u64 wait_timeout = 50'000;

	// One entry of the lwarx wait-site table.
	struct lwarx_site
	{
		u32 pc_lo = 0;
		u32 pc_hi = 0;
		u32 budget = 0;
	};

	// The recovered table, in the fork's order. 3 entries.
	const lwarx_site* lwarx_sites(usz& count);

	// The site `pc` belongs to, or nullptr.
	const lwarx_site* find_lwarx_site(u32 pc);

	// True for the six hardcoded PCs, without touching the thread. This is the
	// caller's fast path, and it is a pure function of the table above.
	bool is_lwarx_site_pc(u32 pc);

	// The fork's budget gate. `value` is what the lwarx loaded and `budget` is
	// the matched record's third field.
	bool budget_gate(u32 value, u32 budget);

	// The fork's title gate: true only for NPMG00010 or NPMG00020, and only
	// for a title id of exactly nine characters.
	//
	// Both constants above are compared as plain ASCII - the XOR is a strcmp
	// accumulation, not a decode step, and it is worth saying so because
	// "XOR'd with 0x30" reads like deobfuscation and is not.
	bool title_supported(const char* title_id);

	// The reservation the fork waits on, as a byte offset into
	// `vm::g_reservations`.
	//
	// `shr r8d, 1` then `and r8d, 0x7fc0`, i.e. `(addr >> 1) & 0x7fc0`.
	//
	// An earlier draft of this file claimed the mask was one bit wider than
	// `vm::reservation_acquire`'s `(addr & 0xff80) / 2` and that the fork
	// therefore waited on the wrong granule. That is wrong, and
	// buildfiles/mgo_waits_test.cpp is what proved it:
	//
	//     (addr & 0xff80) / 2  ==  (addr >> 1) & (0xff80 >> 1)  ==  (addr >> 1) & 0x7fc0
	//
	// because dividing by two is a shift and 0xff80 >> 1 *is* 0x7fc0. The two
	// expressions are the same function; the fork and upstream agree on every
	// address, which is what makes it safe to reuse `reservation_acquire`'s
	// own slot in the replica rather than recomputing it here.
	constexpr u32 reservation_mask = 0x7fc0;
	constexpr u32 reservation_granule_bytes = 0x40; // sizeof the stride, not the granule

	constexpr u32 reservation_slot_offset(u32 addr)
	{
		return (addr >> 1) & reservation_mask;
	}

	// The counter the fork bumps around the wait, at 0x146127ef8, hashed as
	//
	//   popcount(addr & 0xfffffe00)   through the SWAR sequence at 0x1434af294
	//   (addr >> 2) & 0x60            two more bits
	//
	// **0x146127ef8 is `vm::g_resrv_waiters_count`**, not a private guard array:
	// the COFF symbol there is `_ZL21g_resrv_waiters_count.llvm.1733...`, this
	// fork's renamed copy of `vm::g_resrv_waiters_count`. So the replica bumps a
	// byte of the shared reservation-waiter table rather than keeping a private
	// counter, and the hash is *not* a 6-bit hash:
	//
	//   popcount(0xfffffe00) == 23 bits, so the popcount term alone reaches 23,
	//   and the maximum over all u32 is 23 | 0x60 == 119.
	//
	// That is why the bound below is 120 and not 64. An earlier draft called
	// this "a 64-entry guard" and sized the replica's array at 64, which is out
	// of bounds for any address in the top 0x60000 of memory - found by
	// buildfiles/mgo_waits_test.cpp, which walks the whole u32 range.
	constexpr u32 guard_buckets = 120;
	//
	constexpr u32 guard_bucket(u32 addr)
	{
		return ((addr >> 2) & 0x60) | std::popcount(addr & 0xfffffe00u);
	}

	// The full recovered policy, called from ppu_lwarx with the value the
	// lwarx just loaded.
	//
	// Returns true if the guest was actually put to sleep. The replica blocks
	// exactly as the fork does; there is nothing left to decline.
	bool ppu_lwarx_wait(ppu_thread& ppu, u32 addr, u32 value);

	// Four-word signature the fork looks for in the SPU local store at +0x3000
	// before honouring a GETLLAR on gpr1.
	//
	// The whole 0x3c-byte body at 0x1434af140 is that one comparison and
	// nothing else: four u32 loads, four compares, `sete al`. The "ignore
	// gpr1" in the name is the point - the guest reads gpr1 for something
	// unrelated to the load-link address register, and the fork suppresses the
	// resulting trap instead of servicing it.
	struct getllar_magic
	{
		u32 at_0x3000 = 0x027a8043;
		u32 at_0x3004 = 0x82a2a543;
		u32 at_0x3008 = 0x02433943;
		u32 at_0x300c = 0x824fb142;
	};

	constexpr u32 getllar_ls_offset = 0x3000;

	bool geo_getllar_ignore_gpr1(const spu_thread& spu);
}