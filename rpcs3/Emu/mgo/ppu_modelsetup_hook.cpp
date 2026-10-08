#include "stdafx.h"
#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"
#include "Emu/Cell/PPUThread.h"

// Recovered shape of the SaveMGO fork's modelsetup hook handler.
//
// ---------------------------------------------------------------------------
// What was recovered, and how
// ---------------------------------------------------------------------------
//
// The fork's handler for hook record 7 (ppu.modelsetup, guest target
// 0x00234a10) lives at 0x143a19ec0 and is 0x8fb bytes. Its non-stripped body
// opens like this, with r8 = the call_regs block and rcx = the ppu_thread:
//
//   0x143a19ed3  mov  [rsp+0x50], r9          ; spill call_result
//   0x143a19ed8  mov  [rsp+0x48], rdx         ; spill direct_mem
//   0x143a19edd  mov  rdi, rcx                ; keep the cpu
//   0x143a19f19  mov  r15d, [r8+0x18]         ; gpr[3]
//   0x143a19f1d  mov  eax,  [r8+0x20]         ; gpr[4]
//   0x143a19f25  mov  ebp,  [r8+0x28]         ; gpr[5]
//   0x143a19f29  mov  r13d, [r8+0x30]         ; gpr[6]
//   0x143a19f2d  mov  esi,  [rcx+0x460]       ; the guest link register
//   0x143a19f33  mov  ebx,  [r8+0xc0]         ; gpr[24] - the argument block
//   0x143a19f49  lea  r12d, [rsi-4]           ; call site = lr - 4
//   0x143a19f4d  cmp  esi, 0x14ce2c
//   0x143a19f55  cmp  esi, 0x14cea4
//   0x143a19ffc  xor  esi, esi                ; neither -> not this handler's
//
// The two comparisons are the link registers of two of the three recovered
// call sites for this record: 0x14ce28 -> lr 0x14ce2c, and 0x14cea0 ->
// lr 0x14cea4. The third site, 0x14cdb0, is not compared against and so
// falls through to the "not mine" path. That is the whole dispatch: a
// handler reached through a `bl` knows which `bl` it was, and uses that.
//
// Everything after the dispatch - the two byte-map guards, the
// SPURS_TaskStart argument checks, the per-image scratch buffers,
// read_spurs_args, load_image and the worker pool - is implemented in
// mgo/mgo_modelsetup.cpp, which is where the decoded front end now lives.
// This file keeps the two entry points the hook table names.

#include "Emu/mgo/ppu_modelsetup_hook.h"
#include "Emu/mgo/mgo_modelsetup.h"

namespace mgo_modelsetup_hook
{
	// The recovered call sites of hook record 7, in the fork's order:
	// 0x14cea0 and 0x14ce28 are the two the body switches on, 0x14cdb0 is
	// the one it does not.
	constexpr u32 site_a = 0x0014cea0u;
	constexpr u32 site_b = 0x0014ce28u;
	constexpr u32 site_other = 0x0014cdb0u;

	spu_task_hle::ppu::hook_fn handler_for_site(u32 call_site)
	{
		// mgo_modelsetup::launch classifies the call site itself, so all
		// three entries resolve to the same function. They are still exposed
		// per site so the hook table can name the split explicitly, which is
		// what the fork's recovered dispatch does.
		(void)call_site;
		return &mgo_modelsetup::launch;
	}

	spu_task_hle::ppu::hook_fn default_handler()
	{
		return &mgo_modelsetup::launch;
	}

	// Keeps the two constants alive for the header's documentation.
	static_assert(site_a == mgo_modelsetup::site_chara, "site 0x14cea0 is the chara lift");
	static_assert(site_b == mgo_modelsetup::site_bg, "site 0x14ce28 is the bg lift");
	static_assert(site_other == mgo_modelsetup::site_other, "site 0x14cdb0 is the one the fork ignores");
}