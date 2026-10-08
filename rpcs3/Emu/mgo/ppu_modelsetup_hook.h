#pragma once

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

// Recovered shape of the SaveMGO fork's modelsetup hook handler.
//
// The fork registers one handler for guest function 0x00234a10 at three
// different `bl` sites and the handler itself tells them apart by the guest
// link register, which pins down the call site as lr-4. See the comments in
// ppu_modelsetup_hook.cpp for the recovered addresses.

namespace mgo_modelsetup_hook
{
	// Handler for one specific call site of ppu.modelsetup. Always the same
	// body today - the fork's own dispatch is reproduced inside it - but
	// exposed per site so hook_entry::by_site can name the split explicitly.
	spu_task_hle::ppu::hook_fn handler_for_site(u32 call_site);

	// Handler for a call site that is not one of the three recovered ones.
	spu_task_hle::ppu::hook_fn default_handler();
}