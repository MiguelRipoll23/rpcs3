#pragma once

// Built-in patches for Metal Gear Online (NPMG00020), recovered from the
// SaveMGO fork. These are registered with the patch engine at boot and gated
// by the MGO settings in g_cfg.mgo.
class patch_engine;

#include <functional>
#include <string>
#include <vector>

#include "util/types.hpp"

namespace mgo_patches
{
	// Registers the built-in MGO patches that the current settings enable.
	// Called once per boot, right after the regular patches are loaded.
	void register_builtin(class patch_engine& engine);

	// One 4-byte write into a guest module, as recovered from the fork.
	struct guest_word_patch
	{
		u32 offset;     // guest module offset, translated by patch_engine::apply
		u32 value;      // the 4 bytes written verbatim (little-endian, as the fork's `mov dword` does)
	};

	// The fork's five remaining MGO settings are not patch_config.yml entries at
	// all: they each gate a small set of 4-byte writes into the guest
	// executable, applied by patch_engine::apply when (and only when) the module
	// being loaded is the MGO2 main executable.  Returns the patches the current
	// settings select, so the caller can apply them.
	std::vector<guest_word_patch> select_guest_word_patches();

	// True if `name` is the module the fork's guest patches are keyed on.
	bool is_mgo2_exec(std::string_view name);
}