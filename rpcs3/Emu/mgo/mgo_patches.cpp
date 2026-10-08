#include "stdafx.h"
#include "mgo_patches.h"

#include "Utilities/bin_patch.h"
#include "Emu/system_config.h"

// The SaveMGO fork ships a built-in patch_config.yml that hides the lobby BGM
// files so the game cannot play them (this is what "Disable Lobby BGM" does).
// It is keyed on the MGO2 main-ELF executable hash, exactly like every other
// RPCS3 patch, so it only applies to the matching game build.
//
// NOTE: this fork deliberately does NOT reproduce the fork's SaveMGO-server
// connection gate, host fingerprinting, anti-cheat detection, or .text
// integrity check - see MGO_FORK.md.

namespace
{
	// SHA-1 of the NPMG00020 main executable, as computed by
	// ppu_module_manager::load ("PPU-" + 40 hex chars).
	constexpr std::string_view mgo2_exec_hash = "PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1";

	// Disable Lobby BGM: hide both lobby/stage BGM files.
	//
	// This is the fork's embedded patch_config.yml fragment byte for byte,
	// including the leading blank line and -- less obviously -- the spaces
	// *inside* the description key, " MGO Disable Files ".  The fork does not
	// prepend a "Version:" line either; it hands this string straight to the
	// patch loader.
	constexpr std::string_view disable_lobby_bgm_patch = R"(

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
)";
	static_assert(disable_lobby_bgm_patch.size() == 346,
		"the fork's embedded fragment is 0x15a bytes; see MGO_FORK.md");

	// The guest-code patches, recovered from patch_engine::apply.
	//
	// The fork inlines these into patch_engine::apply, guarded by a comparison
	// of the module name against mgo2_exec_hash, and each one is the same shape:
	//
	//     movzx eax, byte ptr [rip + <g_cfg.mgo.X>]
	//     test al, al
	//     je   <next block>                 ; the key gates the whole block
	//     mov  dword ptr [rsp+0xb8], <guest offset>
	//     mov  dword ptr [rsp+0x60], 4
	//     ...   call [rax + 0x30]          ; mem_translate
	//     mov  dword ptr [rax], <value>    ; the 4 bytes, verbatim
	//
	// so a "block" is one or more 4-byte writes and the gate is the preceding
	// `je` to the following block.  The store is a plain `mov dword` on x86, so
	// the value is written little-endian; that is transcribed as-is rather than
	// byte-swapped, because reproducing the fork means reproducing the store, not
	// guessing what the guest instruction was meant to be.
	struct gated_patches
	{
		bool enabled;
		std::initializer_list<mgo_patches::guest_word_patch> patches;
	};

	// Order matches the fork's blocks.  The three writes at 0x14cc80/0x14cc98/
	// 0x14cccc sit inside the same module-hash guard but no config key gates
	// them, so they are unconditional (0x1432d9845, 0x1432d987e, 0x1432d98b7).
	std::vector<mgo_patches::guest_word_patch> build_guest_word_patches()
	{
		const std::initializer_list<gated_patches> blocks{
			{g_cfg.mgo.disable_hud.get(), {{0x0fa1b4, 0x00000060}}}, // 0x1432d96b0
			{g_cfg.mgo.disable_blur.get(), {{0x2bc0e0, 0x2000804e}}}, // 0x1432d96fc
			{g_cfg.mgo.disable_limiter.get(), {{0x0e4f10, 0x2000804e}}}, // 0x1432d9740
			{g_cfg.mgo.spu_culling_wait_bypass.get(), {{0x154228, 0x2000804e}}}, // 0x1432d9784
			// Lower Exposure selects two writes, not one.
			{g_cfg.mgo.lower_exposure.get(), {{0x2a69f4, 0x00006038}, {0x11a6b60, 0xcdcccc3e}}}, // 0x1432d97c8
		};

		std::vector<mgo_patches::guest_word_patch> out;

		for (const auto& block : blocks)
		{
			if (block.enabled)
			{
				out.insert(out.end(), block.patches.begin(), block.patches.end());
			}
		}

		out.push_back({0x14cc80, 0x00000060});
		out.push_back({0x14cc98, 0x00000060});
		out.push_back({0x14cccc, 0x00000060});

		return out;
	}
}

namespace mgo_patches
{
	bool is_mgo2_exec(std::string_view name)
	{
		return name == mgo2_exec_hash;
	}

	std::vector<guest_word_patch> select_guest_word_patches()
	{
		return build_guest_word_patches();
	}
}

namespace mgo_patches
{
	void register_builtin(patch_engine& engine)
	{
		if (g_cfg.mgo.disable_lobby_bgm)
		{
			engine.append_builtin_patches(disable_lobby_bgm_patch);
		}
	}
}