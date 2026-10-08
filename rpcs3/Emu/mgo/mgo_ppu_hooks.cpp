#include "stdafx.h"
#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

#include "Emu/IdManager.h"
#include "Emu/Cell/PPUFunction.h"
#include "Emu/Cell/PPUModule.h"
#include "Emu/Cell/SPUThread.h"
#include "Emu/system_config.h"

#include "Emu/mgo/ppu_geo_collision_hooks.h"
#include "Emu/mgo/ppu_modelsetup_hook.h"
#include "Emu/mgo/mgo_modelsetup.h"
#include "Emu/mgo/mgo_pl_motion_mix.h"
#include "Emu/mgo/drawassist_hooks.h"
#include "Emu/mgo/mgo_motion_play.h"

#include <array>

// Metal Gear Online hook tables.
//
// ---------------------------------------------------------------------------
// SPU module hooks (image-patch / module keyed)
// ---------------------------------------------------------------------------
//
// The SaveMGO fork's binary is not stripped, so every one of its symbols
// resolves to a real address through its COFF symbol table. Two of those
// symbols are the tables themselves:
//
//   spu_task_hle::get_hook_table()     0x143cdf850   -> 2 entries
//   spu_task_hle::get_image_patches()  0x143cdf870   -> 1 entry
//
// Both are std::span getters (out-param in rcx, data pointer, count), and both
// point into .rdata:
//
//   hook table     0x144bcd450
//   image patches  0x144bcd3b0
//
// Reading the strings those tables reference gives the whole picture:
//
//   drawassist.3120                       hook   on SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e
//   drawassist.4f20                       hook   on SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e
//   mixer.single_bus                      patch  on SPU-ae8a758775740615382268346f1a9cc14d9966f9
//   spu/spurs_drawassist.spu.task        the module the two drawassist hooks live in
//
// So Task Acceleration is two hooks into an embedded SPU module, not a table of
// PPU guest addresses, and the single image patch is the Audio Mixer Fast Path.
//
// ---------------------------------------------------------------------------
// PPU hooks
// ---------------------------------------------------------------------------
//
// These live in a second, unrelated table: eight 64-byte records at
// 0x144b29ec0, installed by spu_task_hle::ppu::install at 0x143389c40. The
// records and the whole install mechanism were decoded from that function; see
// the hook_entry comment in ppu_task_hle.h for the field offsets.
//
// The mechanism is worth stating plainly, because it is not what an earlier
// revision of this file assumed. A record does NOT redirect a function entry
// point. It redirects the `bl` instructions that CALL the guest function named
// by `target`, rewriting each to branch to a stub the fork registers as
// "MGO_PPU_HOOK_%02u" (the %02u is the record index). install() confirms this
// with the log line it formats at 0x14338a253:
//
//   "Installed PPU hook %s: %u call site(s) of 0x%x -> MGO_PPU_HOOK_%02u (0x%x)"
//
// The eight records, in table order, with their recovered values:
//
//   #  name                 target     min_level  sites        handler
//   0  ppu.pl_motion_mix    0x003370d8 255        1 @ 0x331d68  0x143a14dc0
//   1  ppu.motion_play      0x001739c0 3          9 @ 0x144b29e20 0x143a158b0
//   2  ppu.geo_line_region  0x000a28a8 3          text scan     0x143a18c80
//   3  ppu.geo_line_auto    0x000a15b0 3          text scan     0x143a18c80
//   4  ppu.geo_line         0x000a1f28 3          text scan     0x143a18c80
//   5  ppu.geo_pool_start   0x001b0c78 3          1 @ 0x9e0ac   0x143a19e00
//   6  ppu.geo_pool_start2  0x001b03b0 3          1 @ 0x9e0d4   0x143a19e00
//   7  ppu.modelsetup       0x00234a10 2          3 @ 0x144b29eb0 0x143a19ec0
//
// Record 1's nine call sites and record 7's three were read out of .rdata:
//
//   motion_play  0x60ac74 0x60ba50 0x60c72c 0x60d508 0x60e258
//                0x60ef34 0xd3f058 0xed69a8 0xd5ab38
//   modelsetup   0x14cea0 0x14ce28 0x14cdb0
//
// Every recovered target and call site falls inside MGO2.ELF's text LOAD, which
// runs 0x10000..0x118e348.
//
// min_level is the byte at +0x24. An earlier revision read those bytes as a
// redirect length and concluded the field was "not a uniform size (3/3/3/2/
// 255)". That was wrong: install() compares the byte against a global
// verbosity byte and skips the record when the global is lower, which is why
// the values are small ints and why pl_motion_mix carries 255, i.e. an entry
// that never installs at any sane verbosity. The record layout is documented in
// ppu_task_hle.h; this file only carries the data.
//
// The handler bodies are not recoverable as source, so a hook whose host body
// is not written yet reports handled=false and dispatch() falls through to the
// guest's own code. Raising Task Acceleration then does less work rather than
// silently corrupting the game.

namespace
{
	using namespace spu_task_hle;
	using namespace spu_task_hle::ppu;

	// Embedded SPU images the hooks are keyed on. These are the standard RPCS3
	// "SPU-<sha1>" identity strings.
	constexpr std::string_view spu_drawassist = "SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e";
	constexpr std::string_view spu_single_bus = "SPU-ae8a758775740615382268346f1a9cc14d9966f9";

	// Default handler for hooks whose host body is not written yet.
	void hook_unimplemented(ppu_thread&, direct_mem&, const call_regs&, call_result& result)
	{
		// Not handled -> the dispatcher falls through to the guest's own code.
		result.handled = false;
	}

	// motion_play's launcher, 0x143a158b0.
	//
	// The guest function is one of nine call sites of the same routine, so the
	// handler serves all of them; what distinguishes them - which clip, which
	// owner, which phase - is inside the guest's arguments rather than in the
	// call site. The recovered work is the DMA seam (see
	// mgo/mgo_motion_play.h), and every one of its checks is a refusal: an
	// unaligned or out-of-window transfer means the lift cannot reproduce what
	// the guest's DMA engine would have done, and the correct answer to that
	// is to decline and let the guest run.
	void motion_play_launch(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
	{
		mgo_motion_play::ctx c;
		c.mem = &mem;

		// gpr[2] is the bone the fork's passes are indexed by.
		const u32 bone = static_cast<u32>(regs.gpr[2]);

		mgo_motion_play::task_run<direct_mem> run(c);

		if (!run.run(bone))
		{
			// Same (file, line, message) triple as every other decline. Only
			// the first failure in a call is recorded, which is why the fork's
			// context keeps a flag next to the message pointer.
			spu_task_hle::note_decline(c.message ? c.message : "motion play declined", __FILE__, __LINE__);
			result.handled = false;
			return;
		}

		// The queue only becomes guest memory here, once every pass has
		// succeeded. A task abandoned half way through writes nothing.
		mgo_motion_play::task_commit(mem);

		result.handled = true;
		result.returned = true;
		result.return_value = 0;
	}

	// pl_motion_mix's launcher, 0x143a14dc0.
	//
	// The guest hands the host a 0x124-byte parameter block and the fork DMAs
	// seven buffers out of it, runs three lifted stages over the staged bone
	// data, and DMAs three back. Everything around that is reproduced in
	// mgo/mgo_pl_motion_mix.cpp - the two self-pointer checks, the busy test,
	// the 16-byte alignment rule, both 128 caps, the six sub-descriptors, the
	// scratch's dirty-block maps and the bone-descriptor proof obligation.
	// The three stages are compiled native code, so the handler reports the
	// fork's own "lifted code declined" reason and leaves result.handled
	// false, which runs the guest's own blend.
	void pl_motion_mix_launch(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
	{
		mgo_pl_motion_mix::launch(cpu, mem, regs, result);
	}

	// The fork's line_check body is 0x1172 bytes and begins with two guards: a
	// single-4KB-page test on guest r5, then a requirement that the structure
	// at (r5 - 0x7db0) carry two magic tags. That part is recovered and
	// implemented as a probe; the structure behind the tags is not identified,
	// so the hook reports what it sees and falls through to the guest.
	void line_check_probe(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
		{
			mgo_geo_coll_hooks::line_check(cpu, mem, regs, result);
		}

		// pool_start is one of the two handlers whose body was recovered in
		// full, so this entry can be marked `complete` and actually patched.
		void pool_start_probe(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
		{
			mgo_geo_coll_hooks::pool_start(cpu, mem, regs, result);
		}

	// The fork's modelsetup handler is the one recovered body that is
	// known to branch on which call site fired, so this entry carries the
	// per-site split explicitly instead of routing every site through one
	// default. See mgo/ppu_modelsetup_hook.cpp.
	void modelsetup_launch(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
	{
		mgo_modelsetup::launch(cpu, mem, regs, result);
	}

	spu_task_hle::ppu::hook_fn modelsetup_site_00() { return modelsetup_launch; }
	spu_task_hle::ppu::hook_fn modelsetup_site_01() { return modelsetup_launch; }
	spu_task_hle::ppu::hook_fn modelsetup_site_02() { return modelsetup_launch; }

	// The SPU module drawassist lives in. Read out of the fork's table, and
	// documentation rather than a match field - the load path has no module
	// name to compare against.
	constexpr std::string_view spurs_drawassist = "spu/spurs_drawassist.spu.task";

	// The fork gates its module hooks on the *log verbosity*, not on
	// `mgo_task_acceleration`: the record carries a `u32 min_verbosity` at
	// +0x30 and the consumer compares it against a single byte loaded from
	// the configuration block with `movzx`. Both shipped records say 0x101.
	u8 s_module_verbosity = 3;

	// Reported once, because the consequence is not obvious from the table.
	bool s_module_gate_reported = false;

	const std::vector<module_hook_entry> module_table
	{
		// Verbatim from 0x144bcd450, both entries transcribed field by field.
		//
		// The sites are offsets into the deployed image, and each record also
		// carries the instruction that must be sitting there. That pairing is
		// the guard: if a game update shifts the function, the word at the
		// site no longer matches and the hook leaves the image alone instead
		// of branching over whatever now lives there.
		//
		// `expected` decodes as a big-endian PPC conditional branch -
		// 0x4020007f is `bc` with BO=1, BI=0, AA=1, LK=1 and a 14-bit
		// displacement of 0x1f, i.e. "call 0x7c if CR0[0] is set". Both
		// entries are that shape, which is why both carry branch_selector 1.
		{ "drawassist.3120", spurs_drawassist, spu_drawassist, 0x00003120u, 0x4020007fu, 0x00003120u, 1u, &::mgo_drawassist_3120, 0x101u },
		{ "drawassist.4f20", spurs_drawassist, spu_drawassist, 0x00004f20u, 0x40fef807u, 0x00004f20u, 1u, &::mgo_drawassist_4f20, 0x101u },
	};

	// --- the single recovered image patch --------------------------------

	// The fork's image-patch record carries a *predicate*, not a worker: its
	// function pointer at 0x143ced610 is
	//
	//   movzx eax, byte ptr [0x1463bacd4] / test al,al / setne al / ret
	//
	// so the patch is enabled by one config byte. That byte is the Audio
	// Mixer Fast Path toggle, which is what the record is named after.
	bool gate_audio_mixer_fast_path()
	{
		return g_cfg.mgo.audio_mixer_fast_path.get();
	}

	const std::vector<image_patch_entry> image_patch_table
	{
		// Verbatim from 0x144bcd3b0 (bytes confirmed by pe.off_of_va):
		//
		//   +0x10 04 fc 00 00   offset      0x0000fc04
		//   +0x14 9f 43 00 4c   match       0x4c00439f
		//   +0x18 1f 00 80 40   replacement 0x4080001f
		//   +0x1c 00 00 00 00   unused
		//   +0x20 10 d6 ce 43   gate        0x143ced610
		//
		// Both words decode as branches rather than data. Read as
		// big-endian PPC64 (which is how the fork compares them - it
		// byte-swaps the image word before the compare):
		//
		//   0x4c00439f  primary opcode 19 (extended branch), BO=0, BI=0,
		//               AA=1, LK=1, extended opcode 0x1cf, i.e. the
		//               branch-conditional-indirect family through CTR
		//   0x4080001f  primary opcode 16 (bc), BO=4, BI=0, AA=1, LK=1,
		//               BD=+7 words
		//
		// So the patch swaps one control transfer for another - it
		// retargets the mixer entry point - rather than altering data.
		// The exact branch semantics are read off the ISA field layout
		// and not confirmed by tracing the image, so the table below is
		// transcribed verbatim rather than interpreted further.
		{ "mixer.single_bus", spu_single_bus, 0x0000fc04u, 0x4c00439fu, 0x4080001fu, 0u, &gate_audio_mixer_fast_path },
	};

	// --- the eight recovered PPU records ---------------------------------
	//
	// `sites` is left empty for the three geo_line* records: the fork lists no
	// call sites for them and installs them by scanning the module text for
	// every `bl` that targets the given address. install() reproduces that.

	std::vector<hook_entry> build_table()
	{
		return
		{
			// 0 - ppu.pl_motion_mix. min_level 255, so this entry is skipped at
			// any realistic verbosity and its handler is not reached.
			{ "ppu.pl_motion_mix", 0x003370d8u, 255, pl_motion_mix_launch, { 0x00331d68u } },

			// 1 - ppu.motion_play. One handler serves all nine sites; the
			// per-site variation is in the guest's arguments, not the caller.
			{ "ppu.motion_play", 0x001739c0u, 3, motion_play_launch,
				{
					0x0060ac74u, 0x0060ba50u, 0x0060c72cu, 0x0060d508u, 0x0060e258u,
					0x0060ef34u, 0x00d3f058u, 0x00ed69a8u, 0x00d5ab38u,
				} },

			// 2-4 - the three line_check registrations. Same handler, three
			// different guest functions, all installed by text scan.
			{ "ppu.geo_line_region", 0x000a28a8u, 3, line_check_probe, {} },
			{ "ppu.geo_line_auto", 0x000a15b0u, 3, line_check_probe, {} },
			{ "ppu.geo_line", 0x000a1f28u, 3, line_check_probe, {} },

			// 5-6 - pool_start, one explicit call site each. These are the two
			// only entries with a fully recovered handler body, so they are
			// also the only ones marked `complete`. See
			// mgo/ppu_geo_collision_hooks.cpp for the recovered body.
			{ "ppu.geo_pool_start", 0x001b0c78u, 3, pool_start_probe, { 0x0009e0acu }, true },
			{ "ppu.geo_pool_start2", 0x001b03b0u, 3, pool_start_probe, { 0x0009e0d4u }, true },

			// 7 - modelsetup, the only entry at min_level 2. The three sites
			// are named individually because the fork's handler distinguishes
			// them by lr-4; the fork compares two of the three and lets the
			// third fall through.
			{
				"ppu.modelsetup", 0x00234a10u, 2, mgo_modelsetup_hook::default_handler(),
				{
					0x0014cea0u, 0x0014ce28u, 0x0014cdb0u,
				},
				false,
				{
					{ 0x0014cea0u, modelsetup_site_00() },
					{ 0x0014ce28u, modelsetup_site_01() },
					{ 0x0014cdb0u, modelsetup_site_02() },
				},
			},
		};
	}
}

const std::vector<spu_task_hle::ppu::module_hook_entry>& spu_task_hle::ppu::get_module_hook_table()
{
	return module_table;
}

bool spu_task_hle::ppu::module_hook_site_matches(const module_hook_entry& entry, const std::string_view image_hash,
	const std::function<u8*(u32, u32)>& translate)
{
	// The fork reads exactly one word, with a size of 4, from the record's
	// image offset - the same shape as the image patches, and with the same
	// "expected" guard.
	u8* ptr = translate(entry.site, sizeof(u32));

	if (!ptr)
	{
		spu_log.warning("MGO: module hook %s: site 0x%05x is outside %s",
			entry.name.data(), entry.site, image_hash.data());
		return false;
	}

	u32 have = 0;
	std::memcpy(&have, ptr, sizeof(have));

	if (have != entry.expected)
	{
		spu_log.warning("MGO: module hook %s: site 0x%05x holds 0x%08x, expected 0x%08x; not installed",
			entry.name.data(), entry.site, have, entry.expected);
		return false;
	}

	return true;
}

const std::vector<spu_task_hle::ppu::image_patch_entry>& spu_task_hle::ppu::get_image_patches()
{
	return image_patch_table;
}

usz spu_task_hle::ppu::on_embedded_spu_image(std::string_view image_hash, std::string_view module_name,
	const std::function<u8*(u32, u32)>& translate, bool forced)
{
	usz installed = 0;

	// The fork runs the image patches first and only when the caller did not
	// force hooks alone. `forced` means "install the hooks and nothing else":
	// at 0x1434ae520 the patch table is tested for emptiness and at
	// 0x1434ae525 the forced flag sends control past the patch loop, so a
	// forced install never touches a byte of the image. The patch loop itself
	// falls through to the module hook loop when it runs out of entries
	// (je 0x1434ae52b at 0x1434ae987), so the two are sequential, not
	// exclusive.
	if (!forced)
	{
		for (const auto& patch : image_patch_table)
		{
			// Image patches are matched on identity alone - there is no
			// module name to compare against, because the record describes
			// the whole image.
			if (patch.image_hash != image_hash)
			{
				continue;
			}

			if (!patch.gate || !patch.gate())
			{
				continue;
			}

			switch (apply_image_patch(patch, translate))
			{
			case image_patch_result::applied:
				spu_log.notice("MGO: Applied patch %s (%s, 0x%05x: 0x%08x -> 0x%08x)",
					patch.name.data(), image_hash.data(), patch.offset, patch.match, patch.replacement);
				installed++;
				break;

			case image_patch_result::already:
				// The fork re-stores the identical word here rather than
				// skipping the write; the bytes are the same either way.
				spu_log.trace("MGO: Patch %s (%s, 0x%05x) is already applied", patch.name.data(), image_hash.data(), patch.offset);
				installed++;
				break;

			case image_patch_result::out_of_range:
			case image_patch_result::not_matched:
				// A guard that does not match is the interesting case: the
				// image is not the one this patch was written against, or the
				// offset is outside it. Either way the image is left alone.
				spu_log.warning("MGO: Patch %s (%s, 0x%05x: expected 0x%08x) not applied", patch.name.data(), image_hash.data(), patch.offset, patch.match);
				break;
			}
		}
	}

	for (const auto& entry : module_table)
	{
		// Match on the image identity, not on the module name.
		//
		// The fork's table carries a module name for documentation - it is how
		// the two drawassist entries are described ("these live in
		// spu/spurs_drawassist.spu.task") - but the SPU image load path has no
		// module name to compare against, and an entry's `image_hash` alone
		// identifies the image it belongs to. An empty image_hash means "any
		// image". A module name is only required when one was supplied and it
		// disagrees.
		if (entry.image_hash != image_hash)
		{
			continue;
		}

		if (!module_name.empty() && entry.module != module_name)
		{
			continue;
		}

		// The fork's gate, reproduced exactly - including its byte-versus-dword
		// asymmetry. With the shipped threshold of 0x101 this never passes, so
		// no module hook installs and the drawassist subsystem stays dormant,
		// which is what the reference build does too.
		if (!forced && static_cast<u32>(s_module_verbosity) < entry.min_verbosity)
		{
			if (!s_module_gate_reported)
			{
				s_module_gate_reported = true;

				spu_log.notice("MGO: module hook %s needs verbosity >= %u but the verbosity is a byte; not installed",
					entry.name.data(), entry.min_verbosity);
			}

			continue;
		}

		if (!entry.fn)
		{
			continue;
		}

		// The site guard. The fork reads the word at the entry's image offset
		// through the same bounds-checked accessor the image patches use and
		// compares it against the record's `expected` instruction; a mismatch
		// means this is not the build the record was written for.
		//
		// Passing it is necessary but not sufficient. The fork then *patches*
		// the site with a branch, which is what makes the task call the host
		// body instead of the module's own entry point; the branch encoding is
		// the one part of this loop not yet decoded, so the replica verifies
		// and reports eligibility and leaves the image untouched. The guest
		// therefore keeps running its original microcode, which is the safe
		// direction to be wrong in.
		if (!module_hook_site_matches(entry, image_hash, translate))
		{
			continue;
		}

		spu_log.notice("MGO: module hook %s is eligible for %s (site 0x%05x holds 0x%08x)",
			entry.name.data(), image_hash.data(), entry.site, entry.expected);
		installed++;
	}

	return installed;
}

std::vector<spu_task_hle::ppu::hook_entry> mgo_ppu_hooks()
{
	static const std::vector<spu_task_hle::ppu::hook_entry> table = build_table();

	return table;
}

// ---------------------------------------------------------------------------
// HLE registration
// ---------------------------------------------------------------------------
//
// The fork's "MGO_PPU_HOOK_%02u" names are not synthesised stubs. They are
// ordinary entries in RPCS3's HLE function table: `ppu_function_manager` hands
// out 8-byte slots of real guest memory, each holding a branch into the
// interpreter entry that runs the host body (see the fill loop in
// ppu_module_manager::load_game, PPUModule.cpp:361). Redirecting a call site
// therefore means branching to `func_addr(index, is_code_addr = true)` - the
// same mechanism the fork's `RPCS3_HLE_LIBRARY` module uses for
// `WaitForSPUsToEmptySNRs`.
//
// One registration per table entry, so slot index == record index, matching the
// `%02u` in the fork's log line.

namespace
{
	// Guest state one hook body is handed. The host bodies written so far are
	// probes that only observe, so the register block is passed through and the
	// return value is ignored.
	struct hook_args
	{
		spu_task_hle::ppu::direct_mem mem;
		spu_task_hle::ppu::call_regs regs{};
		spu_task_hle::ppu::call_result result{};

		explicit hook_args(ppu_thread& cpu) : mem(cpu)
		{
			for (usz i = 0; i < regs.gpr.size(); i++)
			{
				regs.gpr[i] = cpu.gpr[i];
			}

			regs.lr = cpu.lr;
		}
	};

	// register_static_function<> keys its static storage on the address of a
	// distinct function, so each entry needs its own identity symbol. These
	// bodies are never executed - the interpreter entry bound below is what
	// actually runs - but they must exist and be distinct.
	void hook_body_00(ppu_thread&) {}
	void hook_body_01(ppu_thread&) {}
	void hook_body_02(ppu_thread&) {}
	void hook_body_03(ppu_thread&) {}
	void hook_body_04(ppu_thread&) {}
	void hook_body_05(ppu_thread&) {}
	void hook_body_06(ppu_thread&) {}
	void hook_body_07(ppu_thread&) {}

	template<spu_task_hle::ppu::hook_fn Fn>
	void run_hook(ppu_thread& cpu)
	{
		hook_args args{cpu};

		// `cia` is the HLE slot the guest branched into, not the original
		// function - the call site's `bl` was rewritten to point here, so the
		// original address is gone as far as execution is concerned. The guest
		// link register still holds the real return address, and lr-4 recovers
		// the original call site, which is how modelsetup's handler tells its
		// three call sites apart.
		args.regs.pc = cpu.cia;
		args.regs.lr = cpu.lr;
		args.regs.call_site = (cpu.lr >= 4 && (cpu.lr & 3) == 0) ? static_cast<u32>(cpu.lr - 4) : 0;

		Fn(cpu, args.mem, args.regs, args.result);

		// An entry marked `complete` publishes its return value and returns to
		// the caller. A probe leaves the result untouched, and because its call
		// site is never redirected it is never reached this way.
		if (args.result.returned)
		{
			cpu.gpr[3] = args.result.return_value;
		}

		cpu.cia = static_cast<u32>(cpu.lr) & ~3u;
	}

	// Slot index == record index in the table above.
	std::array<u32, 8> register_hooks()
	{
		return
		{
			ppu_module_manager::register_static_function<&hook_body_00>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_00", BIND_FUNC_WITH_BLR(run_hook<hook_unimplemented>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_00")).index,
			ppu_module_manager::register_static_function<&hook_body_01>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_01", BIND_FUNC_WITH_BLR(run_hook<hook_unimplemented>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_01")).index,
			ppu_module_manager::register_static_function<&hook_body_02>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_02", BIND_FUNC_WITH_BLR(run_hook<line_check_probe>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_02")).index,
			ppu_module_manager::register_static_function<&hook_body_03>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_03", BIND_FUNC_WITH_BLR(run_hook<line_check_probe>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_03")).index,
			ppu_module_manager::register_static_function<&hook_body_04>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_04", BIND_FUNC_WITH_BLR(run_hook<line_check_probe>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_04")).index,
			ppu_module_manager::register_static_function<&hook_body_05>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_05", BIND_FUNC_WITH_BLR(run_hook<pool_start_probe>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_05")).index,
			ppu_module_manager::register_static_function<&hook_body_06>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_06", BIND_FUNC_WITH_BLR(run_hook<pool_start_probe>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_06")).index,
			ppu_module_manager::register_static_function<&hook_body_07>("RPCS3_HLE_LIBRARY", "MGO_PPU_HOOK_07", BIND_FUNC_WITH_BLR(run_hook<hook_unimplemented>, "RPCS3_HLE_LIBRARY"), ppu_generate_id("MGO_PPU_HOOK_07")).index,
		};
	}
}

u32 spu_task_hle::ppu::hook_stub_addr(usz index)
{
	static const std::array<u32, 8> indices = register_hooks();

	if (index >= indices.size())
	{
		return 0;
	}

	// `is_code_addr` skips the 4-byte header in each slot, landing on the
	// interpreter entry rather than the branch that reaches it.
	return g_fxo->get<ppu_function_manager>().func_addr(indices[index], true);
}

void mgo_geo_coll_hooks_reset()
{
	mgo_geo_coll_hooks::reset();
}
