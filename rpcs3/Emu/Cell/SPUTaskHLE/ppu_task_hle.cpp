#include "stdafx.h"
#include "ppu_task_hle.h"

#include "Emu/Cell/PPUThread.h"
#include "Emu/Memory/vm.h"
#include "Emu/system_config.h"
#include "Emu/System.h"

#include "Emu/mgo/ppu_geo_collision_hooks.h"
#include "Emu/mgo/mgo_modelsetup.h"
#include "Emu/mgo/mgo_pl_motion_mix.h"
#include "Emu/mgo/mgo_waits.h"

#include <algorithm>
#include <atomic>
#include <cstring>

// The MGO2 hooks themselves live in mgo_ppu_hooks.cpp.
std::vector<spu_task_hle::ppu::hook_entry> mgo_ppu_hooks();

namespace
{
	// Hooks that passed the level gate and were installed for the current
	// executable, keyed by the guest address of the function entry.
	std::map<u32, spu_task_hle::ppu::hook_entry> s_installed;

	// Mirrors the keys of s_installed so callers can test membership cheaply.
	std::set<u32> s_installed_starts;

	// Stub address -> the entry whose call sites were rewritten to branch
	// there. This is what dispatch() keys on, because by the time dispatch
	// runs the original `bl` is no longer the instruction that will execute.
	std::map<u32, spu_task_hle::ppu::hook_entry> s_stub_to_entry;

	// Module hooks already installed for the current run, keyed by the
	// "SPU-<sha1>" identity they were installed against.
	std::set<std::string> s_installed_images;

	// Global verbosity the fork compares each hook record's +0x24 byte against
	// (global at 0x1466bab94 in the reference image, read at 0x143389d84).
	// The fork's own value is not recoverable from a static read, so this
	// mirrors the "3" that every real hook record asks for: entries recorded
	// at +0x24 == 3 install normally, the modelsetup entry at 2 installs more
	// freely, and pl_motion_mix at 255 stays disabled.
	u8 g_mgo_hook_verbosity = 3;

	// Mirror of s_installed_starts.size() so dispatch() can test membership
	// without touching the std::set. Not on the instruction loop any more -
	// dispatch is reached through the HLE entry path - but it still keeps
	// dispatch() a single load and compare in the common case.
	std::atomic<u32> s_installed_count{0};

	// Mirrors the fork's t_last_decline: why the most recent lift declined, and
// where. The fork keeps the (file, line, message) triple on the thread at
// +0x1e8/+0x1f0/+0x1f8; one place is equivalent here.
	std::string s_last_decline;
	std::string s_last_decline_file;
	u32 s_last_decline_line = 0;
}

namespace spu_task_hle
{
	bool level_at_least(mgo_task_acceleration level)
	{
		return g_cfg.mgo.task_acceleration.get() >= level;
	}

	namespace ppu
	{
		// PPC64 `bl` opcode. The fork builds a replacement by masking the
		// existing branch's 26-bit displacement field and OR-ing in 0x48000001
		// (see 0x14338a13e), so this constant is the identity it compares and
		// reconstructs against.
		const u32 bl_opcode = 0x48000001u;

		// Guest address a `bl` at `call_site` branches to, or 0 when the
		// instruction is not a branch.
		//
		// The displacement is bits 2..25 and is already a *byte* offset - it is
		// not scaled by 4. Verified against MGO2.ELF: the recovered modelsetup
		// call sites decode to 0x234a10 with no shift, e.g. at 0x14cea0 the
		// instruction 0x480e7b71 has field 0x000e7b70, and
		// 0x14cea0 + 0xe7b70 = 0x234a10.
		//
		// This matches the fork's own decode at 0x14338a17a:
		//   shl r9d,6 / sar r9d,6 / and r9d,0xfffffffc / add r9d,eax
		// which sign-extends from bit 25 and adds without scaling.
		u32 branch_target(u32 call_site, u32 insn)
		{
			if ((insn & 0xfc000003u) != bl_opcode)
			{
				return 0;
			}

			const s32 disp = static_cast<s32>(insn << 6) >> 6;

			return (call_site + static_cast<u32>(disp)) & ~3u;
		}

		// Displacement `bl` at `call_site` must have to reach `target`, or the
		// call cannot be redirected at all. PPC64 `bl` carries a signed 26-bit
		// word displacement, i.e. +/-32 MB, which is the same bound the fork
		// checks before patching.
		bool branch_reaches(u32 call_site, u32 target)
		{
			const s64 delta = static_cast<s64>(target) - static_cast<s64>(call_site);

			return (delta & 3) == 0 && delta >= -(1 << 25) && delta <= (1 << 25);
		}

		// Rewrites the `bl` at `call_site` so it branches to `target`.
		//
		// This is the write the fork performs at 0x14338a198. It rebuilds the
		// instruction as `0x48000001 | (delta & 0x03fffffc)` and stores it
		// big-endian, matching the `and ecx, 0x3fffffc / or ecx, 0x48000001`
		// pair in the original. Returns false - without writing - when the
		// site is unmapped, is not already a `bl`, or is out of range.
		bool patch_branch(u32 call_site, u32 target)
		{
			if (!vm::check_addr(call_site, vm::page_writable, 4))
			{
				return false;
			}

			const u32 insn = vm::read32(call_site);

			if ((insn & 0xfc000003u) != bl_opcode)
			{
				return false;
			}

			if (!branch_reaches(call_site, target))
			{
				return false;
			}

			// Byte offset, already aligned, straight into bits 2..25.
			const u32 disp = static_cast<u32>(static_cast<s64>(target) - static_cast<s64>(call_site)) & 0x03fffffcu;

			vm::write32(call_site, bl_opcode | disp);

			return true;
		}

		// --- direct_mem -------------------------------------------------------

		u8* direct_mem::guest_ptr(u32 addr, u32 size) const
		{
			if (!vm::check_addr(addr, vm::page_readable, size))
			{
				return nullptr;
			}

			return vm::get_super_ptr<u8>(addr);
		}

		bool direct_mem::guest_valid(u32 addr, u32 size, bool writable) const
		{
			const u8 flags = vm::page_readable | (writable ? vm::page_writable : 0);
			return vm::check_addr(addr, flags, size);
		}

		void direct_mem::publish32(u32 addr, u32 value) const
		{
			if (!guest_valid(addr, sizeof(u32), true))
			{
				return;
			}

			vm::write<u32>(addr, value);
		}

		// --- table ------------------------------------------------------------

		const std::vector<hook_entry>& get_hook_table()
		{
			static const std::vector<hook_entry> table = mgo_ppu_hooks();
			return table;
		}

		// The local store holds big-endian code, so a word is compared and
		// stored byte-swapped. This is the fork's own pair of swaps, at
		// 0x1434ae9f5 (read side) and 0x1434ae967 (write side).
		static u32 swap32(u32 v)
		{
			return (v >> 24) | ((v >> 8) & 0x0000ff00u) | ((v << 8) & 0x00ff0000u) | (v << 24);
		}

		image_patch_result apply_image_patch(const image_patch_entry& entry, const std::function<u8*(u32, u32)>& translate)
		{
			// The size is hardcoded to 4 in the fork (mov dword ptr
			// [rsp+0x48], 4 at 0x1434ae9c7), so the patch is always exactly
			// one instruction wide.
			u8* ptr = translate(entry.offset, 4);

			if (!ptr)
			{
				return image_patch_result::out_of_range;
			}

			u32 have = 0;
			std::memcpy(&have, ptr, sizeof(have));

			// Compare against the big-endian reading of the image.
			const u32 guest = swap32(have);

			if (guest == entry.match)
			{
				have = swap32(entry.replacement);
				std::memcpy(ptr, &have, sizeof(have));
				return image_patch_result::applied;
			}

			// The same word, compared without swapping the replacement: this
			// is true exactly when the patch already ran, so re-deploying an
			// image is a no-op.
			if (guest == entry.replacement)
			{
				return image_patch_result::already;
			}

			return image_patch_result::not_matched;
		}

		std::string_view get_executable_hash()
		{
			const std::string& hash = Emu.GetExecutableHash();
			return hash.empty() ? std::string_view{} : std::string_view{hash};
		}

		usz install(std::string_view name, u32 module_base, u32 module_size, bool forced)
		{
			const auto& table = get_hook_table();

			// The fork bounds the table at 0x11 entries (cmp rsi, 0x11 at
			// 0x143389c85) and refuses to install when the loaded module's
			// executable hash does not match get_executable_hash(). Both checks
			// are reproduced here rather than assumed.
			if (table.size() > 0x11)
			{
				return 0;
			}

			usz patched = 0;

			for (const hook_entry& entry : table)
			{
				if (!entry.fn || entry.target == 0)
				{
					continue;
				}

				if (!forced && entry.min_level > g_mgo_hook_verbosity)
				{
					continue;
				}

				// Collect this entry's call sites. Entries that list none are
				// installed by scanning the module for callers of `target`.
				std::vector<u32> sites = entry.call_sites;

				if (sites.empty())
				{
					if (!vm::check_addr(entry.target, vm::page_executable, 4))
					{
						continue;
					}

					for (u32 off = 0; off + 4 <= module_size; off += 4)
					{
						const u32 addr = module_base + off;

						if (!vm::check_addr(addr, vm::page_executable, 4))
						{
							continue;
						}

						// Guest memory is big-endian; read32 converts to host
						// order, so `insn` is the instruction as decoded.
						const u32 insn = vm::read32(addr);

						// Only bother with words that decode as a `bl` at all;
						// the target comparison below is the real filter.
						if ((insn & 0xfc000003u) != bl_opcode)
						{
							continue;
						}

						if (branch_target(addr, insn) == entry.target)
						{
							sites.push_back(addr);
						}
					}
				}

				usz index = 0;

				for (const auto& candidate : table)
				{
					if (&candidate == &entry)
					{
						break;
					}

					index++;
				}

				// Only an entry whose host body fully replaces the guest
				// function may be redirected. Patching a `bl` bypasses the
				// original body outright, so an observing-only handler would
				// turn a diagnostic into a crash.
				const u32 stub = entry.complete ? hook_stub_addr(index) : 0;

				for (const u32 site : sites)
				{
					if (!vm::check_addr(site, vm::page_executable, 4))
					{
						continue;
					}

					if (stub != 0 && patch_branch(site, stub))
					{
						patched++;
						s_installed_count = static_cast<u32>(s_installed_starts.size()) + 1;
					}

					// Recorded either way, so hooked_function_starts() can
					// report what is hooked.
					s_installed[site] = entry;
					s_installed_starts.insert(site);
				}

				if (stub != 0)
				{
					// dispatch() keys on the stub, because the patched `bl`
					// will hand control to the stub's HLE entry, not to `site`.
					s_stub_to_entry[stub] = entry;
					s_installed_count = static_cast<u32>(s_stub_to_entry.size());
				}
			}

			return patched;
		}

		std::vector<u32> hooked_function_starts()
		{
			// The fork's implementation (0x14338a400) walks the record table
			// and collects each record's +0x20 target, but only for records
			// whose +0x24 byte is 1 - so it reports *installed* entry points,
			// not call sites. It is a diagnostic: "which guest functions are
			// these hooks standing in for", not the dispatch table.
			std::vector<u32> starts;

			const auto& table = get_hook_table();

			starts.reserve(s_installed_count.load(std::memory_order_relaxed));

			for (u32 site : s_installed_starts)
			{
				const auto it = s_installed.find(site);

				if (it == s_installed.end())
				{
					continue;
				}

				if (it->second.target != 0)
				{
					starts.push_back(it->second.target);
				}
			}

			(void)table;

			return starts;
		}

		void on_module_loaded(u32 base, u32 size, bool forced)
		{
			// The fork refuses to install unless the loaded module's executable
			// identity matches its hardcoded hash, and skips the whole pass when
			// the module has no code mapped.
			if (!forced)
			{
				const std::string_view want = "PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1";
				const std::string_view have = get_executable_hash();

				if (have.empty() || have != want)
				{
					return;
				}

				// Second gate, recovered from mgo_waits::ppu_lwarx_wait at
				// 0x1434af238: the whole task-acceleration path is inert unless
				// the running title is one of the two MGO games. The constants
				// there are 0x31303030474d504e and 0x32303030474d504e with a
				// ninth byte of 0x30, which is "NPMG00010" and "NPMG00020" in
				// plain ASCII - not obfuscation, just an XOR-accumulate strcmp.
				//
				// The hash check above is strictly stronger, so this cannot
				// reject anything the hash accepted. It is here because it is
				// what the fork does, and because it is the gate that will
				// matter once other hooks stop being hash-pinned.
				const std::string& title = Emu.GetTitleID();

				if (!mgo_waits::title_supported(title.c_str()))
				{
					return;
				}
			}

			if (!vm::check_addr(base, vm::page_executable, size))
			{
				return;
			}

			const usz patched = install("module", base, size, forced);

			if (patched != 0)
			{
				ppu_log.notice("MGO: %u PPU hook call site(s) installed for module at %#x (%u bytes)",
					static_cast<u32>(patched), base, size);
			}
		}

		bool dispatch(ppu_thread& cpu, u32 cia)
		{
			// Fast path: nothing installed.
			if (s_installed_count.load(std::memory_order_relaxed) == 0)
			{
				return false;
			}

			// The key is the *stub* address, not the original call site.
			//
			// The fork reaches this from ppu_module_manager's generated HLE
			// entry lambdas: it rewrites the call site's `bl` to point at an
			// HLE function slot, RPCS3 dispatches that slot, and the lambda
			// calls dispatch() with the address of the slot it was entered at.
			// So the dispatch key has to be derived from the stub rather than
			// remembered from the original `bl`, which no longer exists as
			// executable code once patched.
			const auto it = s_stub_to_entry.find(cia);

			if (it == s_stub_to_entry.end())
			{
				return false;
			}

			const hook_entry& entry = it->second;
			const u64 lr = cpu.lr;

			direct_mem mem{cpu};

			// Mirror the whole guest register block. The fork's handlers read
			// it directly out of this struct at fixed displacements (r3 at
			// +0x18, r5 at +0x28, r24 at +0xc0, pc at +0x100, lr at +0x108),
			// so every field a handler might touch has to be populated.
			call_regs regs{};
			for (usz i = 0; i < regs.gpr.size(); i++)
			{
				regs.gpr[i] = cpu.gpr[i];
			}

			regs.pc = cia;
			regs.lr = lr;

			// The call site is lr-4 for any hook reached through a `bl`,
			// which is every hook this framework installs. modelsetup's
			// recovered body switches on exactly this value before it does
			// anything else.
			if ((lr & 3) == 0 && lr >= 4)
			{
				regs.call_site = static_cast<u32>(lr - 4);
			}

			// A per-call-site override wins over the entry's default handler.
			// The fork performs the same selection inside its own body, so this
			// is the framework-side equivalent and is only populated where the
			// fork's dispatch is actually known.
			hook_fn fn = entry.fn;

			for (const site_handler& sh : entry.by_site)
			{
				if (sh.call_site == regs.call_site && sh.fn != nullptr)
				{
					fn = sh.fn;
					break;
				}
			}

			if (!fn)
			{
				return false;
			}

			call_result result{};
			fn(cpu, mem, regs, result);

			return result.handled;
		}

		void on_emulation_stop()
		{
			reset();
		}

		const std::set<std::string>& hooked_spu_images()
		{
			return s_installed_images;
		}

		void reset()
		{
			s_installed.clear();
			s_installed_starts.clear();
			s_stub_to_entry.clear();
			s_installed_count = 0;
			s_installed_images.clear();
			s_last_decline.clear();
			s_last_decline_file.clear();
			s_last_decline_line = 0;
		}
	}

		void on_stop(spu_thread&, u32)
	{
		// The fork's on_stop exists so the parallel modelsetup pool can join
		// work owned by a thread that has finished. Nothing here runs lifted
		// work yet, so there is nothing to join.
	}

	std::string_view last_decline()
	{
		return s_last_decline;
	}

	void note_decline(std::string_view why, std::string_view file, u32 line)
	{
		s_last_decline.assign(why);
		s_last_decline_file.assign(file);
		s_last_decline_line = line;

		ppu_log.trace("MGO: declined (%s) at %s:%u", why.data(),
			file.empty() ? "<unknown>" : file.data(), line);
	}

	void reset()
	{
		ppu::reset();

		// Subsystem probes keep per-run state too.
		mgo_geo_coll_hooks::reset();

		// The modelsetup front end keeps one 0x5c180 scratch buffer per
		// known image, so it holds the only allocation in this subsystem
		// that has to be handed back on exit.
		mgo_modelsetup::reset();

		// So does pl_motion_mix's, for the same reason.
		mgo_pl_motion_mix::reset();
	}
}