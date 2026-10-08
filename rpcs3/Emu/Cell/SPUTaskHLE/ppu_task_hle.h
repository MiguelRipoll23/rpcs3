#pragma once

// PPU task HLE framework for Metal Gear Online.
//
// The SaveMGO fork replaces selected MGO2 guest functions with host
// implementations at load time. The framework is gated on two things:
//
//   * the executable identity  - spu_task_hle::ppu::get_executable_hash(),
//     which is the "PPU-<sha1>" hash the patch engine already uses; and
//   * the configured aggressiveness - spu_task_hle::level_at_least(), which
//     compares against g_cfg.mgo.task_acceleration.
//
// A hook is installed by redirecting the guest function entry to a dispatch
// stub. dispatch() then looks the current instruction address up in the hook
// table and runs the matching handler with access to the guest's registers.

#include "Emu/system_config_types.h"
#include "util/types.hpp"

#include <array>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

class ppu_thread;
class spu_thread;

// The per-task environment the SPU module hooks are handed. Defined in
// mgo/drawassist_hooks.h; forward declared here so the module hook table can
// name the fork's worker signature without depending on that header.
namespace mgo_da4f20_detail
{
	struct task_env;
}

namespace spu_task_hle
{
	// True when the configured task-acceleration level is at least `level`.
	// This is the single gate every hook passes through.
	bool level_at_least(mgo_task_acceleration level);

	namespace ppu
	{
		// Guest register access for a hooked function.
		//
		// This layout is not a guess. The fork's handlers take the same block
		// as their third argument (rcx=ppu_thread, rdx=direct_mem,
		// r8=call_regs, r9=call_result), and every recovered handler reads
		// fields out of it at fixed displacements:
		//
		//   +0x000  gpr[0..31]   8 bytes each, so r3 is +0x18, r5 +0x28,
		//                        r24 +0xc0
		//   +0x100  pc
		//   +0x108  lr
		//
		// which matches this struct field for field.
		struct call_regs
		{
			std::array<u64, 32> gpr{};
			u64 pc = 0;   // guest PC of the hooked instruction
			u64 lr = 0;   // guest link register at entry

			// Address of the `bl` that invoked the hook, i.e. lr - 4.
			//
			// This is the fork's dispatch key. modelsetup_launch opens with
			//   lea r12d, [rsi - 4]      ; rsi = lr
			//   cmp  r12d, 0x14cea0
			//   cmp  r12d, 0x14ce28
			// so it distinguishes which of its three call sites fired before
			// doing anything else. A handler that serves several sites must
			// branch on this.
			//
			// It is a derived convenience rather than a separate field the
			// guest owns: the guest's own state is lr, and a hook reached
			// other than through a `bl` has no call site, in which case this
			// is zero.
			u32 call_site = 0;
		};

		// What a handler leaves behind.
		struct call_result
		{
			bool handled = false;  // false -> fall through to the guest code
			bool returned = false; // true  -> return to guest `lr`
			u64 return_value = 0;
		};

		// Safe access to guest memory from a hook handler.
		//
		// These three are the fork's, with the fork's names and signatures
		// (demangled from the reference image):
		//
		//   direct_mem::guest_ptr  (u32)
		//   direct_mem::guest_valid (u32, u32, bool)
		//   direct_mem::publish32   (u32, u32)
		class direct_mem
		{
		public:
			explicit direct_mem(ppu_thread& cpu) : m_cpu(cpu) {}

			// Raw pointer to guest memory, nullptr if out of bounds.
			u8* guest_ptr(u32 addr, u32 size = 1) const;

			bool guest_valid(u32 addr, u32 size, bool writable = false) const;

			// Little-endian store used to publish a result back to the guest.
			void publish32(u32 addr, u32 value) const;

		private:
			ppu_thread& m_cpu;
		};

		using hook_fn = void (*)(ppu_thread&, direct_mem&, const call_regs&, call_result&);

		// A module hook runs inside an SPU task, not on a PPU call, so its
		// worker takes the fork's per-task environment instead of a guest
		// register block. Both of the fork's module hooks have exactly this
		// signature - `void mgo_drawassist_4f20(task_env&)` - and that is the
		// only place `task_env` is ever named in the binary.
		using module_hook_fn = void (*)(mgo_da4f20_detail::task_env&);

		// Per-call-site refinement of a handler.
		//
		// The fork does not use a table for this - each handler switches on
		// call_regs::call_site itself - but recording the sites alongside the
		// entry keeps the recovered dispatch next to the data it came from
		// instead of only in the handler body.
		struct site_handler
		{
			u32 call_site = 0;
			hook_fn fn = nullptr;
		};

		// One entry of the fork's PPU hook table, recovered from .rdata at
		// 0x144b29ec0: eight 64-byte records.
		//
		// The record does NOT hook a function entry point. It redirects the
		// `bl` instructions that *call* a guest function, rewriting each one to
		// branch to a generated stub named "MGO_PPU_HOOK_%02u" (index = record
		// index). See spu_task_hle::ppu::install.
		//
		// Decoded field offsets within the 64-byte record:
		//
		//   +0x00  const char*  name        log channel, e.g. "ppu.geo_line"
		//   +0x08  u32          single      one explicit call site, or 0
		//   +0x10  const u32*   list        array of call sites, or nullptr
		//   +0x18  u64          list_count  length of `list`
		//   +0x20  u32          target      guest address being redirected
		//   +0x24  u8           min_level   see below
		//   +0x28  hook_fn      handler     host implementation
		//   +0x30  u64          reserved    (nonzero only for modelsetup)
		//   +0x38  u64          reserved    (nonzero only for modelsetup)
		//
		// Call sites come from exactly one of three places, in priority order:
		//
		//   single != 0           that one address
		//   list_count != 0       the `list` array
		//   neither                a text scan: every `bl` in the module whose
		//                         computed target equals `target`
		//
		// min_level is the byte at +0x24, compared against a global verbosity
		// byte at 0x1466bab94; install skips the entry when the global is lower.
		// That is why the values look like small integers rather than sizes
		// (3, 3, 3, 2, 255) and why an earlier revision of this file, which
		// read them as a byte count, was wrong. 255 effectively disables an
		// entry unless the global is raised to match.
		struct hook_entry
		{
			std::string_view name;
			u32 target = 0;               // guest address whose callers are redirected
			u8 min_level = 0;             // minimum global verbosity, from +0x24
			hook_fn fn = nullptr;

			// Call sites, when the entry lists them explicitly. Empty means the
			// entry is installed by scanning the module text for callers of
			// `target`, which is what the fork does for all three ppu.geo_line*
			// entries and why no addresses are recorded for them.
			std::vector<u32> call_sites;

			// True only when `fn` fully replaces the guest function.
			//
			// This matters more than it looks. The fork redirects the `bl` that
			// calls the target, so the original body is *bypassed*, not fallen
			// through to - there is no "handled = false" path once the call site
			// is patched. An entry is therefore only safe to install when the
			// host body implements the whole function. Entries that merely
			// observe are recorded but never patched.
			bool complete = false;

			// Optional per-call-site override of `fn`, consulted by
			// dispatch() when call_regs::call_site matches. Empty for every
			// entry except those whose fork counterpart is known to switch on
			// the call site - currently only ppu.modelsetup, whose recovered
			// body compares lr-4 against two of its three sites.
			std::vector<site_handler> by_site;
		};

		// Guest address of the HLE function slot registered for hook `index`,
		// or 0 when it has none.
		//
		// The fork does not synthesise stubs. Its "MGO_PPU_HOOK_%02u" names are
		// ordinary entries in RPCS3's HLE function table, so the call site is
		// redirected to the address of that table's slot - real guest memory
		// holding a branch into the interpreter entry that runs the host body.
		u32 hook_stub_addr(usz index);

		// The fork's hook table is not keyed on a PPU guest address. It is a
		// table of *SPU module entry points*, matched against the hash of the
		// embedded SPU image the game loads. `module` is the entry name as it
		// appears in the SPRX module table, `image_hash` is the "SPU-<sha1>"
		// identity of the embedded image (empty = any image), and `fn` is what
		// runs instead.
		//
		// This is what makes Task Acceleration work at all: the accelerated code
		// lives in SPU modules, not in the main ELF, so a PPU-address table can
		// never match it.
		//
		// Matching is on `image_hash`. `module` is documentation - it names the
		// module an entry lives in, and the SPU image load path has no module
		// name to compare it against - so it is only checked when the caller
		// supplies one.
		//
		// The fork's own record is 0x38 (56) bytes, recovered from the consumer
		// loop at 0x1434ae683 which advances by 0x38 per entry. Both of the
		// fork's entries transcribe exactly (bytes read at 0x144bcd450):
		//
		//   +0x00  const char* name            "drawassist.3120"
		//   +0x08  const char* module          "spu/spurs_drawassist.spu.task"
		//   +0x10  const char* image_hash      "SPU-9aa78281...dd44e"
		//   +0x18  u32         branch_selector 1
		//   +0x1c  u32         site            0x00003120   (image offset)
		//   +0x20  u32         expected        0x4020007f   (instruction there)
		//   +0x24  u32         target          0x00003120
		//   +0x28  hook_fn     fn              0x143cdf890
		//   +0x2c  u32         1
		//   +0x30  u32         min_verbosity   0x101
		//   +0x34  u32         0
		//
		// `site` is an offset *into the deployed image*, not a PPU address -
		// which is the whole point of keying these on an image hash. The
		// consumer reads the word at `site` through the same bounds-checked
		// accessor the image patches use and compares it against `expected`,
		// so a game update that moves the function makes the hook decline
		// rather than rewrite unrelated code.
		//
		// `min_verbosity` is the awkward field. The consumer loads its
		// left-hand side with `movzx ecx, byte ptr [0x1463bac94]` - a single
		// byte, and one that sits in the same configuration block as the
		// Audio Mixer Fast Path toggle at 0x1463bacd4 - and then compares it
		// with a *32-bit* `cmp ecx, dword ptr [r13+rsi+0x30]`. So the
		// threshold is a u32 and the value is a u8. With the shipped value
		// of 0x101 = 257 that comparison can never pass: no byte is >= 257,
		// so **neither drawassist module hook installs in this build**, and
		// the whole subsystem - the 31 opcodes, the 0x2880-byte back end and
		// the integrity scan - is dead code in the shipped fork. The replica
		// reproduces the comparison rather than quietly repairing it.
		struct module_hook_entry
		{
			std::string_view name;       // e.g. "drawassist.3120"
			std::string_view module;     // e.g. "spu/spurs_drawassist.spu.task"
			std::string_view image_hash; // e.g. "SPU-9aa78281..." (empty = any)

			u32 site = 0;            // image offset of the hook's entry point
			u32 expected = 0;        // the instruction that must be there
			u32 target = 0;          // the branch destination the fork writes
			u32 branch_selector = 1; // which branch form `expected` uses

			module_hook_fn fn = nullptr;
			u32 min_verbosity = 0x101;
		};

		const std::vector<module_hook_entry>& get_module_hook_table();

		// Checks one module-hook record against a deployed image: the word at
		// `site` must be readable and must equal `expected`. Returns false
		// and logs when either fails, which is how the fork declines to touch
		// an image it does not recognise.
		bool module_hook_site_matches(const module_hook_entry& entry, std::string_view image_hash,
			const std::function<u8*(u32, u32)>& translate);

		// One entry of the fork's SPU image-patch table, recovered from
		// .rdata at 0x144bcd3b0. The table holds exactly one record, for
		// "mixer.single_bus", and the record is 0x28 (40) bytes:
		//
		//   +0x00  const char* name         "mixer.single_bus"
		//   +0x08  const char* image_hash   "SPU-ae8a75...16d9966f9"
		//   +0x10  u32         offset       0x0000fc04
		//   +0x14  u32         match        0x4c00439f
		//   +0x18  u32         replacement  0x4080001f
		//   +0x1c  u32         reserved     0
		//   +0x20  gate_fn     fn           0x143ced610
		//
		// The 40-byte stride is not a guess: the consumer computes it as
		// `shl rax, 3 / lea r14, [rax + rax*4]` on the element count, i.e.
		// count * 8 * 5 = count * 40. An earlier revision of this file said
		// 0x18 bytes, which was wrong - it read the record's own bytes
		// correctly but stopped counting at the first padding word.
		//
		// Unlike the module hooks, this record has no function pointer to a
		// worker: `fn` is a two-instruction predicate that reads one config
		// byte and returns it as a bool -
		//
		//   0x143ced610  movzx eax, byte ptr [rip + 0x26cd6bd]  ; 0x1463bacd4
		//   0x143ced617  test  al, al
		//   0x143ced619  setne al
		//   0x143ced61c  ret
		//
		// i.e. the patch is gated on a single setting, which is the Audio
		// Mixer Fast Path toggle. So the record says *whether* to patch, and
		// the three u32s say *what* to patch:
		//
		//   offset       byte offset of one big-endian 32-bit instruction
		//                inside the deployed image (local store offsets)
		//   match        the instruction that must be there for the patch to
		//                apply - it is a guard, so a game update that
		//                changes the surrounding code makes the patch a
		//                no-op instead of a corruption
		//   replacement  the instruction to write in its place
		//
		// The consumer at 0x1434ae9f1 reads the word through `translate` and
		// byte-swaps it before comparing against `match`, then byte-swaps
		// `replacement` back on the way in (the swap pair is 0x1434ae9f5 and
		// 0x1434ae967), because the local store holds big-endian code. It
		// also compares the same swapped word against `replacement`
		// un-swapped (0x1434aea07), which is true exactly when the patch has
		// already been applied - so a second load is idempotent.
		struct image_patch_entry
		{
			std::string_view name;
			std::string_view image_hash;

			// Big-endian word offset and the guard/patch pair. See above.
			u32 offset = 0;
			u32 match = 0;
			u32 replacement = 0;

			// Unused padding word in the fork's record, kept so the table
			// can be transcribed verbatim.
			u32 reserved = 0;

			// Returns whether this patch is currently enabled.
			bool (*gate)() = nullptr;
		};

		// What apply_image_patch() did with an entry.
		enum class image_patch_result
		{
			not_matched, // the word is neither match nor replacement
			out_of_range, // translate() refused the offset/size pair
			already,      // the word already reads as replacement
			applied,      // match was replaced
		};

		// Applies one image patch to a deployed image. `translate` is the same
		// bounds-checked accessor the stock patch engine is given and that
		// sys_spu.cpp builds; it returns nullptr when the range is not
		// backed by the image.
		image_patch_result apply_image_patch(const image_patch_entry& entry, const std::function<u8*(u32, u32)>& translate);

		const std::vector<image_patch_entry>& get_image_patches();

		// Called when an embedded SPU image is decrypted and deployed to the
		// SPU local store.
		//
		// The fork's signature is
		//
		//   on_embedded_spu_image(string_view hash, string_view module,
		//                         const std::function<u8*(u32,u32)>& translate,
		//                         bool forced)
		//
		// where `translate` maps an address/size pair into the deployed image
		// and returns nullptr when it is out of range - the same shape the
		// stock patch engine's apply() takes, and the same `mem_translate`
		// lambda sys_spu.cpp builds. That parameter replaces the raw
		// image/size pair this replica originally used, and is strictly better:
		// it puts the bounds check in one place instead of two.
		usz on_embedded_spu_image(std::string_view image_hash, std::string_view module,
			const std::function<u8*(u32, u32)>& translate, bool forced);

		// The full hook table, in the order hooks are considered.
		const std::vector<hook_entry>& get_hook_table();

		// Executable identity gate: the "PPU-<sha1>" hash of the running
		// main ELF, or empty when nothing has been loaded yet.
		std::string_view get_executable_hash();

		// Installs every hook in the table whose level gate passes and whose
		// call sites fall inside the loaded image. Returns the number of call
		// sites actually patched.
		//
		// The fork's signature is
		//
		//   install(std::string_view, u32, u32, bool)
		//
		// - a name (the module or image it is installing for), then base,
		// size and a "forced" flag that bypasses the level gate.
		usz install(std::string_view name, u32 module_base, u32 module_size, bool forced);

		// The guest addresses of every hook *target* currently redirected.
		//
		// Despite the name this is not the call-site set - it is the list of
		// hooked guest function entry points, which is what the fork's name
		// says it is. Recovered from the body at 0x14338a400: it walks the
		// record table, skips records whose +0x24 byte is not 1, and collects
		// each surviving record's +0x20 target into a returned vector.
		std::vector<u32> hooked_function_starts();

		// "SPU-<sha1>" identities whose module hooks are currently installed.
		const std::set<std::string>& hooked_spu_images();

		// Called by the PPU dispatcher when execution reaches a hooked entry.
		//
		// The fork's signature is dispatch(ppu_thread&, u32) and its only
		// callers are the generated HLE entry lambdas in ppu_module_manager -
		// not the instruction loop. See the note in MGO_FORK.md.
		bool dispatch(ppu_thread& cpu, u32 cia);

		void on_emulation_stop();
		void reset();

		// Called from the PPU module loader once a module's segments are mapped
		// and its functions are registered. Installs hooks whose executable-hash
		// gate passes.
		//
		// `base`/`size` describe the module's first segment, which is what the
		// text scan walks. Called for the main ELF, PRX modules and overlays
		// alike; the hash gate decides whether anything is done.
		//
		// This is a replica-local convenience and has no counterpart in the
		// fork, which calls install() directly from its own module-load path.
		void on_module_loaded(u32 base, u32 size, bool forced);
	}

	// Framework-wide teardown, called on game exit.
	void reset();

	// Called when an SPU thread stops. The fork's is
	// on_stop(spu_thread&, u32) and it exists so the parallel modelsetup pool
	// can join work belonging to a thread that has finished.
	void on_stop(spu_thread& spu, u32 cause);

	// Last time a lifter declined to run, as a short reason string.
	//
	// The fork keeps a `t_last_decline` for this. It exists because a lift
	// that declines is silent by design, and a user raising Task Acceleration
	// needs to be able to ask why nothing happened. Replica-local: the fork's
	// is a thread-local, this is not, because nothing here lifts yet.
	std::string_view last_decline();

	// Records why a hook declined, with the source location that did it.
	//
	// This is the fork's mechanism, recovered from pool_start at
	// 0x143a19e54-0x143a19e73: it stores a __FILE__ pointer at thread+0x1e8,
	// a line number at thread+0x1f0, and a message at thread+0x1f8. Every
	// "I will not accelerate this" path in the fork ends by filling those
	// three in, which is how a decline becomes reportable rather than silent.
	//
	// Replica-local in one respect: the fork stores the triple on the thread,
	// this stores it in one place, because no handler here is threaded yet.
	void note_decline(std::string_view why, std::string_view file, u32 line);
}