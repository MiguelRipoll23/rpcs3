#pragma once

// Metal Gear Online geometry-collision / culling hooks.
//
// These correspond to the SaveMGO fork's mgo_geo_coll subsystem, whose own log
// channels are ppu.geo_line, ppu.geo_line_auto, ppu.geo_line_region,
// ppu.geo_pool_start and ppu.geo_pool_start2.
//
// The guest addresses these hooks attach to are properties of the NPMG00020
// executable and are matched through spu_task_hle::ppu's executable-hash gate.
// That hash is known: ppu::get_executable_hash() in the fork returns a 44-byte
// string_view of "PPU-0c7acb83280ab9426400e6a0ae9e1da9482fb5a1", the same
// identity the built-in patch engine uses. The addresses themselves are
// registered at runtime into a 64-byte-per-entry table, so no static table can
// be read out of the binary; until an address is recovered for a hook it is
// simply absent and the guest runs its original code.

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

// The fork splits this subsystem across two namespaces and so does the
// replica. COFF, demangled:
//
//   mgo_geo_coll::why                      the decline-reason enum
//   mgo_geo_coll::range                    a validated guest range
//   mgo_geo_coll::ls_image                 the reproduced local-store image
//   mgo_geo_coll::g_counters               the per-reason counters
//   mgo_geo_coll::detail::snapshot_current / run_handler / ensure_session
//   mgo_geo_coll::detail::bad_point / get_thunk / add_result / write_list
//   mgo_geo_coll::detail::vworker / snap_rec / pending / vw
//   mgo_geo_coll_hooks::line_check         the hook body
//   mgo_geo_coll_hooks::pool_start         the hook body
//
// i.e. everything that is *about the collision work* lives in mgo_geo_coll and
// only the two PPU hook entry points live in mgo_geo_coll_hooks. The earlier
// draft of this file put all of it in mgo_geo_coll_hooks, which is why
// `geo_decline_reason` did not match the binary's `mgo_geo_coll::why`.
namespace mgo_geo_coll
{
	// Why line_check declined, from the fork's 8-entry jump table at
	// 0x144b378c4, indexed (reason - 1). Any other value logs as "declined",
	// which is the table's default arm.
	//
	// The binary passes this by reference as `mgo_geo_coll::why&` to
	// detail::ensure_session and detail::run_handler, so it is a real out
	// parameter of the work functions rather than something line_check invents.
	enum class why : u8
	{
		native_not_built = 1,
		unexpected_globals = 2,
		ppu_fallback = 3,
		unsupported_input = 4,
		worker_init_failed = 5,
		session_tables_changed = 6,
		worker_run_failed = 7,
		unexpected_output = 8,
	};

	// The fork's own wording, verbatim, for each reason above.
	std::string_view why_text(why reason);

	// A validated guest range. `mgo_geo_coll::range` is the type the binary
	// stores in a std::vector (it shows up in the vector instantiations), which
	// is how the two 12-byte input records reach the worker.
	struct range
	{
		u32 addr = 0;
		u32 size = 0;
	};

	// The reproduced local-store image, i.e. the 0x1c8-byte tag window the
	// hook reads out of the guest at (r5 - 0x7db0).
	struct ls_image
	{
		bool readable = false;   // the whole 0x1c8-byte tag window is guest-readable
		u32 at_0x000 = 0;        // 0x94981a01
		u32 at_0x180 = 0;        // 0xe0c21a01
		u32 at_0x198 = 0;        // 0x44c81a01
		u32 at_0x1c4 = 0;        // 0x94ca1a01

		bool matches() const;
	};

	// The per-reason counters, 8 x u64. The binary holds these in one object
	// named g_counters; the replica keeps them on the thread at the offset
	// recovered from the handlers (see geo_thread_state::reason_counters).
	struct g_counters
	{
		u64 by_reason[8] = {};
	};

	namespace detail
	{
		// The five recovered worker entry points. All are templates on
		// spu_task_hle::ppu::direct_mem in the binary:
		//
		//   bool snapshot_current<direct_mem>(vworker&, direct_mem&)
		//   bool run_handler<direct_mem>(vworker&, direct_mem&, char const*,
		//                             u32, u32, mgo_geo_coll::why&)
		//   bool ensure_session<direct_mem>(vworker&, direct_mem&, u32, u32,
		//                                u32, mgo_geo_coll::why&)
		//   bool bad_point<direct_mem>(direct_mem&, u32, float)
		//   bool get_thunk<direct_mem>(void*, u32, u8*, u32)
		//
		// Each hands work to the native collision kernel, which is shipped as
		// compiled code and is not recoverable from a symbol table.
		//
		// Only `vworker` is declared here, because it is the one type these
		// signatures need in order to be written down at all - the binary has
		// an explicit default constructor for it
		// (`mgo_geo_coll::detail::vworker::vworker()`, COFF 0x143ac4f90, which
		// is the same constructor this header's geo_pool documents below).
		// The five entry points themselves are deliberately
		// *not* declared: line_check reproduces the whole front end and then
		// declines with the fork's own `native_not_built` reason, so a
		// declaration with no definition would only invite a call that cannot
		// work. See item 2 in MGO_FORK.md.
		//
		// Also in this namespace, and likewise unreproduced:
		//   write_list::{add, add16, add32, add64}  and write_list::item
		//   add_result(write_list&, u32, char const*, u32)
		//   snap_rec                                  (a vector element)
		//   pending() and vw()                       (function-local statics)
		struct vworker;
	}

	// Guest addresses line_check reads out of the executable, all recovered
	// from its immediate operands. They are properties of the NPMG00020
	// image, not of the emulator, which is why they are constants here.
	namespace guest_globals
	{
		// Points at a 0x40d40-byte region holding a ring of pending work:
		// +0x40d2c is the tail, +0x40d34 the head, +0x40d3c a liveness word.
		constexpr u32 ring_ptr = 0x11a4a94;
		constexpr u32 ring_bytes = 0x40d40;
		constexpr u32 ring_tail = 0x40d2c;
		constexpr u32 ring_head = 0x40d34;
		constexpr u32 ring_live = 0x40d3c;

		// The two session tables. The first is 0x30 bytes; the second is
		// 0x14 bytes and its +0x10 word points at a third, 0x50-byte table.
		constexpr u32 session_a = 0x11a42e8;
		constexpr u32 session_a_bytes = 0x30;
		constexpr u32 session_b = 0x11a4844;
		constexpr u32 session_b_bytes = 0x14;
		constexpr u32 session_c_offset = 0x10;
		constexpr u32 session_c_bytes = 0x50;

		// Points at a word that must be zero for this build; non-zero means
		// the globals belong to a different executable ("other build?").
		constexpr u32 build_word = 0x11a1894;

		// Read as a float and used as the memoisation key for the two
		// 12-byte records in gpr[5] and gpr[6].
		constexpr u32 query_f32 = 0x11a1898;

		// Two 12-byte input records: three u32 offsets each, validated as a
		// 0xc-byte guest range and for float sanity.
		constexpr u32 record_bytes = 0x0c;
	}

	// The pool mgo_geo_coll_hooks::pool_start lazily constructs.
	//
	// Recovered from the fork's constructor at 0x143ac4f90, which zeroes the
	// object in 32-byte vector stores and then sets one byte at +0x224. The
	// size is the 0x300 the caller allocates at 0x143a19e82. The internal
	// layout past that is not identified, but three offsets are read by the
	// recovered handlers:
	//
	//   +0x012  u16  armed with 0x101 by every pool_start call
	//   +0x229  u8   "col_flag"; when gpr[3] has bit 0x1000 set this byte
	//                decides whether the call is supported at all
	//   +0x224  u8   set by the constructor
	struct geo_pool
	{
		u8 storage[0x300] = {};
	};

	// Where the fork keeps the above on the thread it runs on. All four are
	// offsets from `gs:[0x58]`, i.e. the current spu_thread, read out of the
	// recovered handlers rather than from any header.
	struct geo_thread_state
	{
		static constexpr u32 pool_started = 0x0c8; // byte; gates the lazy alloc
		static constexpr u32 pool = 0x388;         // geo_pool*
		static constexpr u32 session = 0x390;      // session tables object*
		static constexpr u32 worker_enabled = 0x0d0; // byte; when clear, fall back
		static constexpr u32 reason_counters = 0x270; // 8 x u64, one per reason
		static constexpr u32 last_reason = 0x2d8; // byte; the reported reason
	};

	// Reads the tag window at (r5 - 0x7db0) out of the guest.
	ls_image probe_tags(spu_task_hle::ppu::direct_mem& mem, u32 r5);
}

namespace mgo_geo_coll_hooks
{
	using mgo_geo_coll::geo_pool;
	using mgo_geo_coll::geo_thread_state;
	using mgo_geo_coll::ls_image;
	using mgo_geo_coll::range;
	using mgo_geo_coll::why;
	using mgo_geo_coll::why_text;
	namespace guest_globals = mgo_geo_coll::guest_globals;

	using mgo_geo_coll::g_counters;
	using mgo_geo_coll::probe_tags;
	// The first gate in mgo_geo_coll_hooks::line_check, recovered from
	// instructions 0x143a18d16-0x143a18d37 of the fork:
	//
	//   lea   eax, [r5 - 0x8000]
	//   cmp   eax, 0xffff0000      / ja  reject
	//   shr   eax, 0xc
	//   lea   ecx, [r5 + 0x7fff]
	//   shr   ecx, 0xc
	//   cmp   eax, ecx             / jbe walk
	//
	// The first test is the real gate: (u32)(r5 - 0x8000) > 0xffff0000 means
	// r5 is below 0x8000 and the pointer is rejected. The second comparison
	// does *not* reject - first <= last is always true, so it always takes
	// the branch into the page walk at 0x143a18e99, which is how the fork
	// verifies that every 4 KB page of the 0x8000-byte window around r5 is
	// present in its reproduced-local-store byte map (skip bits 0x40 for a
	// whole 0x100 and 0x20 for the next 0x10, rejecting when the byte is not
	// 0x81). That byte map is the fork's own allocation tracker and has no
	// counterpart here, so only the range half is reproduced.
	bool passes_page_guard(u32 r5);

	// Guest addresses line_check reads out of the executable, all recovered
	// from its immediate operands. They are properties of the NPMG00020
	// image, not of the emulator, which is why they are constants here.
	// line_check's hook body.
	//
	// The recovered function is a front end for a *native* collision kernel:
	// it validates the call, then hands the work to a x86-64 reimplementation
	// of the guest's own routine and checks the answer. The replica reproduces
	// the whole front end - pool, page guard, tags, guest globals, record
	// validation - and then declines with `native_not_built`, which is the
	// fork's own wording for "this build has no native kernel". The guest
	// therefore always runs its original code, unchanged.
	void line_check(ppu_thread& cpu, spu_task_hle::ppu::direct_mem& mem,
	                const spu_task_hle::ppu::call_regs& regs,
	                spu_task_hle::ppu::call_result& result);

	// pool_start's hook body - one of the two fully recovered handlers.
	//
	// Unlike line_check this is a *complete* replacement, and it is small
	// enough to have been recovered exactly. Its whole behaviour:
	//
	//   if (thread.pool_started)                 // byte at +0xc8
	//   {
	//       *(u16*)(thread.pool + 0x12) = 0x101;
	//       decline("pool start (notification only)");
	//       return 0;
	//   }
	//   thread.pool = new geo_pool();            // operator new(0x300) + ctor
	//   thread.pool_started = 1;
	//   goto arm;
	//
	// So the first call constructs the pool; every call arms a 16-bit flag at
	// pool+0x12 with the value 0x101 and reports that it declined, then
	// returns 0 to the guest. "Notification only" is the fork's own string,
	// read verbatim from the reference image at 0x144b2afd9 - this call site
	// exists to tell the pool something happened, not to do the work itself.
	//
	// The guest function is therefore genuinely replaced, which is why this
	// entry is the first one marked `complete` in the hook table.
	void pool_start(ppu_thread& cpu, spu_task_hle::ppu::direct_mem& mem,
	                const spu_task_hle::ppu::call_regs& regs,
	                spu_task_hle::ppu::call_result& result);

	// Clears the per-run dedup set and the pool.
	void reset();
}