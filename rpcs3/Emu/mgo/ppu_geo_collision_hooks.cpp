#include "stdafx.h"
#include "ppu_geo_collision_hooks.h"

#include "util/logs.hpp"

#include <cstring>
#include <memory>
#include <mutex>
#include <set>

// The fork's own channel names, recovered from .rdata. They are reproduced here
// so a probe run writes to the same places the fork's did, which is what makes
// the output comparable.
LOG_CHANNEL(ppu_geo_line, "ppu.geo_line");
LOG_CHANNEL(ppu_geo_line_auto, "ppu.geo_line_auto");
LOG_CHANNEL(ppu_geo_line_region, "ppu.geo_line_region");
LOG_CHANNEL(ppu_geo_pool_start, "ppu.geo_pool_start");
LOG_CHANNEL(ppu_geo_pool_start2, "ppu.geo_pool_start2");

namespace
{
	using namespace spu_task_hle::ppu;

	// Offsets and magics read straight off the fork's instructions at
	// 0x143a18d3d-0x143a18d9c.
	constexpr u32 struct_offset = 0x7db0;

	// The fork's eight decline strings, in jump-table order (index = reason-1),
	// copied verbatim from the table at 0x144b378c4.
	constexpr std::string_view decline_texts[] =
	{
		"geo collision native not built (x86-64 SSE4.1/FMA3, GCC or Clang)",
		"unexpected globals / TOC (other build?)",
		"PPU fallback path (pool not running or ring full)",
		"unsupported input (col_flag 0x1000, denormal point or radius, aliasing)",
		"virtual worker init failed",
		"session tables changed inside the session",
		"virtual worker run failed (DMA, halt, budget, recursion)",
		"unexpected worker output",
	};

	// Report each distinct guest pointer once; line_check runs per draw call
	// and would otherwise flood the log.
	std::mutex s_mutex;
	std::set<u32> s_reported;

	// pool_start's lazily constructed pool, and whether it exists yet.
	// Recovered as a +0xc8 byte on the thread that stands in for "has the
	// pool been built"; kept here because the replica keeps the pool beside
	// the hook rather than on the ppu_thread.
	std::unique_ptr<mgo_geo_coll::geo_pool> s_pool;
	bool s_pool_started = false;

	u32 read_u32(const direct_mem& mem, u32 addr)
	{
		if (const u8* ptr = mem.guest_ptr(addr, sizeof(u32)))
		{
			u32 value = 0;
			std::memcpy(&value, ptr, sizeof(value));
			return value;
		}

		return 0;
	}

	// Guest data words are big-endian and the fork byte-swaps every one it
	// reads (pointers, floats, the build word). The four structure tags are
	// the exception: they are compared straight out of memory with no swap,
	// so the guest stores those four as little-endian u32.
	u32 read_u32_be(const direct_mem& mem, const u32 addr)
	{
		const u32 value = read_u32(mem, addr);
		return (value >> 24) | ((value >> 8) & 0x0000ff00u) | ((value << 8) & 0x00ff0000u) | (value << 24);
	}

	// True when `value` is a usable float: neither zero, nor a denormal, nor
	// NaN/Inf. This is the fork's own test, repeated for each of the six
	// floats it reads out of the two input records:
	//
	//   test  v, 0x7f800000 / sete a      ; exponent all ones and no mantissa
	//   test  v, 0x007fffff / setne c     ; mantissa non-zero
	//   test  a, c             / jne reject
	bool is_usable_float(const u32 value)
	{
		const bool exponent_all_ones = (value & 0x7f800000u) == 0;
		const bool mantissa_non_zero = (value & 0x007fffffu) != 0;
		return exponent_all_ones && mantissa_non_zero;
	}

	// Reads the pointer a guest global holds and reports whether the region it
	// claims is usable. The fork does this four times, with the size and the
	// range bound recovered from its immediates.
	bool read_global_pointer(const direct_mem& mem, const u32 global_addr, const u32 bytes, u32& out_pointer)
	{
		if (!mem.guest_valid(global_addr, sizeof(u32), false))
		{
			return false;
		}

		out_pointer = read_u32_be(mem, global_addr);

		// The fork compares the pointer against 0x100000000 - bytes (0xfffbf2c0
		// for the ring, -0x30 / -0x14 / -0x50 for the three tables), so a
		// pointer that cannot even hold the region is rejected.
		if (static_cast<u64>(out_pointer) + bytes > 0x1'0000'0000ull)
		{
			return false;
		}

		return mem.guest_valid(out_pointer, bytes, true);
	}
}

namespace mgo_geo_coll
{
	ls_image probe_tags(direct_mem& mem, const u32 r5)
	{
		ls_image out{};

		const u32 base = r5 - struct_offset;

		out.readable = mem.guest_valid(base, 0x1c8);

		if (!out.readable)
		{
			return out;
		}

		out.at_0x000 = read_u32(mem, base + 0x000);
		out.at_0x180 = read_u32(mem, base + 0x180);
		out.at_0x198 = read_u32(mem, base + 0x198);
		out.at_0x1c4 = read_u32(mem, base + 0x1c4);
		return out;
	}

	bool ls_image::matches() const
	{
		return readable
			&& at_0x000 == 0x94981a01
			&& at_0x180 == 0xe0c21a01
			&& at_0x198 == 0x44c81a01
			&& at_0x1c4 == 0x94ca1a01;
	}

	std::string_view why_text(const why reason)
	{
		const u32 index = static_cast<u32>(reason);

		// The fork's table is indexed (reason - 1) and everything else falls
		// through to a single shared string.
		return (index >= 1 && index <= std::size(decline_texts)) ? decline_texts[index - 1] : std::string_view{"declined"};
	}
}

namespace mgo_geo_coll_hooks
{
	bool passes_page_guard(const u32 r5)
	{
		// (u32)(r5 - 0x8000) > 0xffff0000 means r5 is below 0x8000, which is
		// the fork's only rejection here.
		return (r5 - 0x8000u) <= 0xffff0000u;
	}


	namespace
	{
		// One of the two 12-byte input records, as the fork reads it: three
		// big-endian words, each of which must be a usable float, and the
		// whole record must be guest-readable.
		bool validate_record(const direct_mem& mem, const u32 record)
		{
			if (!mem.guest_valid(record, mgo_geo_coll::guest_globals::record_bytes, false))
			{
				return false;
			}

			for (u32 i = 0; i < mgo_geo_coll::guest_globals::record_bytes; i += sizeof(u32))
			{
				if (!is_usable_float(read_u32_be(mem, record + i)))
				{
					return false;
				}
			}

			return true;
		}
	}

	void line_check(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
	{
		// call_regs mirrors the guest fastcall context with gpr[0] == r3, so the
		// fork's [r8+0x10] is guest r5 and [r8+0x28] / [r8+0x30] are gpr[5] and
		// gpr[6]. The word at [r8+0x108] is the call's lr, which the fork also
		// reads - as a double, and requires to round-trip through float.
		const u32 r5 = static_cast<u32>(regs.gpr[2]);
		const u32 r6 = static_cast<u32>(regs.gpr[3]);
		const u32 record_a = static_cast<u32>(regs.gpr[5]);
		const u32 record_b = static_cast<u32>(regs.gpr[6]);

		auto decline = [&result](const why reason)
		{
			// Same mechanism as pool_start: record why, and let the guest run.
			spu_task_hle::note_decline(why_text(reason), __FILE__, __LINE__);
			result.handled = false;
		};

		std::unique_lock lock(s_mutex);

		// The pool is built lazily on the first call, exactly as pool_start
		// does it: operator new(0x300) plus the same constructor.
		if (!s_pool)
		{
			s_pool = std::make_unique<geo_pool>();
			s_pool_started = true;

			ppu_geo_line.trace("line_check: constructed the 0x%x-byte pool", static_cast<u32>(sizeof(geo_pool)));
		}

		// 1. The 0x8000-byte window around the structure pointer must be in
		//    range. The fork additionally walks its reproduced-local-store
		//    page map here, which has no counterpart in the replica.
		if (!passes_page_guard(r5))
		{
			decline(why::unexpected_globals);
			return;
		}

		// 2. The four tags. Each rejects straight to reason 2.
		const ls_image tags = probe_tags(mem, r5);

		if (!tags.matches())
		{
			if (s_reported.insert(r5).second)
			{
				ppu_geo_line.notice("line_check: r5=%08x struct=%08x tags %08x/%08x/%08x/%08x (want 94981a01/e0c21a01/44c81a01/94ca1a01)",
					r5, r5 - struct_offset,
					tags.at_0x000, tags.at_0x180, tags.at_0x198, tags.at_0x1c4);
			}

			decline(why::unexpected_globals);
			return;
		}

		// 3. The globals. All four are read as big-endian words and the
		//    regions they claim must be guest-readable.
		u32 ring = 0, table_a = 0, table_b = 0;

		if (!read_global_pointer(mem, guest_globals::ring_ptr, guest_globals::ring_bytes, ring)
			|| !read_global_pointer(mem, guest_globals::session_a, guest_globals::session_a_bytes, table_a)
			|| !read_global_pointer(mem, guest_globals::session_b, guest_globals::session_b_bytes, table_b))
		{
			decline(why::unexpected_globals);
			return;
		}

		// 4. The build word must be zero. A non-zero value means the globals
		//    belong to a different executable - "other build?".
		if (!mem.guest_valid(guest_globals::build_word, sizeof(u32), false))
		{
			decline(why::unexpected_globals);
			return;
		}

		if (read_u32_be(mem, guest_globals::build_word) != 0)
		{
			decline(why::unexpected_globals);
			return;
		}

		// 5. The two 12-byte records.
		if (!validate_record(mem, record_a) || !validate_record(mem, record_b))
		{
			decline(why::unsupported_input);
			return;
		}

		// 6. col_flag. When the caller sets bit 0x1000 the pool's own flag
		//    byte decides whether the call is supported at all.
		const bool wants_flag = (r6 & 0x1000u) != 0;
		const bool pool_flag = s_pool->storage[0x229] != 0;

		if (wants_flag && !pool_flag)
		{
			decline(why::unsupported_input);
			return;
		}

		// 7. The ring must have work in it, otherwise the fork lets the PPU
		//    run the call itself.
		if (read_u32_be(mem, ring + guest_globals::ring_live) == 0)
		{
			decline(why::ppu_fallback);
			return;
		}

		const u32 tail = read_u32_be(mem, ring + guest_globals::ring_tail);
		const u32 head = read_u32_be(mem, ring + guest_globals::ring_head);

		if (static_cast<s32>(head) <= static_cast<s32>(tail))
		{
			decline(why::ppu_fallback);
			return;
		}

		// 8. The fork would now snapshot the session tables, hand the work to
		//    its virtual worker and check the output. There is no native
		//    kernel in this build, which is precisely the case the fork's
		//    first decline reason exists to describe.
		if (s_reported.insert(r5).second)
		{
			ppu_geo_line_auto.notice("line_check: r5=%08x passed every gate (ring %08x..%08x, tables %08x/%08x/%08x) - no native kernel",
				r5, tail, head, table_a, table_b, table_a);
		}

		decline(why::native_not_built);
	}

	void pool_start(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& result)
	{
		(void)cpu;
		(void)mem;
		(void)regs;

		std::lock_guard lock(s_mutex);

		// First call constructs the pool; later calls skip straight to arming
		// the flag. Recovered control flow jumps to 0x143a19e3b in both cases.
		if (!s_pool)
		{
			s_pool = std::make_unique<geo_pool>();
			s_pool_started = true;

			ppu_geo_pool_start.trace("pool_start: constructed the 0x%x-byte pool", static_cast<u32>(sizeof(geo_pool)));
		}

		// *(u16*)(pool + 0x12) = 0x101 - the only store in the common path.
		// The field is 16-bit, so this is two flags: 0x100 and 0x1.
		auto* base = reinterpret_cast<u16*>(s_pool->storage);
		base[0x12 / sizeof(u16)] = 0x101;

		// The fork then records why it did not handle the call, using a
		// (file, line, message) triple stored on the thread. This is the same
		// mechanism as spu_task_hle::t_last_decline: a lift that declines is
		// silent by design, and the fork needs a way to be asked why.
		spu_task_hle::note_decline("pool start (notification only)", __FILE__, __LINE__);

		// eax = 0 in the fork: this is a full replacement that returns 0.
		result.handled = true;
		result.returned = true;
		result.return_value = 0;
	}

	void reset()
	{
		std::lock_guard lock(s_mutex);
		s_reported.clear();
		s_pool.reset();
		s_pool_started = false;
	}
}