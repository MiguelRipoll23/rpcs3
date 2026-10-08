#include "stdafx.h"
#include "mgo_motion_play.h"

#include "util/logs.hpp"

#include <cstring>

// The fork logs motion playback on the ppu.motion_play channel; the replica
// reuses that name so a run's output is comparable.
LOG_CHANNEL(ppu_motion_play, "ppu.motion_play");

namespace
{
	// The failure strings, quoted verbatim from the two bodies.
	constexpr std::string_view get_misaligned = "dma get: address or size not 16-byte aligned";
	constexpr std::string_view get_range = "dma get: range";
	constexpr std::string_view put_misaligned = "dma put: address or size not 16-byte aligned";
	constexpr std::string_view put_range = "dma put: range";

	// Both DMA helpers mask the guest offset to 18 bits, which is what caps
	// the task's window at 256 KiB.
	constexpr u32 window_mask = 0x3ffff;
}

namespace mgo_motion_play
{
	staging& staging_for_thread()
	{
		// `task_commit` reaches the ring through `thread+0x5f8` and tests
		// `thread+0x120` before allocating it, so it is per-thread state with
		// a lazily created buffer. One instance per thread is the faithful
		// shape.
		static thread_local staging s{};
		return s;
	}

	bool get(ctx& c, u32 addr, const u32 size, const u32 ring_off, const u32 slot)
	{
		// 1. 16-byte alignment on all three of address, size and ring offset.
		//    The guest's DMA engine faults on an unaligned transfer, so a lift
		//    that performed one anyway would not reproduce the guest - it
		//    would crash differently.
		if (((addr | size | ring_off) & 0xf) != 0)
		{
			c.fail(get_misaligned.data());
			return false;
		}

		// 2. The slot index is capped at 31, the address is masked to 18 bits,
		//    and the two must together stay inside the window.
		if (slot > 0x1f)
		{
			c.fail(get_range.data());
			return false;
		}

		const u32 guest = addr & window_mask;

		if (ring_off + guest >= 0x40001)
		{
			c.fail(get_range.data());
			return false;
		}

		// 3. The 32-bit sum of the ring offset and the size must not wrap past
		//    2^32. Reproduced as written: the fork compares the 64-bit sum
		//    against 2^32 with a strict `>`, so a sum landing exactly on
		//    2^32 is accepted.
		if (static_cast<u64>(ring_off) + size > 0x1'0000'0000ull)
		{
			c.fail(get_range.data());
			return false;
		}

		// 4. Every 4 KB page the transfer spans must be backed. The fork walks
		//    its own page map for this - the same 0x100-granule byte walk with
		//    the same 0x81/0x40/0x20 bit meanings that line_check performs.
		//    That map is its allocation tracker and has no counterpart here, so
		//    the question is put to the emulator instead.
		if (!c.mem || !c.mem->guest_valid(guest, size, false))
		{
			c.fail(get_range.data());
			return false;
		}

		if (ring_off + size > staging::ring_bytes)
		{
			c.fail(get_range.data());
			return false;
		}

		const u8* src = c.mem->guest_ptr(guest, size);

		if (!src)
		{
			c.fail(get_range.data());
			return false;
		}

		std::memcpy(c.buf.ring.data() + ring_off, src, size);
		return true;
	}

	bool put(ctx& c, const u32 addr, const u32 size, const u32 ring_off)
	{
		// A zero-length write-back is a successful no-op, and the fork
		// returns true for it before looking at anything else.
		if (size == 0)
		{
			return true;
		}

		if (((addr | size | ring_off) & 0xf) != 0)
		{
			c.fail(put_misaligned.data());
			return false;
		}

		const u32 guest = addr & window_mask;

		if (ring_off + guest > staging::ring_bytes)
		{
			c.fail(put_range.data());
			return false;
		}

		if (static_cast<u64>(size) + ring_off >= 0x1'0000'0001ull)
		{
			c.fail(put_range.data());
			return false;
		}

		if (ring_off + size > staging::ring_bytes)
		{
			c.fail(put_range.data());
			return false;
		}

		// `put` does not copy anything. The bytes are already in the staging
		// ring - the passes wrote them there - and this only records where they
		// have to land. That is what makes `task_commit` exist at all: it is
		// the single point where the queue becomes guest memory, so a task
		// that is abandoned half way through never writes anything back.
		if (!c.mem || !c.mem->guest_valid(guest, size, true))
		{
			c.fail(put_range.data());
			return false;
		}

		c.buf.queue.push_back({ guest, size, ring_off });

		// The fork keeps two cursors in the header; a queue that overruns the
		// ring is refused rather than wrapped, because wrapping would need the
		// copy in task_commit to be split and the recovered body does not
		// split it.
		c.buf.head += size;

		if (c.buf.head > staging::ring_bytes)
		{
			c.fail(put_range.data());
			c.buf.queue.pop_back();
			c.buf.head -= size;
			return false;
		}

		return true;
	}

	template <typename Mem>
	void task_commit(Mem& mem)
	{
		// Recovered body: for each 12-byte record, memcpy from `ring + offset`
		// to `guest + addr`. It allocates the staging buffer on first use and
		// leaves the queue alone afterwards, so this is idempotent.
		staging& buf = staging_for_thread();

		for (const put_rec& rec : buf.queue)
		{
			if (u8* dst = mem.guest_ptr(rec.addr, rec.size))
			{
				std::memcpy(dst, buf.ring.data() + rec.offset, rec.size);
			}
		}
	}

	scratch_t& scratch()
	{
		// The fork declares this as a function-local static with a guard
		// variable, i.e. one instance for the process, initialised on first
		// use. Same shape here.
		static scratch_t s{};
		return s;
	}

	template <typename Mem>
	bool task_run<Mem>::run(const u32 bone)
	{
		// The recovered call order. Each pass is a member of this class in the
		// fork too, and the order below is the one their sizes and names
		// imply: read the tracks, place the tree, accumulate each owner's
		// contribution under its mask, mirror, crossfade, blend, release.
		//
		// The first pass to fail ends the run, exactly as the fork's DMA
		// failures do - and a run that fails must not write anything back, so
		// task_commit is only reached on success.
		fetch_points(bone);

		if (m_ctx.failed)
		{
			return false;
		}

		root(bone);

		if (m_ctx.failed)
		{
			return false;
		}

		mask128 all{};
		all.hi = ~0ull;

		owner_pass(bone, all);

		if (m_ctx.failed)
		{
			return false;
		}

		mirror(bone);
		crossfade(bone);
		blend_pass(bone, 1, 0, false);
		release_motion(bone);

		if (m_ctx.failed)
		{
			ppu_motion_play.trace("motion_play: bone %u declined at '%s'", bone, m_ctx.message ? m_ctx.message : "?");
			return false;
		}

		return true;
	}

	// Explicit instantiations for the type the fork uses.
	template class task_run<spu_task_hle::ppu::direct_mem>;
	template void task_commit<spu_task_hle::ppu::direct_mem>(spu_task_hle::ppu::direct_mem&);

	void reset()
	{
		scratch_t& s = scratch();
		s.bytes = 0;

		// The fork's own reset clears the queue and the cursors; the ring
		// bytes themselves are not scrubbed, and neither are they here.
		staging& buf = staging_for_thread();
		buf.queue.clear();
		buf.head = 0;
		buf.tail = 0;
	}
}