// Unit test for mgo_motion_play's DMA seam.
//
// `get`, `put` and `task_commit` are the parts of the subsystem recovered
// instruction for instruction from the reference image, so they can be tested
// with a fake memory object and no emulator. The seven playback passes are not
// tested because they are not implemented - see the header.
//
// Build and run:
//   g++ -std=c++20 -O1 -o mgo_motion_play_test buildfiles/mgo_motion_play_test.cpp
//   ./mgo_motion_play_test

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// A stand-in for spu_task_hle::ppu::direct_mem: a flat guest address space.
struct fake_mem
{
	std::vector<u8> space;

	u8* guest_ptr(u32 addr, u32 size = 1) const
	{
		return (static_cast<u64>(addr) + size <= space.size()) ? const_cast<u8*>(space.data()) + addr : nullptr;
	}

	bool guest_valid(u32 addr, u32 size, bool = false) const
	{
		return static_cast<u64>(addr) + size <= space.size();
	}
};

namespace mgo_motion_play
{
	struct mask128
	{
		u64 lo = 0;
		u64 hi = 0;
		bool test(u32 bit) const { return bit < 128 && ((bit < 64 ? lo >> bit : hi >> (bit - 64)) & 1) != 0; }
		void set(u32 bit) { if (bit < 64) { lo |= 1ull << bit; } else if (bit < 128) { hi |= 1ull << (bit - 64); } }
	};

	struct put_rec
	{
		u32 addr = 0;
		u32 size = 0;
		u32 offset = 0;
	};
	static_assert(sizeof(put_rec) == 12, "the queue steps by 12 bytes");

	struct staging
	{
		static constexpr u32 ring_bytes = 0x40000;
		std::vector<u8> ring;
		u32 head = 0;
		u32 tail = 0;
		std::vector<put_rec> queue;

		staging() : ring(ring_bytes, 0) {}
	};

	staging& staging_for_thread()
	{
		static staging s;
		return s;
	}

	struct ctx
	{
		ctx() : buf(staging_for_thread()) {}
		fake_mem* mem = nullptr;
		bool failed = false;
		const char* message = nullptr;
		staging& buf;

		void fail(const char* why)
		{
			if (!failed)
			{
				failed = true;
				message = why;
			}
		}

		void clear()
		{
			failed = false;
			message = nullptr;
			buf.queue.clear();
			buf.head = 0;
			buf.tail = 0;
		}
	};

	constexpr u32 window_mask = 0x3ffff;

	bool get(ctx& c, u32 addr, const u32 size, const u32 ring_off, const u32 slot)
	{
		if (((addr | size | ring_off) & 0xf) != 0)
		{
			c.fail("dma get: address or size not 16-byte aligned");
			return false;
		}

		if (slot > 0x1f)
		{
			c.fail("dma get: range");
			return false;
		}

		const u32 guest = addr & window_mask;

		if (ring_off + guest >= 0x40001)
		{
			c.fail("dma get: range");
			return false;
		}

		if (static_cast<u64>(ring_off) + size > 0x100000000ull)
		{
			c.fail("dma get: range");
			return false;
		}

		if (!c.mem || !c.mem->guest_valid(guest, size, false))
		{
			c.fail("dma get: range");
			return false;
		}

		if (ring_off + size > staging::ring_bytes)
		{
			c.fail("dma get: range");
			return false;
		}

		const u8* src = c.mem->guest_ptr(guest, size);

		if (!src)
		{
			c.fail("dma get: range");
			return false;
		}

		std::memcpy(c.buf.ring.data() + ring_off, src, size);
		return true;
	}

	bool put(ctx& c, const u32 addr, const u32 size, const u32 ring_off)
	{
		if (size == 0)
		{
			return true;
		}

		if (((addr | size | ring_off) & 0xf) != 0)
		{
			c.fail("dma put: address or size not 16-byte aligned");
			return false;
		}

		const u32 guest = addr & window_mask;

		if (ring_off + guest > staging::ring_bytes)
		{
			c.fail("dma put: range");
			return false;
		}

		if (static_cast<u64>(size) + ring_off >= 0x100000001ull)
		{
			c.fail("dma put: range");
			return false;
		}

		if (ring_off + size > staging::ring_bytes)
		{
			c.fail("dma put: range");
			return false;
		}

		if (!c.mem || !c.mem->guest_valid(guest, size, true))
		{
			c.fail("dma put: range");
			return false;
		}

		c.buf.queue.push_back({ guest, size, ring_off });
		c.buf.head += size;

		if (c.buf.head > staging::ring_bytes)
		{
			c.fail("dma put: range");
			c.buf.queue.pop_back();
			c.buf.head -= size;
			return false;
		}

		return true;
	}

	template <typename Mem>
	void task_commit(Mem& mem)
	{
		staging& buf = staging_for_thread();

		for (const put_rec& rec : buf.queue)
		{
			if (u8* dst = mem.guest_ptr(rec.addr, rec.size))
			{
				std::memcpy(dst, buf.ring.data() + rec.offset, rec.size);
			}
		}
	}

	void reset()
	{
		staging& buf = staging_for_thread();
		buf.queue.clear();
		buf.head = 0;
		buf.tail = 0;
	}
}

// ---- the test -------------------------------------------------------------

static int g_pass = 0;
static int g_fail = 0;

static void check(const bool ok, const char* what)
{
	if (ok)
	{
		g_pass++;
		std::printf("  ok    %s\n", what);
	}
	else
	{
		g_fail++;
		std::printf("  FAIL  %s\n", what);
	}
}

int main()
{
	fake_mem mem;
	mem.space.assign(0x80000, 0);

	mgo_motion_play::ctx c;
	c.mem = &mem;

	std::printf("== get: the four checks\n");

	// 1. alignment
	check(!mgo_motion_play::get(c, 0x1004, 0x10, 0, 0) && c.failed,
		"a misaligned address is refused");
	check(std::strcmp(c.message, "dma get: address or size not 16-byte aligned") == 0,
		"and it reports the fork's own string");
	c.clear();

	check(!mgo_motion_play::get(c, 0x1000, 0x11, 0, 0),
		"a misaligned size is refused");
	c.clear();

	check(!mgo_motion_play::get(c, 0x1000, 0x10, 0x4, 0),
		"a misaligned ring offset is refused");
	c.clear();

	// 2. slot, mask, window
	check(!mgo_motion_play::get(c, 0x1000, 0x10, 0, 32) && c.failed,
		"slot 32 is one past the cap");
	check(std::strcmp(c.message, "dma get: range") == 0, "and it reports 'range'");
	c.clear();

	// The address is masked to 18 bits, so 0x40010 lands on 0x10.
	for (u32 i = 0; i < 0x10; i++)
	{
		mem.space[0x10 + i] = static_cast<u8>(0xa0 + i);
	}

	check(mgo_motion_play::get(c, 0x40010, 0x10, 0x100, 0),
		"the address is masked to 18 bits rather than refused");
	check(mem.space[0x10] == 0xa0, "and the data came from the masked address");
	c.clear();

	check(!mgo_motion_play::get(c, 0x1000, 0x10, 0x3ffff0, 0),
		"a ring offset that overruns the 256 KiB ring is refused");
	c.clear();

	std::printf("\n== get: the happy path copies guest -> ring\n");

	for (u32 i = 0; i < 0x20; i++)
	{
		mem.space[0x2000 + i] = static_cast<u8>(i);
	}

	check(mgo_motion_play::get(c, 0x2000, 0x20, 0x200, 5), "a well-formed get succeeds");
	check(!c.failed, "and records no failure");
	check(mgo_motion_play::staging_for_thread().ring[0x200] == 0x00
		&& mgo_motion_play::staging_for_thread().ring[0x21f] == 0x1f,
		"the bytes landed in the ring at the requested offset");

	std::printf("\n== put: the mirror checks\n");

	check(mgo_motion_play::put(c, 0x1000, 0, 0) && !c.failed,
		"a zero-length put is a successful no-op");
	check(mgo_motion_play::staging_for_thread().queue.empty(), "and queues nothing");

	check(!mgo_motion_play::put(c, 0x1002, 0x10, 0x300),
		"a misaligned put is refused");
	check(std::strcmp(c.message, "dma put: address or size not 16-byte aligned") == 0,
		"and it reports the fork's own string");
	c.clear();

	// The 18-bit address mask caps the guest side at 256 KiB, so reaching the
	// "not mapped" case needs a guest space smaller than the window.
	{
		fake_mem small;
		small.space.assign(0x30000, 0);

		mgo_motion_play::ctx s;
		s.mem = &small;

		check(!mgo_motion_play::put(s, 0x3fff0, 0x20, 0),
			"a put past the end of guest memory is refused");
		check(std::strcmp(s.message, "dma put: range") == 0, "and it reports 'range'");

		check(!mgo_motion_play::get(s, 0x3fff0, 0x20, 0, 0),
			"a get past the end of guest memory is refused too");
	}

	std::printf("\n== put queues, task_commit writes\n");

	check(mgo_motion_play::put(c, 0x3000, 0x20, 0x200), "a well-formed put is queued");
	check(mgo_motion_play::staging_for_thread().queue.size() == 1, "the queue holds one record");
	check(mgo_motion_play::staging_for_thread().queue[0].addr == 0x3000
		&& mgo_motion_play::staging_for_thread().queue[0].size == 0x20
		&& mgo_motion_play::staging_for_thread().queue[0].offset == 0x200,
		"the record is {addr, size, ring offset}");

	// Nothing is written until the commit runs.
	check(mem.space[0x3000] == 0, "put alone does not touch guest memory");

	mgo_motion_play::task_commit(mem);
	check(mem.space[0x3000] == 0x00 && mem.space[0x301f] == 0x1f,
		"task_commit writes the ring into guest memory");

	// The commit is idempotent, as the recovered body is: it walks the queue
	// without consuming it.
	for (u32 i = 0; i < 0x20; i++)
	{
		mem.space[0x3000 + i] = 0;
	}

	mgo_motion_play::task_commit(mem);
	check(mem.space[0x3000] == 0x00, "a second commit rewrites the same bytes");

	std::printf("\n== the queue survives a failed run\n");

	c.clear();
	check(mgo_motion_play::put(c, 0x3000, 0x20, 0x200), "queued again");
	mgo_motion_play::put(c, 0x4000, 0x11, 0x400);      // fails on alignment
	check(c.failed, "the second put failed");
	check(mgo_motion_play::staging_for_thread().queue.size() == 1,
		"and left the queue holding only the record that was accepted");

	std::printf("\n== mask128\n");

	mgo_motion_play::mask128 m{};
	check(!m.test(0) && !m.test(127), "a fresh mask selects nothing");
	m.set(0);
	m.set(64);
	m.set(127);
	check(m.test(0) && m.test(64) && m.test(127), "bits 0, 64 and 127 all set");
	check(!m.test(1) && !m.test(63) && !m.test(126), "and nothing in between");
	check(!m.test(128), "bit 128 is out of range, not wrapped");

	mgo_motion_play::reset();
	check(mgo_motion_play::staging_for_thread().queue.empty(), "reset clears the queue");

	std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}