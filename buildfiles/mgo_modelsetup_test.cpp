// Unit test for the mgo_modelsetup front end.
//
// Everything below is host logic over plain data - the status table, the
// FNV-1a-64 image hash, the reproduced-LS granule walk, the open-addressed
// page_set, the access tracker and the SPURS_TaskStart argument gates - so all
// of it is testable without the emulator. The parts that need guest memory
// (read_spurs_args, load_image) are the two functions recovered in full from
// 0x143ac5380 and 0x143ac5520 and are verified byte-for-byte by
// buildfiles/mgo_verify_re.py instead.
//
// Build and run (no RPCS3 headers needed):
//   g++ -std=c++20 -O1 -o mgo_modelsetup_test buildfiles/mgo_modelsetup_test.cpp
//   ./mgo_modelsetup_test

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using s32 = std::int32_t;
using usz = std::size_t;

namespace mgo_modelsetup
{
	// --- transcribed from 0x144b378e4 ------------------------------------
	enum class status : u8
	{
		none = 0,
		built_without_sse = 1,
		not_a_model_setup_image = 2,
		task_image_differs = 3,
		unexpected_spurs_args = 4,
		unmapped_guest_memory = 5,
		taskset_unreadable = 6,
		lifted_code_declined = 7,
		task_did_not_put = 8,
	};

	const char* status_text(status value)
	{
		switch (value)
		{
		case status::none: return "none";
		case status::built_without_sse: return "built without SSE4.1/SSSE3/FMA3";
		case status::not_a_model_setup_image: return "not a model setup image";
		case status::task_image_differs: return "task image differs from the lifted one";
		case status::unexpected_spurs_args: return "unexpected SPURS_TaskStart arguments";
		case status::unmapped_guest_memory: return "unmapped guest memory";
		case status::taskset_unreadable: return "SPURS taskset not readable";
		case status::lifted_code_declined: return "lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)";
		case status::task_did_not_put: return "task did not PUT its record";
		default: return "?";
		}
	}

	constexpr u32 decline_line = 0x69;

	// --- transcribed from 0x144b36e20 ------------------------------------
	struct image_info
	{
		u32 image_base = 0;
		u32 entry = 0;
		u32 hash_bytes = 0;
		u32 word_0c = 0;
		u32 word_10 = 0;
		u32 word_14 = 0;
		u32 word_18 = 0;
		u32 word_1c = 0;
		u32 chunk_count = 0;
		u32 reserved_24 = 0;
		u64 image_hash = 0;
	};

	const std::vector<image_info>& images()
	{
		static const std::vector<image_info> table
		{
			{ 0x0100c280u, 0x00009f18u, 0x0000ac00u, 0x0001c1c0u, 0x0000ab80u, 0x0000ac80u, 0x0000ab40u, 0x0003fd80u, 0x00000100u, 0u, 0x743c495a49e3aaa3ull },
			{ 0x01009480u, 0x00004cf0u, 0x00005880u, 0x00012940u, 0x00005800u, 0x00005900u, 0x00005790u, 0x0003fde0u, 0x00000080u, 0u, 0xf977d8259dcadeaeull },
		};
		return table;
	}

	s32 image_index(u32 image_address)
	{
		for (usz i = 0; i < images().size(); i++)
		{
			if (images()[i].image_base == image_address)
			{
				return static_cast<s32>(i);
			}
		}

		return -1;
	}

	// --- the call-site dispatch -------------------------------------------
	inline constexpr u32 site_chara = 0x0014cea0u;
	inline constexpr u32 site_bg = 0x0014ce28u;
	inline constexpr u32 site_other = 0x0014cdb0u;

	enum class site_kind { none, chara, bg, other };

	site_kind classify_site(u32 call_site)
	{
		switch (call_site)
		{
		case site_chara: return site_kind::chara;
		case site_bg: return site_kind::bg;
		case site_other: return site_kind::other;
		default: return site_kind::none;
		}
	}

	// --- the reproduced-LS byte map ---------------------------------------
	inline constexpr u8 granule_mapped = 0x81;
	inline constexpr u8 granule_skip_page = 0x40;
	inline constexpr u8 granule_skip_16 = 0x20;

	bool walk_granules(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi)
	{
		if (!map_byte)
		{
			return false;
		}

		for (u32 granule = lo; granule <= hi;)
		{
			const u8 byte = map_byte(granule);

			if ((~byte) & 0x81)
			{
				return false;
			}

			if (byte & granule_skip_page)
			{
				granule = (granule & ~0xffu) + 0x100u;
				continue;
			}

			if (byte & granule_skip_16)
			{
				granule = (granule & ~0xfu) + 0x10u;
				continue;
			}

			granule++;
		}

		return true;
	}

	bool window_forward_ok(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi)
	{
		if (lo > 0xfffffffcu)
		{
			return false;
		}

		const u32 first = lo >> 12;
		const u32 last = hi >> 12;

		if (first > last)
		{
			return true;
		}

		return walk_granules(map_byte, first, last);
	}

	bool window_backwards_ok(const std::function<u8(u32 granule)>& map_byte, u32 ptr)
	{
		const u32 start = ptr - 0x8000u;

		if (start > 0xfffffffcu)
		{
			return false;
		}

		const u32 first = start >> 12;
		const u32 last = (start + 0xffff8003u) >> 12;

		if (first > last)
		{
			return true;
		}

		return walk_granules(map_byte, first, last);
	}

	// --- FNV-1a-64 --------------------------------------------------------
	inline constexpr u64 fnv_offset_basis = 0xcbf29ce484222325ull;
	inline constexpr u64 fnv_prime = 0x100000001b3ull;

	u64 fnv1a64(const u8* data, u32 bytes)
	{
		u64 hash = fnv_offset_basis;

		for (u32 i = 0; i < bytes; i++)
		{
			hash = (hash ^ data[i]) * fnv_prime;
		}

		return hash;
	}

	// --- the SPURS_TaskStart gates ----------------------------------------
	inline constexpr u32 spurs_option_word = 0x10000u;
	inline constexpr u32 spurs_arg_max = 0xffffff80u;

	bool spurs_args_ok(u32 gpr3, u32 gpr6)
	{
		if (gpr3 > spurs_arg_max)
		{
			return false;
		}

		return ((gpr6 ^ spurs_option_word) | (gpr3 & 0xfu)) == 0;
	}

	// --- the conflict tracker ---------------------------------------------
	class page_set
	{
	public:
		void insert(u32 page)
		{
			if (m_table.size() < static_cast<usz>(m_count) * 2 + 2)
			{
				grow();
			}

			if (m_table.empty())
			{
				return;
			}

			const u32 mask = static_cast<u32>(m_table.size()) - 1;
			u32 slot = (page * 0x9e3779b1u) >> 12;
			const u32 key = page + 1;

			while (true)
			{
				slot &= mask;

				const u32 found = m_table[slot];

				if (found == key)
				{
					return;
				}

				if (found == 0)
				{
					m_table[slot] = key;
					m_slots.push_back(slot);
					m_count++;
					return;
				}

				slot++;
			}
		}

		void grow()
		{
			usz want = m_table.empty() ? 8 : m_table.size() * 2;

			std::vector<u32> old;
			old.swap(m_table);
			m_table.assign(want, 0);

			m_count = 0;
			m_slots.clear();

			for (u32 slot : old)
			{
				if (slot != 0)
				{
					insert(slot - 1);
				}
			}
		}

		bool contains(u32 page) const
		{
			if (m_table.empty())
			{
				return false;
			}

			const u32 mask = static_cast<u32>(m_table.size()) - 1;
			u32 slot = (page * 0x9e3779b1u) >> 12;

			for (usz probe = 0; probe < m_table.size(); probe++)
			{
				slot &= mask;

				const u32 found = m_table[slot];

				if (found == 0)
				{
					return false;
				}

				if (found == page + 1)
				{
					return true;
				}

				slot++;
			}

			return false;
		}

		u32 size() const { return m_count; }
		u32 capacity() const { return static_cast<u32>(m_table.size()); }

	private:
		std::vector<u32> m_table;
		std::vector<u32> m_slots;
		u32 m_count = 0;
	};

	struct access
	{
		u32 addr = 0;
		u32 size = 0;
	};

	class tracker
	{
	public:
		void watch(u32 addr)
		{
			m_watch_pages.push_back(addr);
			m_watch_stamps.push_back(0);
			m_watch_cap = static_cast<u32>(m_watch_pages.size());
		}

		void on_get(u32 addr, u32 size)
		{
			m_reads.push_back({ addr, size });

			const u32 first = addr >> 12;
			const u32 last = (addr + size - 1) >> 12;

			for (u32 page = first; page <= last; page++)
			{
				m_read_pages.insert(page);
			}

			if (m_watch_count < m_watch_cap && m_watch_pages[m_watch_count] == addr)
			{
				m_watch_stamps[m_watch_count++] = m_watch_clock++;
			}
		}

		void on_put(u32 addr, u32 size)
		{
			m_writes.push_back({ addr, size });

			const u32 first = addr >> 12;
			const u32 last = (addr + size - 1) >> 12;

			for (u32 page = first; page <= last; page++)
			{
				m_written_pages.insert(page);
			}
		}

		const std::vector<access>& reads() const { return m_reads; }
		const std::vector<access>& writes() const { return m_writes; }
		const page_set& read_pages() const { return m_read_pages; }
		const page_set& written_pages() const { return m_written_pages; }

	private:
		page_set m_read_pages;
		page_set m_written_pages;
		std::vector<access> m_reads;
		std::vector<access> m_writes;
		std::vector<u32> m_watch_pages;
		std::vector<u64> m_watch_stamps;
		u32 m_watch_cap = 0;
		u32 m_watch_count = 0;
		u64 m_watch_clock = 0;
	};
}

// ---------------------------------------------------------------------------

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const char* what)
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

// A byte map that reports `present` granules as 0x81 and everything else as 0.
static std::function<u8(u32)> flat_map(u32 present, u32 absent = 0xffffffffu)
{
	return [present, absent](u32 granule) -> u8
	{
		return granule >= present && granule <= absent ? mgo_modelsetup::granule_mapped : u8(0);
	};
}

static void test_status_table()
{
	std::printf("\n== the 9-entry status table (0x144b378e4)\n");

	const char* want[] =
	{
		"none",
		"built without SSE4.1/SSSE3/FMA3",
		"not a model setup image",
		"task image differs from the lifted one",
		"unexpected SPURS_TaskStart arguments",
		"unmapped guest memory",
		"SPURS taskset not readable",
		"lifted code declined (DMA, load/store outside the reproduced LS, budget, halt)",
		"task did not PUT its record",
	};

	for (u32 i = 0; i < 9; i++)
	{
		check(std::strcmp(mgo_modelsetup::status_text(static_cast<mgo_modelsetup::status>(i)), want[i]) == 0, want[i]);
	}

	check(std::strcmp(mgo_modelsetup::status_text(static_cast<mgo_modelsetup::status>(9)), "?") == 0,
		"index 9 falls back to \"?\"");
	check(std::strcmp(mgo_modelsetup::status_text(static_cast<mgo_modelsetup::status>(200)), "?") == 0,
		"a wild index falls back to \"?\"");
	check(mgo_modelsetup::decline_line == 0x69, "declines are reported at line 0x69");
}

static void test_image_table()
{
	std::printf("\n== the image table (0x144b36e20)\n");

	const auto& table = mgo_modelsetup::images();

	check(table.size() == 2, "there are exactly two images");
	check(sizeof(mgo_modelsetup::image_info) == 0x30, "an image record is 0x30 bytes");
	check(table[0].image_base == 0x0100c280u, "record 0 is the chara image at 0x100c280");
	check(table[1].image_base == 0x01009480u, "record 1 is the bg image at 0x1009480");
	check(table[0].image_hash == 0x743c495a49e3aaa3ull, "record 0 hashes to 0x743c495a49e3aaa3");
	check(table[1].image_hash == 0xf977d8259dcadeaeull, "record 1 hashes to 0xf977d8259dcadeae");
	check(table[0].hash_bytes == 0xac00u && table[1].hash_bytes == 0x5880u, "the hashed lengths differ per image");
	check(table[0].reserved_24 == 0 && table[1].reserved_24 == 0, "+0x24 is zero in both records");

	check(mgo_modelsetup::image_index(0x0100c280u) == 0, "the chara image is record 0");
	check(mgo_modelsetup::image_index(0x01009480u) == 1, "the bg image is record 1");
	check(mgo_modelsetup::image_index(0x01000000u) == -1, "an unknown image is rejected");
	check(mgo_modelsetup::image_index(0x00000000u) == -1, "a null image is rejected");
}

static void test_site_dispatch()
{
	std::printf("\n== the call-site dispatch\n");

	using k = mgo_modelsetup::site_kind;

	check(mgo_modelsetup::classify_site(0x0014cea0u) == k::chara, "lr 0x14cea4 is the chara site");
	check(mgo_modelsetup::classify_site(0x0014ce28u) == k::bg, "lr 0x14ce2c is the bg site");
	check(mgo_modelsetup::classify_site(0x0014cdb0u) == k::other, "site 0x14cdb0 is the one the fork ignores");
	check(mgo_modelsetup::classify_site(0x0014cea4u) == k::none, "an lr, not a call site, is not matched");
	check(mgo_modelsetup::classify_site(0x0014cdb4u) == k::none, "an unmatched call site is not ours");
}

static void test_fnv()
{
	std::printf("\n== FNV-1a-64 (0x143ac5805)\n");

	// The published FNV-1a-64 vectors, which is what the fork's constants are.
	const u8 empty[1] = { 0 };
	check(mgo_modelsetup::fnv1a64(empty, 0) == 0xcbf29ce484222325ull, "the empty input hashes to the basis");

	const u8 a = 'a';
	check(mgo_modelsetup::fnv1a64(&a, 1) == 0xaf63dc4c8601ec8cull, "\"a\" hashes to 0xaf63dc4c8601ec8c");

	const u8 foobar[6] = { 'f', 'o', 'o', 'b', 'a', 'r' };
	check(mgo_modelsetup::fnv1a64(foobar, 6) == 0x85944171f73967e8ull, "\"foobar\" hashes to 0x85944171f73967e8");

	// Byte order matters, so a one-bit change has to move the hash.
	u8 copy[6];
	std::memcpy(copy, foobar, sizeof(copy));
	copy[3] ^= 1;
	check(mgo_modelsetup::fnv1a64(copy, 6) != mgo_modelsetup::fnv1a64(foobar, 6), "one flipped bit changes the hash");
}

static void test_granule_walk()
{
	std::printf("\n== the reproduced-LS granule walk\n");

	using mgo_modelsetup::granule_mapped;
	using mgo_modelsetup::granule_skip_16;
	using mgo_modelsetup::granule_skip_page;
	using mgo_modelsetup::walk_granules;

	auto all_mapped = [](u32) { return u8(granule_mapped); };
	check(walk_granules(all_mapped, 0, 0), "a single mapped granule passes");
	check(walk_granules(all_mapped, 0, 0x40), "a range of mapped granules passes");
	check(!walk_granules([](u32 g) { return u8(g == 5 ? 0 : granule_mapped); }, 0, 10),
		"a hole in the middle fails");
	check(!walk_granules(flat_map(4), 0, 10), "the walk stops at the first unmapped granule");
	check(walk_granules({}, 0, 0) == false, "a missing map is not a pass");

	// The presence test comes *before* the skip test, so a skip bit has to
	// ride on top of 0x81: a bare 0x41 is rejected before its 0x40 is read.
	check(!walk_granules([](u32 g) { return u8(g == 1 ? 0x41 : granule_mapped); }, 1, 1),
		"a bare 0x41 fails the presence test");
	check(walk_granules([](u32 g) { return u8(g == 1 ? 0xc1 : granule_mapped); }, 1, 0x100),
		"0xc1 - the same bit on top of 0x81 - passes it");

	// 0x40 skips a whole 0x100, so the map need not cover it.
	auto sparse = [](u32 g) -> u8
	{
		return (g == 0 || g == 0x100) ? u8(granule_mapped)
		     : (g == 1 ? u8(granule_mapped | granule_skip_page) : u8(0));
	};
	check(walk_granules(sparse, 0, 0x100), "a 0x40 bit skips the 0xff granules behind it");
	check(!walk_granules(sparse, 0, 0x101), "the walk still checks the granule after the skip");

	// 0x20 skips the next 0x10.
	auto sparse16 = [](u32 g) -> u8
	{
		return (g == 0 || g == 0x10) ? u8(granule_mapped)
		     : (g == 1 ? u8(granule_mapped | granule_skip_16) : u8(0));
	};
	check(walk_granules(sparse16, 0, 0x10), "a 0x20 bit skips the 0x0f granules behind it");
	check(!walk_granules(sparse16, 0, 0x11), "the walk still checks the granule after the skip");

	// Only 0x81 is accepted: any other bit in the low 7 fails.
	check(!walk_granules([](u32) { return u8(0x80); }, 0, 0), "0x80 alone is not mapped");
	check(!walk_granules([](u32) { return u8(0x01); }, 0, 0), "0x01 alone is not mapped");
	check(walk_granules([](u32) { return u8(0x81 | granule_skip_page); }, 0, 0x100), "0xc1 keeps its skip bit");
}

static void test_page_guard()
{
	std::printf("\n== the two window guards\n");

	using mgo_modelsetup::window_backwards_ok;
	using mgo_modelsetup::window_forward_ok;

	auto all_mapped = [](u32) { return u8(mgo_modelsetup::granule_mapped); };

	// --- forward, as load_image and the launcher use it ------------------
	check(window_forward_ok(all_mapped, 0x00000000u, 0x33), "a forward window at 0 is fine");
	check(window_forward_ok(all_mapped, 0x00100000u, 0x00100033u), "an ordinary forward window passes");
	check(!window_forward_ok(all_mapped, 0xfffffffdu, 0xfffffffdu + 0x33), "a forward window that wraps is rejected");
	// 0x00100000 is page 0x100, not 0x1000.
	check(!window_forward_ok([](u32 g) { return u8(g == 0x100 ? 0 : mgo_modelsetup::granule_mapped); },
			0x00100000u, 0x00100033u), "a hole in the window is caught");
	// The forward window is compared as *page numbers*, so a 0x34-byte window
	// visits one granule unless it straddles a 4 KB page boundary.
	u32 visited = 0;
	auto counting = [&visited](u32) -> u8
	{
		visited++;
		return u8(mgo_modelsetup::granule_mapped);
	};

	visited = 0;
	window_forward_ok(counting, 0x00100f00u, 0x00100f33u);
	check(visited == 1, "a 0x34-byte window inside one page visits one entry");
	visited = 0;
	window_forward_ok(counting, 0x00100ffeu, 0x00101033u);
	check(visited == 2, "a 0x34-byte window across a page boundary visits both");

	// --- backwards, as read_spurs_args uses it ---------------------------
	//
	// The near end is ptr - 0x8000 and the far end a further 0x7ffd *below*
	// that, so the two page numbers normally compare as first > last and the
	// walk is skipped. The gate that survives is the wrap test, which rejects
	// exactly the three pointers whose window ends past 0xfffffffc.
	check(window_backwards_ok(all_mapped, 0x00100000u), "an ordinary queue pointer passes");
	check(window_backwards_ok(all_mapped, 0x00000000u), "a queue pointer of 0 passes the wrap test");
	check(window_backwards_ok(all_mapped, 0x00007ffcu), "0x7ffc is one below the wrap");
	check(!window_backwards_ok(all_mapped, 0x00007ffdu), "0x7ffd wraps and is rejected");
	check(!window_backwards_ok(all_mapped, 0x00007ffeu), "0x7ffe wraps and is rejected");
	check(!window_backwards_ok(all_mapped, 0x00007fffu), "0x7fff wraps and is rejected");
	check(window_backwards_ok(all_mapped, 0x00008000u), "0x8000 is one past the wrap");

	// The walk runs when ptr is low enough that ptr - 0x8000 - 0x7ffd
	// underflows, and is skipped above that.
	visited = 0;
	window_backwards_ok(counting, 0x00020000u);
	check(visited == 0, "the backwards walk is skipped for a typical pointer");
	visited = 0;
	window_backwards_ok(all_mapped, 0x00008000u);
	visited = 0;
	window_backwards_ok(counting, 0x00008000u);
	check(visited > 0, "the backwards walk runs when the far end underflows");
	visited = 0;
	window_backwards_ok(counting, 0x0000fffcu);
	check(visited > 0, "and it still runs at the top of that range");
	visited = 0;
	window_backwards_ok(counting, 0x00010000u);
	check(visited == 0, "but not from 0xfffd up");
}

static void test_spurs_args()
{
	std::printf("\n== the SPURS_TaskStart argument gates\n");

	using mgo_modelsetup::spurs_args_ok;

	// (gpr[6] ^ 0x10000) | (gpr[3] & 0xf) must be zero, and gpr[3] <= 0xffffff80.
	check(spurs_args_ok(0x00100000u, 0x00010000u), "the canonical arguments are accepted");
	check(!spurs_args_ok(0x00100001u, 0x00010000u), "a gpr[3] that is not 16-byte aligned is rejected");
	check(!spurs_args_ok(0x00100000u, 0x00000000u), "a gpr[6] that is not 0x10000 is rejected");
	check(!spurs_args_ok(0x00100008u, 0x00010000u), "a gpr[3] aligned to 8 but not 16 is rejected");
	check(spurs_args_ok(0xffffff80u, 0x00010000u), "gpr[3] exactly at the ceiling is accepted");
	check(!spurs_args_ok(0xffffff81u, 0x00010000u), "gpr[3] one past the ceiling is rejected");
}

static void test_page_set()
{
	std::printf("\n== par::page_set (0x143b46a00)\n");

	mgo_modelsetup::page_set set;

	check(set.size() == 0 && set.capacity() == 0, "a fresh set is empty");
	check(!set.contains(0), "an empty set contains nothing");

	set.insert(0);
	check(set.size() == 1, "one insert adds one page");
	check(set.contains(0), "page 0 is present");
	check(!set.contains(1), "page 1 is absent");

	set.insert(0);
	check(set.size() == 1, "inserting the same page twice is a no-op");

	// The table stays at least half empty: `lea edx, [rax*2 + 2]`.
	for (u32 i = 1; i < 5000; i++)
	{
		set.insert(i);
	}

	check(set.size() == 5000, "5000 distinct pages are all present");
	check(set.capacity() >= 10002, "the table is at least twice the load");
	check((set.capacity() & (set.capacity() - 1)) == 0, "the table size is a power of two");

	bool all = true;

	for (u32 i = 0; i < 5000; i++)
	{
		all = all && set.contains(i);
	}

	check(all, "every inserted page survives the rehashes");

	set.insert(0x7fffffffu);
	check(set.contains(0x7fffffffu), "a very large page number hashes and probes cleanly");

	bool none_wrong = true;

	for (u32 i = 5000; i < 6000; i++)
	{
		none_wrong = none_wrong && !set.contains(i);
	}

	check(none_wrong, "uninserted pages are absent");

	// Page 0 is stored as 1, so it must not be confused with an empty slot.
	mgo_modelsetup::page_set fresh;
	fresh.insert(0);
	check(fresh.contains(0), "page 0 is stored as 1 and is not an empty slot");
	check(!fresh.contains(0xffffffffu), "an uninserted page reads as absent");
}

static void test_tracker()
{
	std::printf("\n== par::tracker (0x143b46920 / 0x143b46d30)\n");

	mgo_modelsetup::tracker t;

	t.on_get(0x10000000u, 0x10);
	t.on_put(0x10004000u, 0x2000);

	check(t.reads().size() == 1 && t.reads()[0].addr == 0x10000000u && t.reads()[0].size == 0x10,
		"a read records {addr, size}");
	check(t.writes().size() == 1 && t.writes()[0].addr == 0x10004000u, "a write records {addr, size}");
	check(t.read_pages().contains(0x10000u), "the read page_set holds the read page");
	check(!t.read_pages().contains(0x10004u), "the read page_set does not hold the written page");
	check(t.written_pages().contains(0x10004u), "the written page_set holds the written page");

	// A read spanning three pages inserts all three.
	mgo_modelsetup::tracker wide;
	wide.on_get(0x00000000u, 0x2001u);
	check(wide.read_pages().contains(0) && wide.read_pages().contains(1) && wide.read_pages().contains(2),
		"a 0x2001-byte read covers pages 0, 1 and 2");
	check(wide.read_pages().size() == 3, "and inserts exactly three pages");

	// The watch slot compares the *address*, not the page: 0x143b46941
	// compares esi before it is shifted at 0x143b469b5.
	mgo_modelsetup::tracker watched;
	watched.watch(0x00123400u);
	watched.on_get(0x00100000u, 4);
	check(watched.reads().size() == 1, "an unwatched read is still recorded");
	watched.on_get(0x00123400u, 4);
	watched.on_get(0x00123400u, 4);
	check(watched.reads().size() == 3, "a watched address can be read repeatedly");
	check(watched.read_pages().size() == 2, "re-reading the same page does not reinsert it");
}

int main()
{
	test_status_table();
	test_image_table();
	test_site_dispatch();
	test_fnv();
	test_granule_walk();
	test_page_guard();
	test_spurs_args();
	test_page_set();
	test_tracker();

	std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}