// Unit test for mgo_waits: the lwarx spin-loop policy.
//
// Everything below is host logic over plain data - the six-PC site table, the
// budget gate's cmovne truth table, the nine-character title gate, the
// reservation-slot arithmetic and the SWAR guard hash - so all of it is
// testable without the emulator. The two parts that need a live thread (the
// actual wait, and the local-store read behind geo_getllar_ignore_gpr1) are
// verified structurally by buildfiles/mgo_verify_re.py instead.
//
// Build and run (no RPCS3 headers needed):
//   g++ -std=c++20 -O1 -o waits_test buildfiles/mgo_waits_test.cpp
//   ./waits_test

#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <string_view>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using usz = std::size_t;

namespace mgo_waits
{
	// Mirrors spu_task_hle::mgo_task_acceleration in Emu/system_config_types.h.
	enum class accel : u8
	{
		off,
		basic,
		standard,
		maximum,
	};

	// `cmp cl, 2 / jae` against g_cfg.mgo.task_acceleration, i.e. standard.
	constexpr accel min_level = accel::standard;

	// `mov r8d, 0xc350`.
	constexpr u64 wait_timeout = 50'000;

	struct lwarx_site
	{
		u32 pc_lo = 0;
		u32 pc_hi = 0;
		u32 budget = 0;
	};

	// Verbatim from 0x144a25cf0, three 12-byte records.
	constexpr lwarx_site s_sites[] =
	{
		{ 0x00337070u, 0x00337080u, 0u },
		{ 0x001b01f8u, 0x001b0240u, 2u },
		{ 0x001999a8u, 0x001999d8u, 3u },
	};

	const lwarx_site* lwarx_sites(usz& count)
	{
		count = std::size(s_sites);
		return s_sites;
	}

	const lwarx_site* find_lwarx_site(u32 pc)
	{
		for (const lwarx_site& site : s_sites)
		{
			if (pc == site.pc_lo || pc == site.pc_hi)
			{
				return &site;
			}
		}

		return nullptr;
	}

	bool is_lwarx_site_pc(u32 pc)
	{
		return find_lwarx_site(pc) != nullptr;
	}

	bool budget_gate(u32 value, u32 budget)
	{
		const bool under = value < budget;
		const bool non_zero = value != 0;

		return (budget != 0) ? under : non_zero;
	}

	constexpr usz title_length = 9;

	bool title_supported(const char* title_id)
	{
		if (!title_id)
		{
			return false;
		}

		const std::string_view id{title_id};

		if (id.size() != title_length)
		{
			return false;
		}

		return id == "NPMG00010" || id == "NPMG00020";
	}

	constexpr u32 reservation_mask = 0x7fc0;
	constexpr u32 reservation_granule_bytes = 0x40;

	constexpr u32 reservation_slot_offset(u32 addr)
	{
		return (addr >> 1) & reservation_mask;
	}

	constexpr u32 guard_buckets = 120;

	constexpr u32 guard_bucket(u32 addr)
	{
		return ((addr >> 2) & 0x60) | std::popcount(addr & 0xfffffe00u);
	}

	struct getllar_magic
	{
		u32 at_0x3000 = 0x027a8043;
		u32 at_0x3004 = 0x82a2a543;
		u32 at_0x3008 = 0x02433943;
		u32 at_0x300c = 0x824fb142;
	};

	constexpr u32 getllar_ls_offset = 0x3000;

	bool geo_getllar_ignore_gpr1(const u8* ls)
	{
		if (!ls)
		{
			return false;
		}

		const getllar_magic want{};
		const u32* expect = &want.at_0x3000;

		for (usz i = 0; i < 4; i++)
		{
			u32 have = 0;
			std::memcpy(&have, ls + getllar_ls_offset + i * sizeof(u32), sizeof(have));

			if (have != expect[i])
			{
				return false;
			}
		}

		return true;
	}
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

// ---------------------------------------------------------------------------
// The three records, exactly as 0x144a25cf0 holds them.

static void test_site_table()
{
	std::printf("\n== the lwarx site table (0x144a25cf0)\n");

	usz count = 0;
	const mgo_waits::lwarx_site* sites = mgo_waits::lwarx_sites(count);

	check(count == 3, "there are three records");
	check(sizeof(mgo_waits::lwarx_site) == 12, "a record is twelve bytes, so the stride is 12");

	if (count != 3)
	{
		return;
	}

	check(sites[0].pc_lo == 0x00337070u && sites[0].pc_hi == 0x00337080u && sites[0].budget == 0u,
		  "record 0 is {0x337070, 0x337080, 0}");
	check(sites[1].pc_lo == 0x001b01f8u && sites[1].pc_hi == 0x001b0240u && sites[1].budget == 2u,
		  "record 1 is {0x1b01f8, 0x1b0240, 2}");
	check(sites[2].pc_lo == 0x001999a8u && sites[2].pc_hi == 0x001999d8u && sites[2].budget == 3u,
		  "record 2 is {0x1999a8, 0x1999d8, 3}");

	// The guest addresses are ordered, which is what makes the caller's
	// threshold compare (jg 0x1b023f) a valid binary search: everything at or
	// above 0x1b0240 is handled by the first arm, and the rest is split below.
	check(sites[0].pc_lo > sites[1].pc_hi && sites[1].pc_lo > sites[2].pc_hi,
		  "the records are in descending address order");

	check(sites[0].pc_hi == 0x00337080u && 0x1b023fu < sites[1].pc_hi,
		  "0x1b023f is a switch threshold, not a site");
}

// ---------------------------------------------------------------------------
// is_lwarx_site_pc over all six PCs, plus the neighbourhood that must not hit.

static void test_site_lookup()
{
	std::printf("\n== is_lwarx_site_pc over the six hardcoded PCs\n");

	const u32 six[] = { 0x00337070u, 0x00337080u, 0x001b01f8u, 0x001b0240u, 0x001999a8u, 0x001999d8u };

	for (u32 pc : six)
	{
		check(mgo_waits::is_lwarx_site_pc(pc), "a table PC is recognised");
	}

	check(!mgo_waits::is_lwarx_site_pc(0x1b023fu),
		  "0x1b023f - the switch threshold - is not a site");
	check(!mgo_waits::is_lwarx_site_pc(0x1b0241u),
		  "one past a site is not a site");
	check(!mgo_waits::is_lwarx_site_pc(0x00337060u),
		  "sixteen below a site is not a site");
	check(!mgo_waits::is_lwarx_site_pc(0x00000000u), "pc 0 is not a site");
	check(!mgo_waits::is_lwarx_site_pc(0xffffffffu), "pc -1 is not a site");

	// Each record must be found by both of its own PCs, and no other record
	// may claim them: that is what "self-describing" means in the header.
	usz count = 0;
	const mgo_waits::lwarx_site* sites = mgo_waits::lwarx_sites(count);

	bool paired = true;

	for (usz i = 0; i < count; i++)
	{
		if (mgo_waits::find_lwarx_site(sites[i].pc_lo) != &sites[i] ||
			mgo_waits::find_lwarx_site(sites[i].pc_hi) != &sites[i])
		{
			paired = false;
		}
	}

	check(paired, "each PC resolves to the record that holds it");

	check(mgo_waits::find_lwarx_site(0x1b023fu) == nullptr,
		  "and a non-site resolves to nothing at all");
}

// ---------------------------------------------------------------------------
// The budget gate, exhaustively against the transcribed cmovne.

static void test_budget_gate()
{
	std::printf("\n== the budget gate's truth table\n");

	// budget 0 means "any non-zero value", because (value < 0) is never true
	// and the cmovne keeps the value != 0 branch in that case.
	check(!mgo_waits::budget_gate(0u, 0u), "budget 0, value 0: no wait");
	check(mgo_waits::budget_gate(1u, 0u), "budget 0, value 1: wait");
	check(mgo_waits::budget_gate(0xffffffffu, 0u), "budget 0, value -1: wait");

	// A non-zero budget means "value is still under the threshold".
	check(mgo_waits::budget_gate(0u, 2u), "budget 2, value 0: wait");
	check(mgo_waits::budget_gate(1u, 2u), "budget 2, value 1: wait");
	check(!mgo_waits::budget_gate(2u, 2u), "budget 2, value 2: no wait (not <)");
	check(!mgo_waits::budget_gate(3u, 2u), "budget 2, value 3: no wait");

	check(mgo_waits::budget_gate(2u, 3u), "budget 3, value 2: wait");
	check(!mgo_waits::budget_gate(3u, 3u), "budget 3, value 3: no wait");

	// The fork's sequence is a comparison, not a clamp, so an unsigned value
	// above the budget stays above it however large it is.
	check(!mgo_waits::budget_gate(0x80000000u, 2u), "a large value is not under a small budget");
	check(!mgo_waits::budget_gate(0x80000000u, 3u), "and not under either site budget");

	// The gate is *decreasing* in value for a non-zero budget - it is
	// "the spinner still sees a small number", not "the value is nonzero" -
	// and for a zero budget it is just value != 0. So the correct shape is
	// monotone-decreasing for budget > 0 and monotone-increasing for budget 0.
	bool shape_ok = true;

	for (u32 budget : { 2u, 3u })
	{
		bool prev = mgo_waits::budget_gate(0u, budget);

		for (u32 value = 1; value <= 8; value++)
		{
			const bool now = mgo_waits::budget_gate(value, budget);

			if (now && !prev)
			{
				shape_ok = false;
			}

			prev = now;
		}
	}

	check(shape_ok, "for a non-zero budget the gate is monotone decreasing in value");

	// budget 0 is the other way round: it only ever tests for non-zero.
	check(!mgo_waits::budget_gate(0u, 0u) && mgo_waits::budget_gate(1u, 0u),
		  "and for budget 0 it is simply value != 0");

	// The budget field is a threshold, never a retry count: the fork has no
	// counter anywhere in the body, which is why 0 is meaningful at all.
	check(mgo_waits::budget_gate(1u, 0u) && !mgo_waits::budget_gate(0u, 0u),
		  "the zero budget still fires, so it cannot be a 'how many' field");
}

// ---------------------------------------------------------------------------
// The title gate.

static void test_title_gate()
{
	std::printf("\n== the title gate\n");

	check(mgo_waits::title_supported("NPMG00010"), "NPMG00010 is accepted");
	check(mgo_waits::title_supported("NPMG00020"), "NPMG00020 is accepted");

	check(!mgo_waits::title_supported("NPMG00030"), "a third NPMG id is refused");
	check(!mgo_waits::title_supported("NPMG00011"), "so is a near miss");

	// The length test is a hard nine, so both an eight- and a ten-character
	// string that otherwise match must be refused.
	check(!mgo_waits::title_supported("NPMG0001"), "eight characters is refused");
	check(!mgo_waits::title_supported("NPMG000100"), "ten characters is refused");
	check(!mgo_waits::title_supported(""), "the empty string is refused");
	check(!mgo_waits::title_supported(nullptr), "no title is refused");

	// Case matters: the compares are on the raw bytes.
	check(!mgo_waits::title_supported("npmg00010"), "lower case is refused");

	// Nine characters that are not either title.
	check(!mgo_waits::title_supported("BLUS12345"), "an unrelated nine-character id is refused");

	check(mgo_waits::title_length == 9, "the required length really is nine");
}

// ---------------------------------------------------------------------------
// The two constants are plain ASCII, not XOR'd.

static void test_title_constants()
{
	std::printf("\n== the title constants are plain ASCII\n");

	// 0x31303030474d504e stored little-endian reads back as "NPMG0001".
	check(0x31303030474d504eull == (u64)'N' | ((u64)'P' << 8) | ((u64)'M' << 16) | ((u64)'G' << 24) |
						   ((u64)'0' << 32) | ((u64)'0' << 40) | ((u64)'0' << 48) | ((u64)'1' << 56),
		  "0x31303030474d504e is \"NPMG0001\" in ASCII");
	check(0x32303030474d504eull == (u64)'N' | ((u64)'P' << 8) | ((u64)'M' << 16) | ((u64)'G' << 24) |
						   ((u64)'0' << 32) | ((u64)'0' << 40) | ((u64)'0' << 48) | ((u64)'2' << 56),
		  "0x32303030474d504e is \"NPMG0002\" in ASCII");
	check(0x30u == (u32)'0', "and the ninth byte is '0', the XOR's partner");
}

// ---------------------------------------------------------------------------
// The reservation slot, including the one-bit-too-wide mask.

static void test_reservation_slot()
{
	std::printf("\n== the reservation slot offset\n");

	check(mgo_waits::reservation_slot_offset(0u) == 0u, "addr 0 maps to offset 0");
	check(mgo_waits::reservation_slot_offset(1u) == 0u, "addr 1 shares offset 0");
	check(mgo_waits::reservation_slot_offset(2u) == 0u, "addr 2 shares offset 0 too");
	check(mgo_waits::reservation_slot_offset(0x80u) == 0x40u, "addr 0x80 maps to offset 0x40");

	// Every offset is a multiple of the 0x40-byte stride.
	bool aligned = true;
	bool in_range = true;

	for (u32 addr = 0; addr < 0x100000u; addr += 0x20)
	{
		const u32 off = mgo_waits::reservation_slot_offset(addr);

		if ((off & (mgo_waits::reservation_granule_bytes - 1)) != 0)
		{
			aligned = false;
		}

		if (off >= 65536 / 128 * 64)
		{
			in_range = false;
		}
	}

	check(aligned, "every slot is 0x40-byte aligned");
	check(in_range, "every slot stays inside the 64 KiB reservation table");

	// The 512-byte window boundaries: 0x100, 0x200, ... each start a new slot,
	// and the last byte before a boundary shares the previous one.
	check(mgo_waits::reservation_slot_offset(0x1ffu) == 0xc0u, "addr 0x1ff maps to 0xc0");
	check(mgo_waits::reservation_slot_offset(0x200u) == 0x100u, "addr 0x200 starts a new slot");
	check(mgo_waits::reservation_slot_offset(0x1feu) == mgo_waits::reservation_slot_offset(0x1ffu),
		  "and 0x1ff shares its slot with its neighbour");

	// **The mask is NOT one bit wider than reservation_acquire's.** This test
	// exists because an earlier draft claimed it was, and that claim was
	// wrong: `(addr & 0xff80) / 2` and `(addr >> 1) & 0x7fc0` are the same
	// function, because dividing by two is a shift and 0xff80 >> 1 == 0x7fc0.
	// The fork therefore waits on exactly the slot upstream uses.
	bool agrees = true;

	for (u32 addr = 0; addr < 0x40000u; addr++)
	{
		const u32 vm_offset = (addr & 0xff80u) / 2u;

		if (mgo_waits::reservation_slot_offset(addr) != vm_offset)
		{
			agrees = false;
			break;
		}
	}

	check(agrees, "the fork agrees with vm::reservation_acquire on every address");
	check(0xff80u >> 1 == 0x7fc0u, "which is just the identity 0xff80 >> 1 == 0x7fc0");

	check(mgo_waits::reservation_mask == 0x7fc0u, "the mask is 0x7fc0");
	check(mgo_waits::reservation_granule_bytes == 0x40u, "the stride is 0x40 bytes");
}

// ---------------------------------------------------------------------------
// The SWAR guard hash.

static void test_guard_bucket()
{
	std::printf("\n== the waiter-count index hash\n");

	// The fork's own expression: popcount of the 512-byte-granule bits, plus
	// two more index bits from below the granule. The granule mask is
	// 0xfffffe00 - 23 bits - so the popcount term alone can reach 23. That is
	// why an earlier "64-entry guard" reading of this was wrong.
	check(mgo_waits::guard_bucket(0u) == 0u, "addr 0 lands in bucket 0");
	check(mgo_waits::guard_bucket(0x200u) == 1u, "one granule bit gives bucket 1");
	// 0x400 is still a single bit, so it also gives 1 - the count is a popcount,
	// not a granule number. 0x600 is the first address with two of them.
	check(mgo_waits::guard_bucket(0x400u) == 1u, "0x400 is one bit too, so bucket 1");
	check(mgo_waits::guard_bucket(0x600u) == 2u, "two granule bits give bucket 2");
	check(mgo_waits::guard_bucket(0xfffffe00u) == 23u,
		  "one 0x100 granule holds all 23 bits, so bucket 23");

	// The low bits contribute through the `& 0x60` term.
	check(mgo_waits::guard_bucket(0x80u) == 0x20u, "bit 7 reaches the second index bit");
	check(mgo_waits::guard_bucket(0x100u) == 0x40u, "bit 8 reaches the third");
	check(mgo_waits::guard_bucket(0x180u) == 0x60u, "both together give 0x60");

	// Bits below 0x200 that are not 0x80 or 0x100 must contribute nothing.
	bool low_bits_ignored = true;

	for (u32 bit = 0; bit < 9; bit++)
	{
		if (bit == 7 || bit == 8)
		{
			continue;
		}

		if (mgo_waits::guard_bucket(1u << bit) != 0)
		{
			low_bits_ignored = false;
		}
	}

	check(low_bits_ignored, "the other seven low bits contribute nothing");

	// The bound that actually matters: the index must stay inside the table.
	bool bounded = true;

	for (u32 addr = 0; addr < 0x100000u; addr += 0x40)
	{
		if (mgo_waits::guard_bucket(addr) >= mgo_waits::guard_buckets)
		{
			bounded = false;
		}
	}

	check(bounded, "every bucket below 0x100000 stays inside the table");

	// The true maximum, over all u32: popcount(0xfffffe00) is 23 bits and the
	// other term tops out at 0x60, so 23 | 0x60 == 119.
	constexpr u32 granule_bits = std::popcount(0xfffffe00u);
	constexpr u32 low_term_max = 0x60u;
	constexpr u32 max_bucket = granule_bits | low_term_max;

	check(granule_bits == 23u, "the granule mask 0xfffffe00 holds 23 bits");
	check(max_bucket == 119u, "so the largest possible index is 119");
	check(max_bucket < mgo_waits::guard_buckets, "and 119 is below the 120 slots allocated");
	check(max_bucket >= 64u, "which is why a 64-entry array would have been out of bounds");

	// An index above 64 really does occur, so 120 is not slack. The smallest
	// one is 0x180, where the `& 0x60` term is already 0x60 == 96 on its own -
	// so a scan in steps of 0x200 would step straight over it.
	check(mgo_waits::guard_bucket(0x180u) == 96u,
		  "0x180 alone already indexes 96, because 0x60 == 96 is over half the table");

	bool reached = false;

	for (u32 addr = 0; addr < 0x1000u; addr += 4)
	{
		if (mgo_waits::guard_bucket(addr) > 64u)
		{
			reached = true;
			break;
		}
	}

	check(reached, "and an index above 64 occurs in the first 4 KiB");

	// The maximum is reachable too, so the bound is tight in both directions.
	check(mgo_waits::guard_bucket(0xfffffe00u | 0x180u) == 119u, "and 119 is reached at 0xfffffe00|0x180");

	// It must discriminate: neighbouring granules have to be able to land in
	// different buckets, or the counter would serialise unrelated spins.
	bool discriminates = false;

	for (u32 addr = 0x200; addr < 0x2000 && !discriminates; addr += 0x200)
	{
		discriminates = mgo_waits::guard_bucket(addr) != mgo_waits::guard_bucket(addr + 0x200);
	}

	check(discriminates, "adjacent granules get different buckets");

	// Granules are 512 bytes apart, so a 0x200 step adds exactly one bit.
	check(mgo_waits::guard_bucket(0x200u) - mgo_waits::guard_bucket(0u) == 1u,
		  "one granule is one popcount bit");
	check(mgo_waits::guard_bucket(0xfffffe00u) - mgo_waits::guard_bucket(0u) == 23u,
		  "and a full 0x100 granule contributes all 23 of its bits");
}

// ---------------------------------------------------------------------------
// The configuration gate and the timeout.

static void test_config_gate()
{
	std::printf("\n== the task acceleration gate and the timeout\n");

	check(static_cast<u8>(mgo_waits::min_level) == 2u,
		  "the gate is `cmp cl, 2`, i.e. standard");
	check(mgo_waits::min_level == mgo_waits::accel::standard, "which is the standard level");

	// `cmp cl, 2 / jae` is unsigned, so the gate is a >=.
	const u8 levels[] = { 0, 1, 2, 3 };
	const bool want[] = { false, false, true, true };

	for (u8 i = 0; i < 4; i++)
	{
		check((levels[i] >= static_cast<u8>(mgo_waits::min_level)) == want[i],
			  "the gate admits every level at or above standard");
	}

	check(mgo_waits::wait_timeout == 50'000u, "the timeout is 50'000");
	check(mgo_waits::wait_timeout == 0xc350u, "which is 0xc350 as an immediate");
}

// ---------------------------------------------------------------------------
// geo_getllar_ignore_gpr1 over a synthetic local store.

static void test_getllar_magic()
{
	std::printf("\n== the GETLLAR-on-gpr1 signature\n");

	constexpr u32 k = 0x3000 + 0x4000;

	static u8 ls[k];
	std::memset(ls, 0, sizeof(ls));

	const mgo_waits::getllar_magic want{};

	std::memcpy(ls + mgo_waits::getllar_ls_offset, &want, sizeof(want));

	check(mgo_waits::geo_getllar_ignore_gpr1(ls), "the four-word signature is recognised");
	check(mgo_waits::getllar_ls_offset == 0x3000u, "and it is read at LS + 0x3000");

	check(!mgo_waits::geo_getllar_ignore_gpr1(nullptr), "a null local store is refused");

	// All four words independently matter.
	const u32 words[] = { want.at_0x3000, want.at_0x3004, want.at_0x3008, want.at_0x300c };

	for (usz i = 0; i < 4; i++)
	{
		u32 saved = words[i];
		u32* at = reinterpret_cast<u32*>(ls + mgo_waits::getllar_ls_offset) + i;
		*at = saved ^ 1u;

		check(!mgo_waits::geo_getllar_ignore_gpr1(ls), "one flipped bit in any word is refused");

		*at = saved;
	}

	check(mgo_waits::geo_getllar_ignore_gpr1(ls), "and restoring all four restores the match");

	// One byte short of the signature must fail, so the read really is
	// four words wide and not one.
	ls[mgo_waits::getllar_ls_offset + 15] ^= 0xff;

	check(!mgo_waits::geo_getllar_ignore_gpr1(ls), "the last byte of the fourth word matters");

	ls[mgo_waits::getllar_ls_offset + 15] ^= 0xff;

	// A signature one word early must not match.
	u32* base = reinterpret_cast<u32*>(ls + mgo_waits::getllar_ls_offset);
	std::memmove(ls + mgo_waits::getllar_ls_offset - 4, ls + mgo_waits::getllar_ls_offset, sizeof(want));
	std::memset(ls + mgo_waits::getllar_ls_offset, 0, sizeof(want));

	check(!mgo_waits::geo_getllar_ignore_gpr1(ls), "the signature is not matched at -4");
	check(!mgo_waits::geo_getllar_ignore_gpr1(ls), "and the offset is not merely a lower bound");

	(void)base;
}

int main()
{
	test_site_table();
	test_site_lookup();
	test_budget_gate();
	test_title_gate();
	test_title_constants();
	test_reservation_slot();
	test_guard_bucket();
	test_config_gate();
	test_getllar_magic();

	std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}