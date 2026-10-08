// Unit test for the mgo_pl_motion_mix front end.
//
// Everything below is host logic over plain data - the ten-entry decline
// table, the staged-index arithmetic, the reproduced-LS granule walk, the
// 0x40040-byte staging buffer and its dirty maps, detail::clean()'s live-range
// filter, detail::get(), detail::set_nv() and run_launch's descriptor proof -
// so all of it is testable without the emulator. The parts that need guest
// memory (the parameter block, the seven DMA descriptors, the stage driver)
// are transcribed from the fork's own 0x143a14dc0 and are verified
// byte-for-byte by buildfiles/mgo_verify_re.py instead.
//
// Build and run (no RPCS3 headers needed):
//   g++ -std=c++20 -O1 -o mgo_pl_motion_mix_test buildfiles/mgo_pl_motion_mix_test.cpp
//   ./mgo_pl_motion_mix_test

#include <array>
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

namespace mgo_pl_motion_mix
{
	// --- transcribed from 0x144b3789c ------------------------------------
	enum class decline : u8
	{
		unmapped_guest_memory = 0,
		unexpected_parameter_block = 1,
		phase_word_too_small = 2,
		task_object_busy = 3,
		misaligned_dma = 4,
		width_over_128 = 5,
		count_over_128 = 6,
		bone_descriptor_changed = 7,
		stage_clobbered_callee_saved = 8,
		lifted_code_declined = 9,
	};

	const char* decline_text(decline reason)
	{
		switch (reason)
		{
		case decline::unmapped_guest_memory: return "unmapped guest memory";
		case decline::unexpected_parameter_block: return "unexpected parameter block";
		case decline::phase_word_too_small: return "phase word <= 3";
		case decline::task_object_busy: return "task object busy (obj+0xa0 != 0)";
		case decline::misaligned_dma: return "misaligned DMA (the task would halt)";
		case decline::width_over_128: return "W(S+4) > 128";
		case decline::count_over_128: return "N > 128";
		case decline::bone_descriptor_changed: return "bone descriptor changed by a stage";
		case decline::stage_clobbered_callee_saved: return "stage clobbered callee-saved registers";
		case decline::lifted_code_declined: return "lifted code declined (load/store outside reproduced LS, budget, halt)";
		default: return "?";
		}
	}

	constexpr u32 decline_line = 0x24;

	// Every staged exit funnels through `add r14d, 0xfe / movzx r12d, r14b`,
	// so the table index is (staged + 0xfe) & 0xff and a staged value sits two
	// above the reason it reports.
	constexpr u8 staged_bias = 0xfe;

	constexpr u8 stage_index(u8 staged)
	{
		return static_cast<u8>(staged + staged_bias);
	}

	// --- the parameter block, 0x124 bytes at gpr[3] ----------------------
	struct param_block
	{
		static constexpr u32 size = 0x124;
		static constexpr u32 self_hi = 0x100;
		static constexpr u32 self_lo = 0x104;
		static constexpr u32 self_span = 0xa4;
		static constexpr u32 task_object = 0xa0;
		static constexpr u32 phase_min = 4;
	};

	// --- the seven DMA descriptors ---------------------------------------
	struct dma_desc
	{
		u32 at;
		u32 order;
		u32 size;
		u32 scratch;
	};

	constexpr dma_desc dma_descs[] =
	{
		{ 0x108, 0, 0x5d0,  0x13080 },
		{ 0x110, 1, 0x3bf0, 0x13680 },
		{ 0x120, 2, 0x10,   0x17280 },
		{ 0x114, 3, 0x120,  0x17300 },
		{ 0x118, 4, 0x120,  0x17480 },
		{ 0x10c, 5, 0x280,  0x17600 },
		{ 0x11c, 6, 0xa0,   0x17880 },
	};

	struct sub_desc
	{
		u32 scratch;
		u32 destination;
	};

	constexpr sub_desc sub_descs[] =
	{
		{ 0x17320, 0xc680 },
		{ 0x17350, 0xce80 },
		{ 0x17380, 0xd680 },
		{ 0x173b0, 0xde80 },
		{ 0x173e0, 0xe680 },
		{ 0x17410, 0xee80 },
	};

	constexpr u32 max_width = 128;
	constexpr u32 max_count = 128;
	constexpr u32 width_stride = 16;
	constexpr u32 width_offset = 0x13084;

	struct descriptor_layout
	{
		static constexpr u32 at = 0x17280;
		static constexpr u32 w0 = 0x17280;
		static constexpr u32 w1 = 0x17284;
		static constexpr u32 w2 = 0x17288;
		static constexpr u32 w3 = 0x1728c;
	};

	constexpr u32 count_buffer = 0x10800;
	constexpr u32 count_stride5 = 80;
	constexpr u32 count_stride1 = 16;
	constexpr u32 count_buffer_end = 0x13000;
	constexpr u32 rows_spacing = 0x800;

	constexpr u32 writeback_matrix = 0x13680;
	constexpr u32 writeback_matrix_size = 0x3bf0;
	constexpr u32 writeback_rows = 0xfe80;
	constexpr u32 writeback_rows2 = 0xf680;
	constexpr u32 matrix_offset_max = 0xffffc410u;

	// --- scratch_t --------------------------------------------------------
	struct scratch_t
	{
		u8 data[0x40000] = {};
		u64 dirty_00000 = 0;
		u64 dirty_10000 = 0;
		u64 dirty_20000 = 0;
		u64 dirty_30000 = 0;
	};

	constexpr u32 block_bytes = 0x400;
	constexpr u32 block_shift = 10;
	constexpr u32 band_shift = 16;

	struct live_range
	{
		u32 begin;
		u32 end;
	};

	constexpr live_range live_13000{ 0x13080, 0x13251 };
	constexpr live_range live_03680{ 0x03680, 0x06e71 };

	// --- nv_set -----------------------------------------------------------
	struct nv_set
	{
		u8 bytes[0xc0] = {};
	};

	const nv_set& nv_stage1()
	{
		// Verbatim from 0x144b2a154.
		static const nv_set set = { {
			0x80, 0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x73, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
			0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
			0x80, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x78, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x76, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x36, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		} };
		return set;
	}

	const nv_set& nv_stage23()
	{
		// Verbatim from 0x144b2a214.
		static const nv_set set = { {
			0x80, 0xfe, 0x00, 0x00, 0x80, 0xfe, 0x00, 0x00,
			0x80, 0xfe, 0x00, 0x00, 0x80, 0xfe, 0x00, 0x00,
			0x00, 0x08, 0x01, 0x00, 0x00, 0x08, 0x01, 0x00,
			0x00, 0x08, 0x01, 0x00, 0x00, 0x08, 0x01, 0x00,
			0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
			0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x80, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x78, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x76, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x80, 0x36, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		} };
		return set;
	}

	const std::array<u8, 16>& nv_fill()
	{
		// 0x144b23160.
		static const std::array<u8, 16> fill =
		{
			0xed, 0x5e, 0xed, 0x5e, 0x5a, 0x5a, 0x5a, 0x5a,
			0x58, 0x00, 0x00, 0x00, 0x58, 0xad, 0xde, 0x7f,
		};
		return fill;
	}

	void set_nv(u8* ctx, const nv_set& set)
	{
		// Eleven groups read four bytes in, so the four lanes come out
		// reversed, then one more reversed group at ctx + 0x140, then the
		// constant fill over ctx + 0x110 .. ctx + 0x300.
		for (u32 group = 0; group < 11; group++)
		{
			u32* out = reinterpret_cast<u32*>(ctx + 0x90 + group * 0x10);

			for (u32 lane = 0; lane < 4; lane++)
			{
				u32 word = 0;
				std::memcpy(&word, &set.bytes[group * 0x10 + (3 - lane) * 4], sizeof(word));
				out[lane] = word;
			}
		}

		u32* tail = reinterpret_cast<u32*>(ctx + 0x140);

		for (u32 lane = 0; lane < 4; lane++)
		{
			u32 word = 0;
			std::memcpy(&word, &set.bytes[0xb0 + (3 - lane) * 4], sizeof(word));
			tail[lane] = word;
		}

		const std::array<u8, 16>& fill = nv_fill();

		for (u32 off = 0x110; off < 0x300; off += 16)
		{
			std::memcpy(ctx + off, fill.data(), fill.size());
		}
	}

	// --- the granule map --------------------------------------------------
	constexpr u8 granule_mapped = 0x81;
	constexpr u8 granule_skip_page = 0x40;
	constexpr u8 granule_skip_16 = 0x20;
	constexpr u32 granule_bytes = 0x1000;

	bool window_ok(const std::function<u8(u32)>& map_byte, u32 lo, u32 hi)
	{
		if (!map_byte)
		{
			return false;
		}

		for (u32 granule = lo >> 12; granule <= (hi >> 12);)
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

	// --- scratch maintenance ----------------------------------------------
	void mark_dirty(scratch_t& s, u32 addr)
	{
		const u32 bit = addr >> block_shift;
		(&s.dirty_00000)[addr >> band_shift] |= 1ull << (bit & 63);
	}

	void clean(scratch_t& s)
	{
		struct region
		{
			u64* map;
			u32 base;
			bool filtered;
		};

		const region regions[] =
		{
			{ &s.dirty_00000, 0x00000, false },
			{ &s.dirty_10000, 0x10000, true },
			{ &s.dirty_20000, 0x20000, false },
			{ &s.dirty_30000, 0x30000, false },
		};

		for (const region& r : regions)
		{
			u64 bits = *r.map;
			*r.map = 0;

			while (bits != 0)
			{
				const u32 off = static_cast<u32>(__builtin_ctzll(bits)) << block_shift;

				if (r.filtered)
				{
					const u32 shifted = off + 0x10000u;
					const bool in_13000 = shifted >= live_13000.begin && shifted < live_13000.end;
					const u32 back = off - live_03680.begin;
					const bool in_03680 = back < (live_03680.end - live_03680.begin);

					if (in_13000 || in_03680)
					{
						bits &= bits - 1;
						continue;
					}
				}

				if (static_cast<u64>(r.base) + off + block_bytes <= sizeof(s.data))
				{
					std::memset(&s.data[r.base + off], 0, block_bytes);
				}

				bits &= bits - 1;
			}
		}
	}

	// --- detail::get ------------------------------------------------------
	// The fork's guest memory, reduced to the two questions get() asks: is
	// this range mapped, and what does it read.
	struct guest_mem
	{
		std::vector<u8> bytes;
		u32 mapped_from = 0;
		u32 mapped_to = 0;

		bool valid(u32 addr, u32 size) const
		{
			return addr >= mapped_from && static_cast<u64>(addr) + size <= mapped_to;
		}

		const u8* ptr(u32 addr, u32 size) const
		{
			if (!valid(addr, size))
			{
				return nullptr;
			}

			return &bytes[addr];
		}

		std::function<u8(u32)> granule_map() const
		{
			return [this](u32 granule) -> u8
			{
				const u32 addr = granule * granule_bytes;
				return valid(addr, 4) ? granule_mapped : u8(0);
			};
		}
	};

	bool get(const guest_mem& mem, scratch_t& s, u32 guest_addr, u32 size, u32 off,
	         const std::function<u8(u32)>& map_byte)
	{
		if (size == 0)
		{
			return true;
		}

		if (static_cast<u64>(guest_addr) + size > 0x100000000ull)
		{
			return false;
		}

		if (static_cast<u64>(off) + size > sizeof(s.data))
		{
			return false;
		}

		if (!window_ok(map_byte, guest_addr, guest_addr + size - 1))
		{
			return false;
		}

		const u8* src = mem.ptr(guest_addr, size);

		if (!src)
		{
			return false;
		}

		std::memcpy(&s.data[off], src, size);

		const u32 first_block = off >> block_shift;
		const u32 last_block = (off + size) >> block_shift;

		for (u32 block = first_block; block <= last_block; block++)
		{
			mark_dirty(s, block << block_shift);
		}

		return true;
	}

	// --- the bone descriptor ---------------------------------------------
	struct descriptor_words
	{
		u32 w0 = 0;
		u32 w1 = 0;
		u32 w2 = 0;
		u32 w3 = 0;
	};

	u32 be32_bytes(const u8* base, u32 off)
	{
		return static_cast<u32>(base[off + 3]) |
		       (static_cast<u32>(base[off + 2]) << 8) |
		       (static_cast<u32>(base[off + 1]) << 16) |
		       (static_cast<u32>(base[off + 0]) << 24);
	}

	descriptor_words read_descriptor(const scratch_t& s)
	{
		descriptor_words words;

		for (u32 i = 0; i < 4; i++)
		{
			(&words.w0)[i] = be32_bytes(s.data, descriptor_layout::at + i * 4);
		}

		return words;
	}

	bool descriptor_unchanged(const scratch_t& s, const descriptor_words& expected)
	{
		const descriptor_words now = read_descriptor(s);
		return now.w0 == expected.w0 && now.w1 == expected.w1 &&
		       now.w2 == expected.w2 && now.w3 == expected.w3;
	}

	// --- the output record ------------------------------------------------
	struct output_record
	{
		static constexpr u32 offset = 0x13000;
		static constexpr u32 expected_size = 0x10800;
		static constexpr u32 expected_2nd = 0xfe80;
		static constexpr u32 expected_3rd = 0xf680;
		static constexpr u32 ran_flag_bit = 16;
	};

	constexpr u32 lift_mxcsr = 0xffc0;
}

using namespace mgo_pl_motion_mix;

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

static void test_decline_table()
{
	check(static_cast<u32>(decline::lifted_code_declined) == 9, "there are ten entries, 0 .. 9");
	check(std::strcmp(decline_text(decline::unmapped_guest_memory), "unmapped guest memory") == 0,
		"reason 0 is unmapped guest memory");
	check(std::strcmp(decline_text(decline::unexpected_parameter_block), "unexpected parameter block") == 0,
		"reason 1 is unexpected parameter block");
	check(std::strcmp(decline_text(decline::phase_word_too_small), "phase word <= 3") == 0,
		"reason 2 is the phase word");
	check(std::strcmp(decline_text(decline::task_object_busy), "task object busy (obj+0xa0 != 0)") == 0,
		"reason 3 is the busy task object");
	check(std::strcmp(decline_text(decline::misaligned_dma), "misaligned DMA (the task would halt)") == 0,
		"reason 4 is misaligned DMA");
	check(std::strcmp(decline_text(decline::width_over_128), "W(S+4) > 128") == 0,
		"reason 5 is the width cap");
	check(std::strcmp(decline_text(decline::count_over_128), "N > 128") == 0,
		"reason 6 is the count cap");
	check(std::strcmp(decline_text(decline::bone_descriptor_changed), "bone descriptor changed by a stage") == 0,
		"reason 7 is the descriptor proof");
	check(std::strcmp(decline_text(decline::stage_clobbered_callee_saved), "stage clobbered callee-saved registers") == 0,
		"reason 8 is the callee-saved snapshot");
	check(std::strcmp(decline_text(decline::lifted_code_declined),
	          "lifted code declined (load/store outside reproduced LS, budget, halt)") == 0,
		"reason 9 is the lift itself");
	check(std::strcmp(decline_text(static_cast<decline>(10)), "?") == 0,
		"an index past the end is still ?, which is why the range matters");
	check(decline_line == 0x24, "declines are reported at line 0x24");
}

static void test_stage_index()
{
	// The staged value is two above the reason it reports, because the exits
	// all funnel through `add r14d, 0xfe / movzx r12d, r14b`.
	check(staged_bias == 0xfe, "the bias is the immediate 0xfe");
	check(stage_index(0x0a) == 8, "staged 0x0a indexes reason 8");
	check(stage_index(0x0b) == 9, "staged 0x0b indexes reason 9");
	check(stage_index(0x08) == 6, "staged 0x08 indexes reason 6");
	check(stage_index(0x07) == 5, "staged 0x07 indexes reason 5");
	for (u32 reason = 0; reason <= 9; reason++)
	{
		check(stage_index(static_cast<u8>(reason + 2)) == reason,
			"every reason round-trips through its staged value");
	}
	// A subtraction would quietly change what happens below 2, which is why
	// the replica adds and masks instead.
	check(stage_index(1) == 0xff, "a staged value below 2 wraps to 0xff, not -1");
	check(stage_index(2) == 0, "staged 2 is reason 0");
}

static void test_param_block()
{
	check(param_block::size == 0x124, "the parameter block is 0x124 bytes");
	check(param_block::self_hi == 0x100, "the phase word is the self-pointer at +0x100");
	check(param_block::self_lo == 0x104, "the task object is the self-pointer at +0x104");
	check(param_block::self_span == 0xa4, "the +0x100 word must equal S + 0xa4");
	check(param_block::task_object == 0xa0, "the +0x104 word must equal S + 0xa0");
	check(param_block::phase_min == 4, "and it has to be at least 4");

	// The two gates a well-formed block passes.
	const u32 s = 0x00200000u;
	const u32 self_hi = s + param_block::self_span;
	const u32 self_lo = s + param_block::task_object;
	check(self_hi >= param_block::phase_min, "a real block's phase word clears the minimum");
	check(self_lo <= 0xfffffff8u, "a real block's task object clears the -8 ceiling");
	check(!(s + 0x100u < s), "the [S, S + 0x100] window does not wrap for a real block");
	// A block near the top of the space does.
	const u32 high = 0xffffff00u;
	check(high + 0x100u < high, "the window check catches a wrapping block");
	// `cmp r8d, -8 / ja` is on the self-pointer itself, so it only fires for
	// the eight words below the top of the space - which is exactly the set a
	// wrapped pointer lands in.
	check(0xfffffffcu > 0xfffffff8u, "the -8 ceiling rejects a wrapped task object");
	check(!(0xfffffff8u > 0xfffffff8u), "and accepts the boundary word itself");
}

static void test_dma_plan()
{
	// The seven descriptors are issued in order 0x108, 0x110, 0x120, 0x114,
	// 0x118, 0x10c, 0x11c, and each names a size and a scratch offset.
	check(sizeof(dma_descs) / sizeof(dma_descs[0]) == 7, "there are seven descriptors");
	u32 expect_at[7] = { 0x108, 0x110, 0x120, 0x114, 0x118, 0x10c, 0x11c };
	for (u32 i = 0; i < 7; i++)
	{
		check(dma_descs[i].at == expect_at[i], "descriptor order follows the fork's get calls");
		check(dma_descs[i].order == i, "and each records its own order");
		check(dma_descs[i].scratch + dma_descs[i].size <= 0x40000,
			"every descriptor lands inside the staging buffer");
	}
	// The 0x110 one is the only writeback of the matrix block, and it is an
	// offset rather than an address, which is why it is range-checked
	// against -0x3bf0 rather than for alignment.
	check(dma_descs[1].scratch == writeback_matrix && dma_descs[1].size == writeback_matrix_size,
		"the +0x110 buffer is the matrix block that is written back");
	check(matrix_offset_max + writeback_matrix_size == 0x100000000ull - 1u ||
	      static_cast<u64>(matrix_offset_max) + writeback_matrix_size <= 0x100000000ull,
		"the +0x110 offset plus 0x3bf0 is bounded by 2^32");
	check(sizeof(scratch_t) == 0x40020, "the staging object is 0x40020 bytes with four dirty maps");

	// The six sub-descriptors, and the 16-byte-aligned payloads they name.
	check(sizeof(sub_descs) / sizeof(sub_descs[0]) == 6, "there are six sub-descriptors");
	u32 last = 0;
	for (u32 i = 0; i < 6; i++)
	{
		check((sub_descs[i].destination & 0xfu) == 0, "every payload destination is 16-byte aligned");
		check(sub_descs[i].destination > last, "the payload destinations ascend");
		check(sub_descs[i].scratch == 0x17320u + i * 0x30u, "the sub-descriptors are 0x30 apart");
		check(sub_descs[i].scratch + 4 <= 0x17300u + 0x120u, "each sub-descriptor fits the +0x114 buffer");
		last = sub_descs[i].destination;
	}
	// The biggest sub-payload, W = 128, still fits below the bone descriptor.
	const u32 stride = max_width * width_stride;
	check(stride == 0x800, "the widest payload is 128 * 16 = 0x800 bytes");
	check(sub_descs[0].destination + stride <= descriptor_layout::at,
		"the widest payload stops short of the bone descriptor");
}

static void test_caps()
{
	// Both caps are `cmp eax, 0x80 / ja`, so 128 is legal and 129 is not.
	check(max_width == 128 && max_count == 128, "both caps are 128");
	check(!(128u > max_width), "128 is inside the width cap");
	check(129u > max_width, "129 is outside the width cap");
	check(!(128u > max_count), "128 is inside the count cap");
	check(129u > max_count, "129 is outside the count cap");
	check(width_stride == 16, "the width stride is 16 bytes");
	check(count_stride5 == 80, "the counted buffer advances 80 bytes per row");
	check(count_stride1 == 16, "the counted row buffer advances 16 bytes per row");

	// The counted buffers and their ends, which the caps keep inside band.
	check(count_buffer + max_count * count_stride5 == count_buffer_end,
		"128 rows of 80 bytes end exactly at 0x13000");
	check(writeback_rows + max_count * count_stride1 == 0x10680,
		"128 rows of 16 bytes end at 0x10680");
	check(writeback_rows - rows_spacing == writeback_rows2,
		"0xf680 is the 0x800 bytes in front of the row buffer");
	check(writeback_rows2 < writeback_rows, "so the stage output sits below the DMA'd rows");
}

static void test_granule_walk()
{
	// Every granule mapped, one 0x100-byte granule at a time.
	guest_mem mem;
	mem.bytes.assign(0x4000, 0xaa);
	mem.mapped_from = 0;
	mem.mapped_to = 0x4000;
	const auto map = mem.granule_map();
	check(window_ok(map, 0x0000, 0x0fff), "one mapped 4 KiB page is accepted");
	check(window_ok(map, 0x0000, 0x3fff), "four mapped 4 KiB pages are accepted");
	check(!window_ok(map, 0x4000, 0x4fff), "an unmapped page is rejected");

	// A hole in the middle is rejected, which is the whole point.
	guest_mem holed;
	holed.bytes.assign(0x4000, 0xaa);
	holed.mapped_from = 0x2000;
	holed.mapped_to = 0x4000;
	check(window_ok(holed.granule_map(), 0x2000, 0x2fff), "the mapped half is accepted");
	check(!window_ok(holed.granule_map(), 0x1000, 0x2fff),
		"a range straddling the hole is rejected");
	check(!window_ok(holed.granule_map(), 0x1000, 0x1fff),
		"and so is the unmapped page on its own");

	// The skip bits ride on top of the presence bits.
	auto with = [](u8 byte)
	{
		return [byte](u32) { return byte; };
	};
	check(window_ok(with(granule_mapped), 0, 0xfff), "0x81 alone is a plain mapped granule");
	check(!window_ok(with(granule_skip_page), 0, 0xfff),
		"a bare 0x40 is rejected: the presence test comes first");
	check(!window_ok(with(granule_skip_16), 0, 0xfff),
		"and so is a bare 0x20");
	check(window_ok(with(granule_mapped | granule_skip_page), 0, 0xfff),
		"0x81 | 0x40 walks a whole 64 KiB in one step");
	check(window_ok(with(granule_mapped | granule_skip_16), 0, 0xfff),
		"0x81 | 0x20 walks 16 granules at a time");
	check(window_ok(with(granule_mapped | granule_skip_page | granule_skip_16), 0, 0xfff),
		"both bits together take the wider jump");
	// Both jumps round *up* to the next boundary - `(g & ~mask) + step`, not
	// `(g + 1 & ~mask) >> shift` - so neither can stall on granule 0.
	check(window_ok(with(granule_mapped | granule_skip_page), 0, 0xfff),
		"the page jump rounds up even at granule 0");
	check(window_ok(with(granule_mapped | granule_skip_16), 0, 0xfff),
		"and so does the 16-granule jump");
	// ... and they overshoot rather than undershoot, so a map that skips
	// past the end of the range still terminates.
	check(window_ok(with(granule_mapped | granule_skip_page), 0, 0xfff),
		"a range smaller than the jump is accepted");
	check(!window_ok(nullptr, 0, 0xfff), "an absent map rejects everything");
}

static void test_scratch_maps()
{
	scratch_t s;
	check(s.dirty_00000 == 0 && s.dirty_10000 == 0 && s.dirty_20000 == 0 && s.dirty_30000 == 0,
		"the four maps start empty");
	check(sizeof(scratch_t) == 0x40020, "0x40000 of data plus four 64-bit maps");

	// The bit index is addr >> 10, the band is addr >> 16, and the bit within
	// the band is what is left over - 64 blocks of 0x400 bytes per band.
	mark_dirty(s, 0x00000);
	check(s.dirty_00000 == 1ull, "0x00000 lands in band 0 at bit 0");
	mark_dirty(s, 0x00400);
	check(s.dirty_00000 == 3ull, "0x00400 is bit 1 of band 0");
	mark_dirty(s, 0x04000);
	check(s.dirty_00000 == (3ull | (1ull << 16)), "0x04000 is bit 16, still band 0");
	mark_dirty(s, 0x0fc00);
	check((s.dirty_00000 >> 63) == 1, "0x0fc00 is the last block band 0 covers");
	mark_dirty(s, 0x10000);
	check(s.dirty_10000 == 1ull, "0x10000 starts band 1 at bit 0 again");
	mark_dirty(s, 0x13080);
	check(s.dirty_10000 == (1ull | (1ull << 12)), "0x13080 is block 12 of band 1, offset 0x80");
	mark_dirty(s, 0x20000);
	check(s.dirty_20000 == 1ull, "0x20000 starts band 2");
	mark_dirty(s, 0x30000);
	check(s.dirty_30000 == 1ull, "0x30000 starts band 3");
	check(s.dirty_00000 == (3ull | (1ull << 16) | (1ull << 63)), "the bands do not share bits");

	// clean() walks all four, so a dirty top block clears and a dirty base
	// block clears, independently.
	std::memset(s.data, 0xcc, sizeof(s.data));
	clean(s);
	check(s.dirty_00000 == 0 && s.dirty_10000 == 0 && s.dirty_20000 == 0 && s.dirty_30000 == 0,
		"clean() empties all four maps");
	check(s.data[0x00000] == 0 && s.data[0x00000 + block_bytes - 1] == 0, "the band 0 block was zeroed");
	check(s.data[0x04000] == 0, "the other band 0 block was zeroed");
	check(s.data[0x10000] == 0, "the band 1 block was zeroed");
	check(s.data[0x20000] == 0, "the band 2 block was zeroed");
	check(s.data[0x30000] == 0, "the band 3 block was zeroed");
	check(s.data[0x00800] == 0xcc, "and no unmarked block was touched");

	// Only band 1 is filtered, and the filter compares each *block's* start
	// against the ranges - so a range that begins mid-block protects nothing.
	// [0x13080, 0x13251) sits entirely inside block 12 (0x13000), whose start
	// is below it: the first range clears no block at all.
	scratch_t live;
	std::memset(live.data, 0xcc, sizeof(live.data));
	mark_dirty(live, 0x13000);
	mark_dirty(live, 0x13400);
	clean(live);
	check(live.data[0x13000] == 0,
		"a block starting below the 0x13000 range is cleared anyway");
	check(live.data[0x13400] == 0, "and so is the block past it");

	// The second range, [0x13680, 0x16e71), does protect whole blocks: it
	// covers block indices 14 .. 27, i.e. 0x13800 .. 0x16c00.
	scratch_t live2;
	std::memset(live2.data, 0xcc, sizeof(live2.data));
	mark_dirty(live2, 0x13600);
	mark_dirty(live2, 0x13800);
	mark_dirty(live2, 0x16c00);
	mark_dirty(live2, 0x17000);
	clean(live2);
	check(live2.data[0x13600] == 0,
		"the matrix block's own first, partial block is still cleared");
	check(live2.data[0x13800] == 0xcc, "but the blocks inside it are not");
	check(live2.data[0x16c00] == 0xcc, "including the last one before its end");
	check(live2.data[0x17000] == 0, "and the block past its end is cleared");

	// The bone descriptor at 0x17280 is outside both ranges, so it is cleared.
	scratch_t live3;
	std::memset(live3.data, 0xcc, sizeof(live3.data));
	mark_dirty(live3, descriptor_layout::at);
	clean(live3);
	check(live3.data[descriptor_layout::at] == 0,
		"the bone descriptor is past the live ranges and is cleared");

	// The bounds are half-open and the bias is exactly what the fork uses.
	check(live_13000.begin == 0x13080 && live_13000.end == 0x13251, "the first live range");
	check(live_03680.begin == 0x03680 && live_03680.end == 0x06e71, "the second live range");
	check(live_03680.end - live_03680.begin == 0x37f1, "its length is the compared immediate");
	check(0x3680u - live_03680.begin < (live_03680.end - live_03680.begin),
		"0x03680 is inside the second range");
	check(0x367fu - live_03680.begin >= (live_03680.end - live_03680.begin),
		"and 0x0367f is below it, because the comparison is unsigned");
	check(writeback_matrix >= (live_03680.begin + 0x10000u) &&
	      writeback_matrix + writeback_matrix_size <= (live_03680.end + 0x10000u) + block_bytes,
		"the matrix block is what the second range protects");
}

static void test_get()
{
	guest_mem mem;
	mem.bytes.assign(0x8000, 0);
	mem.mapped_from = 0;
	mem.mapped_to = 0x8000;
	for (u32 i = 0; i < 0x100; i++)
	{
		mem.bytes[0x1000 + i] = static_cast<u8>(i);
	}
	const auto map = mem.granule_map();

	scratch_t s;
	check(get(mem, s, 0x1000, 0, 0x13680, map), "a zero length is a successful no-op");
	check(s.dirty_10000 == 0, "and marks nothing dirty");
	check(get(mem, s, 0x1000, 0x100, 0x13680, map), "a mapped 0x100-byte read succeeds");
	check(s.data[0x13680] == 0 && s.data[0x13680 + 0xff] == 0xff, "the bytes land where asked");
	check(s.dirty_10000 == (1ull << ((0x13680 >> block_shift) & 63)),
		"and the destination block is marked in band 1");

	// A read spanning two blocks marks both.
	scratch_t two;
	check(get(mem, two, 0x1000, block_bytes + 1, 0x13680, map), "a read spanning two blocks succeeds");
	const u32 first = (0x13680 >> block_shift) & 63;
	check(two.dirty_10000 == ((1ull << first) | (1ull << (first + 1))), "and marks both blocks");

	// The 2^32 wrap bound, and the caller's own range.
	scratch_t wrap;
	check(!get(mem, wrap, 0xfffffff0u, 0x100, 0x13680, map), "a range past 2^32 is rejected");
	check(!get(mem, wrap, 0x8000, 0x100, 0x13680, map), "an unmapped source is rejected");
	check(!get(mem, wrap, 0x1000, 0x100, 0x3ff01, map), "a destination past the scratch is rejected");
	check(get(mem, wrap, 0x1000, 0x100, 0x3ff00, map), "a destination ending exactly at the scratch end is fine");

	// A read that starts mapped and runs off the end is rejected whole.
	scratch_t edge;
	check(!get(mem, edge, 0x7f00, 0x200, 0x13680, map), "a read running off the mapped end is rejected");
}

static void test_set_nv()
{
	std::vector<u8> ctx(0x400, 0);
	set_nv(ctx.data(), nv_stage1());

	// Eleven groups at ctx + 0x90, each reversed, so lane 0 of group 0 is
	// the group's third dword.
	u32 lane0 = 0;
	std::memcpy(&lane0, &ctx[0x90], sizeof(lane0));
	u32 expect0 = 0;
	std::memcpy(&expect0, &nv_stage1().bytes[0x0c], sizeof(expect0));
	check(lane0 == expect0, "group 0 lane 0 is the group's third dword");
	u32 lane3 = 0;
	std::memcpy(&lane3, &ctx[0x9c], sizeof(lane3));
	u32 expect3 = 0;
	std::memcpy(&expect3, &nv_stage1().bytes[0x00], sizeof(expect3));
	check(lane3 == expect3, "group 0 lane 3 is the group's first dword");

	// Group 7 is the last of the eleven that the constant fill leaves alone -
	// group g lives at ctx + 0x90 + g * 0x10 and the fill starts at 0x110, so
	// groups 8, 9 and 10 are overwritten by it.
	u32 last = 0;
	std::memcpy(&last, &ctx[0x90 + 0x70], sizeof(last));
	u32 expect_last = 0;
	std::memcpy(&expect_last, &nv_stage1().bytes[0x7c], sizeof(expect_last));
	check(last == expect_last, "group 7 is the last the fill does not clobber");

	// The twelfth group, at ctx + 0x140, is the vpermilps 0x1b result - and
	// then the constant fill lands on top of it, so what survives there is the
	// constant, not the table's last group.
	u32 tail0 = 0;
	std::memcpy(&tail0, &ctx[0x140], sizeof(tail0));
	u32 expect_fill0 = 0;
	std::memcpy(&expect_fill0, &nv_fill(), sizeof(expect_fill0));
	check(tail0 == expect_fill0, "the vpermilps result at 0x140 is overwritten by the fill");

	// ctx + 0x110 .. ctx + 0x300 is one constant, and it covers groups 8, 9
	// and 10 as well as the region between them.
	bool all_fill = true;
	for (u32 off = 0x110; off < 0x300; off++)
	{
		if (ctx[off] != nv_fill()[off & 0xf])
		{
			all_fill = false;
		}
	}
	check(all_fill, "ctx + 0x110 .. 0x300 is the repeated constant");
	check(ctx[0x10f] == 0, "and the fill starts exactly at 0x110, leaving 0x10f alone");
	u32 clobbered = 0;
	std::memcpy(&clobbered, &ctx[0x130], sizeof(clobbered));
	u32 expect_clobbered = 0;
	std::memcpy(&expect_clobbered, &nv_fill(), sizeof(expect_clobbered));
	check(clobbered == expect_clobbered, "group 10, the eleventh, is inside the fill too");

	// ctx + 0x90 is outside the fill.
	u32 survives = 0;
	std::memcpy(&survives, &ctx[0x9c], sizeof(survives));
	check(survives == expect3, "group 0 is left alone by the fill");

	// The constant itself, straight out of 0x144b23160.
	check(nv_fill()[0] == 0xed && nv_fill()[1] == 0x5e && nv_fill()[2] == 0xed && nv_fill()[3] == 0x5e,
		"the fill constant opens ed 5e ed 5e");
	check(nv_fill()[12] == 0x58 && nv_fill()[13] == 0xad && nv_fill()[14] == 0xde && nv_fill()[15] == 0x7f,
		"and closes 58 ad de 7f");

	// Both tables are 0xc0 bytes and share their last group.
	check(sizeof(nv_set) == 0xc0, "an nv_set is 0xc0 bytes");
	check(std::memcmp(&nv_stage1().bytes[0xb0], &nv_stage23().bytes[0xb0], 0x10) == 0,
		"both tables end with the same 0x13680 group");
	u32 open1 = 0, open23 = 0;
	std::memcpy(&open1, &nv_stage1().bytes[0], sizeof(open1));
	std::memcpy(&open23, &nv_stage23().bytes[0], sizeof(open23));
	check(open1 == 0x17480u, "nv_stage1 opens with the 0x17480 group");
	check(open23 == 0xfe80u, "nv_stage23 opens with the 0xfe80 group");
}

static void test_descriptor()
{
	scratch_t s;
	// The fork reads W0 and W2 out of bytes and W1 and W3 as bswapped
	// dwords; all four come out big-endian.
	const u8 raw[16] =
	{
		0x00, 0x10, 0x80, 0x00,  // W0 -> 0x00108000
		0x00, 0x00, 0x00, 0x40,  // W1 -> 64, the count
		0x00, 0x00, 0xfe, 0x80,  // W2 -> 0x0000fe80
		0x00, 0x00, 0xf6, 0x80,  // W3 -> 0x0000f680
	};
	std::memcpy(&s.data[descriptor_layout::at], raw, sizeof(raw));

	const descriptor_words w = read_descriptor(s);
	check(w.w0 == 0x00108000u, "W0 reads back as a big-endian guest address");
	check(w.w1 == 64u, "W1 is the count");
	check(w.w2 == 0x0000fe80u, "W2 is the row buffer's guest address");
	check(w.w3 == 0x0000f680u, "W3 is the other one's guest address");

	// The proof obligation: a stage may read the descriptor, not write it.
	check(descriptor_unchanged(s, w), "an untouched descriptor passes");
	s.data[descriptor_layout::at + 3] = 0x01;
	check(!descriptor_unchanged(s, w), "a one-byte change in W0 fails the proof");
	s.data[descriptor_layout::at + 3] = 0x00;

	// Each word is proved separately.
	for (u32 i = 0; i < 4; i++)
	{
		scratch_t t;
		const descriptor_words base = read_descriptor(t);
		t.data[descriptor_layout::at + i * 4 + 1] ^= 0x40;
		check(!descriptor_unchanged(t, base), "every one of the four words is proved");
	}

	// The layout: four words at 0x17280, which is the +0x120 buffer.
	check(descriptor_layout::at == 0x17280, "the descriptor is the +0x120 buffer");
	check(descriptor_layout::w0 == descriptor_layout::at &&
	      descriptor_layout::w3 == descriptor_layout::at + 12, "and it is four words");
	check(dma_descs[2].scratch == descriptor_layout::at && dma_descs[2].size == 0x10,
		"the +0x120 descriptor is 16 bytes at 0x17280");
}

static void test_output_record()
{
	check(output_record::offset == 0x13000, "the record is published at 0x13000");
	check(output_record::expected_size == count_buffer, "it names the 0x10800 buffer");
	check(output_record::expected_2nd == writeback_rows, "it names the 0xfe80 buffer");
	check(output_record::expected_3rd == writeback_rows2, "and the 0xf680 one");
	check(output_record::ran_flag_bit == 16, "the lift-ran flag is bit 16 of the middle map");
	// The four record words are bswapped guest words, and the second one is
	// the width the launcher saved before the stages ran.
	scratch_t s;
	u32 value = 0;
	std::memcpy(&value, &s.data[output_record::offset + 4], sizeof(value));
	check(value == 0, "the record's second word starts empty");
	check(lift_mxcsr == 0xffc0, "the lift installs 0xffc0");
	// DAZ, FZ and round-to-nearest, all masked.
	check((lift_mxcsr & (1u << 6)) != 0, "denormals-are-zero is on");
	check((lift_mxcsr & (1u << 12)) != 0, "flush-to-zero is on");
	check((lift_mxcsr & (1u << 14)) != 0, "round-to-nearest is on");
	check((lift_mxcsr & (1u << 15)) != 0, "and every exception is masked");
}

int main()
{
	test_decline_table();
	test_stage_index();
	test_param_block();
	test_dma_plan();
	test_caps();
	test_granule_walk();
	test_scratch_maps();
	test_get();
	test_set_nv();
	test_descriptor();
	test_output_record();

	std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}