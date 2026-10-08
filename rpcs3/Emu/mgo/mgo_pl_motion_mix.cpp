#include "stdafx.h"
#include "mgo_pl_motion_mix.h"

#include "util/logs.hpp"

#include <cstring>
#include <memory>

// The fork's own channel for this subsystem.
LOG_CHANNEL(ppu_pl_motion_mix, "ppu.pl_motion_mix");

namespace mgo_pl_motion_mix
{
	// The reproduced-LS granule map. The fork maintains its own allocation map
	// with one byte per 0x1000 of local store - the walk indexes it with
	// `address >> 12` (0x143a1ac8b) - and the replica answers the same question
	// from the VM, so the walk below is the fork's but the byte comes from
	// guest_valid instead of a side table.
	inline constexpr u8 granule_mapped = 0x81;
	inline constexpr u8 granule_skip_page = 0x40;
	inline constexpr u8 granule_skip_16 = 0x20;
	inline constexpr u32 granule_bytes = 0x1000;
}

namespace
{
	using namespace spu_task_hle::ppu;
	using mgo_pl_motion_mix::granule_bytes;
	using mgo_pl_motion_mix::granule_mapped;
	using mgo_pl_motion_mix::granule_skip_16;
	using mgo_pl_motion_mix::granule_skip_page;

	u32 swap32(u32 v)
	{
		return (v >> 24) | ((v >> 8) & 0x0000ff00u) | ((v << 8) & 0x00ff0000u) | (v << 24);
	}

	std::function<u8(u32)> granule_map(direct_mem& mem)
	{
		return [&mem](u32 granule) -> u8
		{
			const u32 addr = granule * granule_bytes;
			return mem.guest_valid(addr, 4) ? granule_mapped : u8(0);
		};
	}

	// A raw big-endian dword. Used for the two parameter-block self-pointers,
	// which the fork compares *without* a byte swap because they are the guest's
	// own pointers being compared with the guest's own arithmetic.
	bool load_raw32(direct_mem& mem, u32 addr, u32& out)
	{
		const u8* ptr = mem.guest_ptr(addr, sizeof(u32));
		if (!ptr)
		{
			return false;
		}

		std::memcpy(&out, ptr, sizeof(out));
		return true;
	}

	bool load_be32(direct_mem& mem, u32 addr, u32& out)
	{
		const u8* ptr = mem.guest_ptr(addr, sizeof(u32));
		if (!ptr)
		{
			return false;
		}

		std::memcpy(&out, ptr, sizeof(out));
		out = swap32(out);
		return true;
	}

	// The per-thread staging buffer. The fork keeps it at thread + 0x608 behind
	// a byte at thread + 0x130 (0x143a1aa68). It is 0x40040 bytes and there is
	// no reason to have more than one.
	std::unique_ptr<mgo_pl_motion_mix::scratch_t> s_scratch;

	// The fork's own instrumented lift. Every entry point from here on -
	// mgo_pl_motion_mix_lift::{pm_082c0, pm_0a7a8, pm_04780} and
	// mgo_pl_motion_mix::run_launch - is compiled native code the fork lifted
	// from a guest function by offset, and nothing but the name survives in the
	// symbol table. Approximating it would mean inventing bone matrices and
	// writing them into guest memory, so the replica reports the fork's own
	// reason for a lift that cannot run and lets the guest blend for itself.
	bool stage_not_built(mgo_pl_motion_mix::stage which)
	{
		const char* name = which == mgo_pl_motion_mix::stage::one ? "pm_082c0"
		                    : which == mgo_pl_motion_mix::stage::two ? "pm_0a7a8"
		                                                             : "pm_04780";
		ppu_pl_motion_mix.trace("MGO: ppu.pl_motion_mix declined: %s is not built in this replica", name);
		return false;
	}
}

namespace mgo_pl_motion_mix
{
	// -----------------------------------------------------------------------
	// Decline reasons
	// -----------------------------------------------------------------------

	std::string_view decline_text(decline reason)
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

	// -----------------------------------------------------------------------
	// The granule walk
	// -----------------------------------------------------------------------

	bool window_ok(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi)
	{
		if (!map_byte)
		{
			return false;
		}

		for (u32 granule = lo >> 12; granule <= (hi >> 12);)
		{
			const u8 byte = map_byte(granule);

			// The presence test comes first, so a skip bit has to ride on top
			// of 0x81 - a bare 0x40 is rejected before its skip is read.
			if ((~byte) & 0x81)
			{
				return false;
			}

			if (byte & granule_skip_page)
			{
				// 0x143a1acf0  and  r10d, 0xffffff00
				// 0x143a1acf7  add  r10d, 0x100
				granule = (granule & ~0xffu) + 0x100u;
				continue;
			}

			if (byte & granule_skip_16)
			{
				// 0x143a1ad30  and  r10d, 0xfffffff0
				// 0x143a1ad34  add  r10d, 0x10
				granule = (granule & ~0xfu) + 0x10u;
				continue;
			}

			granule++;
		}

		return true;
	}

	// -----------------------------------------------------------------------
	// scratch_t
	// -----------------------------------------------------------------------

	scratch_t& scratch()
	{
		if (!s_scratch)
		{
			// 0x143a279b5: operator new(0x40040, align 0x40), then
			// memset(scratch, 0, 0x40020).
			s_scratch = std::make_unique<scratch_t>();
		}

		return *s_scratch;
	}

	void mark_dirty(scratch_t& s, u32 addr)
	{
		// The bit index is the address shifted down past a block, the qword
		// index is that shifted down past 64 bits, and the bit within the
		// qword is what is left:
		//
		//   0x143a1acc2  shr  ecx, 0xa          ; the block
		//   0x143a1ad4b  shl  rdx, cl           ; ... its bit (cl is masked to 6)
		//   0x143a1ad4e  shr  r9d, 0x10         ; ... and its band
		//   0x143a1ad52  or   [rsi + r9*8 + 0x40000], rdx
		//
		// so the four maps are indexed by addr >> 16 and each covers 0x10000
		// bytes of the staging buffer.
		const u32 bit = addr >> block_shift;

		(&s.dirty_00000)[addr >> band_shift] |= 1ull << (bit & 63);
	}

	void clean(scratch_t& s)
	{
		// 0x143a1aad0, complete. Each map is walked one set bit at a time and
		// each bit clears one 0x400-byte block:
		//
		//   mov  rbx, rdi
		//   tzcnt rcx, rbx
		//   shl  ecx, 0xa
		//   add  ecx, rsi
		//   mov  r8d, 0x400 / xor edx, edx / call memset
		//   and  rdi, rbx
		//   jne  <next bit>
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
					// The two live ranges the fork refuses to clear:
					//
					//   0x143a1ac19  or   eax, 0x10000
					//   0x143a1ac1e  cmp  eax, 0x13080  / jb  clear
					//   0x143a1ac25  cmp  eax, 0x13251  / setb
					//   0x143a1ac2d  add  ecx, 0xffffc980
					//   0x143a1ac33  cmp  ecx, 0x37f1   / setb
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

	bool get(direct_mem& mem, scratch_t& s, u32 guest_addr, u32 size, u32 off,
	         const std::function<u8(u32 granule)>& map_byte)
	{
		// 0x143a1ac50. A zero length is a successful no-op:
		//
		//   0x143a1ac57  mov  al, 1
		//   0x143a1ac59  test r9d, r9d
		//   0x143a1ac5c  je   <return>
		if (size == 0)
		{
			return true;
		}

		// 0x143a1ac72: `movabs r11, 0x100000000 / cmp rcx, r11 / jbe ok`.
		if (static_cast<u64>(guest_addr) + size > 0x100000000ull)
		{
			return false;
		}

		if (static_cast<u64>(off) + size > sizeof(s.data))
		{
			return false;
		}

		// 0x143a1ac88: the page walk over the source range.
		if (!window_ok(map_byte, guest_addr, guest_addr + size - 1))
		{
			return false;
		}

		// 0x143a1aca4: `add rax, [rip + ...]` - the fork adds the guest base
		// to the address and calls memcpy directly, with no per-page bounce
		// buffer, because the range was just proved contiguous.
		const u8* src = mem.guest_ptr(guest_addr, size);

		if (!src)
		{
			return false;
		}

		std::memcpy(&s.data[off], src, size);

		// 0x143a1acbf onwards: mark every 0x400 block the destination range
		// touches, `first = off >> 10` through `last = (off + size) >> 10`.
		// The fork only marks `first` when `(first + last)` is even
		// (0x143a1ad3a / 0x143a1ad40) and the path that skips it starts its
		// loop from an unwritten register; the condition's purpose is not
		// identifiable, so the replica marks the whole range, which can only
		// ever clear more.
		const u32 first_block = off >> block_shift;
		const u32 last_block = (off + size) >> block_shift;

		for (u32 block = first_block; block <= last_block; block++)
		{
			mark_dirty(s, block << block_shift);
		}

		return true;
	}

	// -----------------------------------------------------------------------
	// nv_set
	// -----------------------------------------------------------------------

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
		// 0x144b23160, the `vmovaps xmm0, [rip + 0x11081fd]` constant set_nv
		// writes over ctx + 0x110 .. ctx + 0x300.
		static const std::array<u8, 16> fill =
		{
			0xed, 0x5e, 0xed, 0x5e, 0x5a, 0x5a, 0x5a, 0x5a,
			0x58, 0x00, 0x00, 0x00, 0x58, 0xad, 0xde, 0x7f,
		};
		return fill;
	}

	void set_nv(u8* ctx, const nv_set& set)
	{
		// 0x143a1adb0, complete. Eleven groups of sixteen bytes, each read as
		// four u32s starting at `group*0x10 + 0xc` - an unaligned load four
		// bytes into the group - and stored forwards from ctx + 0x90.
		//
		// `vmovdqu xmm0, [rdx + 0xc] / vpinsrd xmm0, xmm0, [rdx + 8], 1 /
		//  vpinsrd xmm0, xmm0, [rdx + 4], 2 / vpinsrd xmm0, xmm0, [rdx], 3`
		//
		// reads dwords +0xc, +8, +4, +0 into lanes 0..3, so lane 0 is
		// dword[3], lane 1 is dword[2] and so on: the four words come out
		// reversed. Reproduced as a reverse per group.
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

		// 0x143a1af49: `vpermilps xmm0, xmmword ptr [rdx + 0xb0], 0x1b` into
		// ctx + 0x140. 0x1b reverses the four lanes, so this is dwords
		// 3, 2, 1, 0 again.
		u32* tail = reinterpret_cast<u32*>(ctx + 0x140);

		for (u32 lane = 0; lane < 4; lane++)
		{
			u32 word = 0;
			std::memcpy(&word, &set.bytes[0xb0 + (3 - lane) * 4], sizeof(word));
			tail[lane] = word;
		}

		// 0x143a1af63 onwards: ctx + 0x110 .. ctx + 0x300 with one constant.
		const std::array<u8, 16>& fill = nv_fill();

		for (u32 off = 0x110; off < 0x300; off += 16)
		{
			std::memcpy(ctx + off, fill.data(), fill.size());
		}
	}

	// -----------------------------------------------------------------------
	// The stages
	// -----------------------------------------------------------------------

	namespace
	{
		// A big-endian word assembled out of four separate byte loads, which is
		// how the fork reads every field of the staged buffers:
		//
		//   movzx eax, byte ptr [rdi + N + 3]
		//   movzx edx, byte ptr [rdi + N + 2] / shl edx, 8
		//   mov  ecx, dword ptr [rdi + N]    / shl ecx, 0x18
		//   or   ...
		u32 be32_bytes(const u8* base, u32 off)
		{
			return static_cast<u32>(base[off + 3]) |
			       (static_cast<u32>(base[off + 2]) << 8) |
			       (static_cast<u32>(base[off + 1]) << 16) |
			       (static_cast<u32>(base[off + 0]) << 24);
		}
	}

	descriptor_words read_descriptor(const scratch_t& s)
	{
		// All four are byte-swapped dwords in the replica's model. The fork
		// reads two of them that way and assembles the other two from bytes;
		// both spellings produce the same big-endian value once the buffer is
		// interpreted as a guest buffer, so one loader serves all four.
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

	// -----------------------------------------------------------------------
	// The launcher
	// -----------------------------------------------------------------------

	namespace
	{
		// Every early exit in the fork loads its string with a `lea` and
		// reports through the same file/line/message triple as everything else.
		// Reproduced as one helper so the order below reads the way the
		// recovered control flow does.
		void report_decline(decline reason)
		{
			spu_task_hle::note_decline(decline_text(reason), __FILE__, decline_line);
		}
	}

	void launch(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& out)
	{
		(void)cpu;

		const auto map = granule_map(mem);

		// gpr[3] is the parameter block. 0x143a14dd3 / 0x143a14dd7:
		// `mov rcx, [r8 + 0x18]` / `lea edx, [rcx + 0x100]`.
		const u32 s = static_cast<u32>(regs.gpr[3]);

		// 0x143a14de4: `cmp edx, -0x24` catches the wrap, then the page walk
		// at 0x143a14f04 covers [S, S + 0x100].
		if (!window_ok(map, s, s + 0x100u))
		{
			report_decline(decline::unmapped_guest_memory);
			return;
		}

		// 0x143a14e51: the two self-pointers, read *raw* - no byte swap,
		// because they are the guest's own pointers being compared with the
		// guest's own arithmetic.
		u32 self_hi = 0, self_lo = 0;

		if (!load_raw32(mem, s + param_block::self_hi, self_hi) ||
		    !load_raw32(mem, s + param_block::self_lo, self_lo))
		{
			report_decline(decline::unmapped_guest_memory);
			return;
		}

		// 0x143a14e6f and 0x143a14e8c.
		if (self_hi != s + param_block::self_span || self_lo != s + param_block::task_object)
		{
			report_decline(decline::unexpected_parameter_block);
			return;
		}

		// 0x143a14e92: `cmp r8d, -8 / ja` - the task object pointer has to
		// sit far enough from the top of the space that a later range check
		// cannot wrap.
		if (self_lo > 0xfffffff8u)
		{
			report_decline(decline::unexpected_parameter_block);
			return;
		}

		// The seven descriptors. Read raw from the guest, then byte-swapped
		// as one group at 0x143a14ff0 - 0x143a15003.
		u32 descs[7] = {};

		for (u32 i = 0; i < 7; i++)
		{
			if (!load_raw32(mem, s + dma_descs[i].at, descs[i]))
			{
				report_decline(decline::unmapped_guest_memory);
				return;
			}
		}

		// 0x143a14eef: the eight bytes at the task object must be mapped.
		if (!window_ok(map, self_lo, self_lo + 7u))
		{
			report_decline(decline::unmapped_guest_memory);
			return;
		}

		// 0x143a14fc9: the first self-pointer read a second time and compared
		// against 4 - the "phase word <= 3" gate. It is a pointer *and* a
		// phase word, because the guest keeps the phase in a field that also
		// has to equal S + 0xa4.
		if (self_hi < param_block::phase_min)
		{
			report_decline(decline::phase_word_too_small);
			return;
		}

		// 0x143a14fdd: `cmp dword ptr [r10 + rax], 0 / je` - the task must
		// not already be running. Read raw, again, because it is the guest's
		// own flag word.
		u32 busy = 1;

		if (!load_raw32(mem, self_lo, busy) || busy != 0)
		{
			report_decline(decline::task_object_busy);
			return;
		}

		// 0x143a15008 - 0x143a1501d: the OR of all seven descriptors must be
		// 16-byte aligned. A misaligned SPU DMA address faults the task, so
		// the lift refuses rather than silently emulating a halt - which is
		// why the decline text says so.
		u32 combined = 0;

		for (u32 i = 0; i < 7; i++)
		{
			descs[i] = swap32(descs[i]);
			combined |= descs[i];
		}

		if (combined & 0xfu)
		{
			report_decline(decline::misaligned_dma);
			return;
		}

		scratch_t& buf = scratch();
		clean(buf);

		// The four unconditional reads at 0x143a1504d - 0x143a150b0.
		for (u32 i = 0; i < 4; i++)
		{
			const dma_desc& d = dma_descs[i];

			if (!get(mem, buf, descs[i], d.size, d.scratch, map))
			{
				report_decline(decline::unmapped_guest_memory);
				return;
			}
		}

		// The width: byte 4 of the +0x108 buffer, assembled big-endian. The
		// decline says W(S+4) because that buffer is S.
		const u32 width = be32_bytes(buf.data, width_offset);

		if (width > max_width)
		{
			report_decline(decline::width_over_128);
			return;
		}

		const u32 stride = width * width_stride;

		// 0x143a150fa onwards: six sub-descriptors out of the +0x114 buffer,
		// each `stride` bytes wide. The low byte of each destination address
		// must be 16-byte aligned.
		for (u32 i = 0; i < 6; i++)
		{
			const u32 target = be32_bytes(buf.data, sub_descs[i].scratch);

			if (target & 0xfu)
			{
				report_decline(decline::misaligned_dma);
				return;
			}

			if (!get(mem, buf, target, stride, sub_descs[i].destination, map))
			{
				report_decline(decline::unmapped_guest_memory);
				return;
			}
		}

		// The three remaining unconditional reads at 0x143a152d8 - 0x143a15325.
		for (u32 i = 4; i < 7; i++)
		{
			const dma_desc& d = dma_descs[i];

			if (!get(mem, buf, descs[i], d.size, d.scratch, map))
			{
				report_decline(decline::unmapped_guest_memory);
				return;
			}
		}

		// 0x143a15332 - 0x143a15364: each sub-descriptor's payload buffer gets
		// its own size written into its first word. The immediate is the byte
		// pattern of a big-endian 0x0000c680 - stored little-endian on the host
		// so the guest reads 00 00 c6 80 - which is why these look like floats
		// and are not.
		for (const sub_desc& sd : sub_descs)
		{
			u32 be = swap32(sd.destination);
			std::memcpy(&buf.data[sd.destination], &be, sizeof(be));
		}

		// From here the fork installs its own MXCSR (0xffc0: DAZ, FZ and
		// round-to-nearest, all masked) and restores it on every exit, and the
		// descriptor snapshot goes to the stack.
		//
		//   0x143a1536e  stmxcsr [rsp + 0x70]
		//   0x143a15377  mov  dword ptr [rsp + 0x70], 0xffc0
		//   0x143a1537f  ldmxcsr [rsp + 0x70]
		//
		// The replica does not need it - nothing of its own is lifted - but the
		// descriptor read below is, so the four words are pulled here.
		const descriptor_words before = read_descriptor(buf);

		// The count, N, is the second word of the descriptor:
		//   0x143a154d2  mov  eax, [rcx + 0x17284] / bswap eax
		//   0x143a1552a  cmp  eax, 0x80 / ja
		const u32 count = before.w1;

		if (count > max_count)
		{
			report_decline(decline::count_over_128);
			return;
		}

		// The low byte of the third word must be 16-byte aligned:
		//   0x143a15535  or  edx, r9d
		//   0x143a1553e  test dl, 0xf / jne
		if (before.w2 & 0xfu)
		{
			report_decline(decline::misaligned_dma);
			return;
		}

		// 0x143a15551: get(s, 0x10800, W0, N * 80) and
		// 0x143a1557a: get(s, 0xfe80,  W2, N * 16).
		//
		// The two are the last two arguments the fork sets up in registers:
		// W2 is `[rsp + 0x28]` (assembled out of bytes 0x17288 - 0x1728b) and
		// W3 is `[rsp + 0x24]` (`bswap` of the dword at 0x1728c), while W0 is
		// `[rsp + 0x44]` and W1 (the count) is `[rsp + 0x2c]`. So 0xfe80 is
		// W2's copy and 0xf680 - the *other* writeback source - is never DMA'd
		// in at all: it is the buffer the three stages write their result into.
		if (!get(mem, buf, before.w0, count * count_stride5, count_buffer, map) ||
		    !get(mem, buf, before.w2, count * count_stride1, writeback_rows, map))
		{
			report_decline(decline::unmapped_guest_memory);
			return;
		}

		// Everything above is the fork's own front end. From here on it is the
		// lift:
		//
		//   set_nv(nv_stage1) / pm_082c0
		//   compare ctx + 0x90 .. + 0x3f0 against its snapshot   -> reason 8
		//   run_launch, whose false is                            -> reason 7
		//   nv_stage23 / pm_0a7a8, the same pair again
		//   pm_04780, the pair a third time
		//   then the output record check and the three writebacks.
		//
		// The three stages and run_launch are compiled native code. The
		// replica does not approximate them - an invented blend would write
		// plausible-looking bone matrices into guest memory - and reports the
		// fork's own reason for a lift that cannot run.
		const bool ran_one = stage_not_built(stage::one);
		const bool ran_two = stage_not_built(stage::two);
		const bool ran_three = stage_not_built(stage::three);

		if (!ran_one && !descriptor_unchanged(buf, before))
		{
			report_decline(decline::stage_clobbered_callee_saved);
			return;
		}

		if (!ran_one)
		{
			report_decline(decline::bone_descriptor_changed);
			return;
		}

		if (!ran_two || !ran_three)
		{
			report_decline(decline::lifted_code_declined);
			return;
		}

		(void)ran_two;
		(void)ran_three;
		(void)matrix_offset_max;
		(void)writeback_matrix;
		(void)writeback_matrix_size;
		(void)writeback_rows;
		(void)writeback_rows2;
		(void)output_record::offset;

		report_decline(decline::lifted_code_declined);

		// Not handled: the guest's own pl_motion_mix runs.
		out.handled = false;
	}

	void reset()
	{
		s_scratch.reset();
	}
}