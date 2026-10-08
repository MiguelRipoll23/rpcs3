#pragma once

// Metal Gear Online "player motion mix" hook.
//
// Recovered from the SaveMGO fork's mgo_pl_motion_mix subsystem. The fork's own
// log channel for it is "ppu.pl_motion_mix", and the handler hook record 0 runs
// is `(anonymous namespace)::pl_motion_mix_launch` at 0x143a14dc0, 0xae3 bytes.
//
// ---------------------------------------------------------------------------
// What it does
// ---------------------------------------------------------------------------
//
// pl_motion_mix is the player-animation blend. The guest hands the host a
// 0x124-byte parameter block, the host DMAs seven buffers out of it into one
// 0x40040-byte staging scratch, then runs three "stages" of a lifted SPU
// routine over the staged bone data, proving after each stage that the bone
// descriptor is untouched, and finally DMAs three buffers back.
//
// The three stages are mgo_pl_motion_mix_lift::{pm_082c0, pm_0a7a8, pm_04780}
// plus the shared driver mgo_pl_motion_mix::run_launch, all of which are
// compiled native code lifted from guest functions by offset. Everything
// around them is recoverable and is implemented below:
//
//   * the ten-entry decline table at 0x144b3789c (see the correction below),
//   * the parameter block's layout and its two self-pointer checks,
//   * detail::scratch / detail::clean / detail::get - complete,
//   * detail::set_nv and both nv_set tables - complete,
//   * run_launch's four-word bone-descriptor comparison - complete,
//   * the MXCSR discipline, the two 0x80 width caps and the three writebacks.
//
// What is *not* recoverable is the arithmetic inside the three stages. The
// replica therefore reproduces the whole front end and then declines with the
// fork's own wording for a lift that cannot run.

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

#include <array>
#include <functional>
#include <string_view>

namespace mgo_pl_motion_mix
{
	// -----------------------------------------------------------------------
	// Decline reasons
	// -----------------------------------------------------------------------

	// The fork's decline table, ten int32 rel32 offsets at 0x144b3789c, read by
	//
	//   0x143a15486  lea  rax, [rip + 0x112240f]   ; 0x144b3789c
	//   0x143a1548d  movsxd r11, dword ptr [rax + r12*4]
	//   0x143a15491  add  r11, rcx
	//
	// **Correction to an earlier revision of these notes**, which recorded
	// this as eight entries indexed `reason - 1` with a "declined" default.
	// It is ten entries indexed *directly*, with no bound check on the index
	// at this site - so the index really does have to be in 0..9, and the
	// COFF symbol `switch.table._ZN12_GLOBAL__N_120pl_motion_mix_launch...`
	// sits at the table itself.
	//
	// The five early exits bypass the table and load a string with a plain
	// `lea` instead, so those five appear twice: once as a direct string and
	// once as its table index.
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

	// The fork's own wording, verbatim.
	std::string_view decline_text(decline reason);

	// How the staged exits turn a register into a table index.
	//
	// Every staged exit funnels through one pair of instructions:
	//
	//   0x143a15476  add    r14d, 0xfe
	//   0x143a1547d  movzx  r12d, r14b
	//
	// so the index is (staged - 2) & 0xff. Every staged value in the body is
	// therefore two above its reason: 0xa for reason 8, 0xb for reason 9, and
	// so on. Reproduced as an addition and a byte-sized mask rather than as a
	// subtraction, because a subtraction would quietly change what happens to
	// a value below 2.
	constexpr u8 staged_bias = 0xfe;

	constexpr u8 stage_index(u8 staged)
	{
		return static_cast<u8>(staged + staged_bias);
	}

	// The line the fork blames for a pl_motion_mix decline, from
	// `mov dword ptr [rax + 0x1f0], 0x24` at 0x143a14e0d.
	constexpr u32 decline_line = 0x24;

	// -----------------------------------------------------------------------
	// The guest parameter block
	// -----------------------------------------------------------------------

	// gpr[3] points at this. Its first 0x101 bytes must be mapped
	// (`cmp edx, -0x24` on gpr[3] + 0x100 at 0x143a14de4, then the page walk
	// at 0x143a14f04), and it carries two self-pointers:
	//
	//   guest[S + 0x100] == S + 0xa4   and   >= 4
	//   guest[S + 0x104] == S + 0xa0   and   <= 0xfffffff8
	//
	// The second is also the task object, and `guest[S + 0xa0] == 0` is the
	// "not busy" test (`cmp dword ptr [r10 + rax], 0 / je` at 0x143a14fdd).
	// Both are compared *without* a byte swap, because they are the guest's own
	// pointers read back as raw words.
	struct param_block
	{
		static constexpr u32 size = 0x124;

		// The two self-pointers, and the "phase word <= 3" gate on the first.
		static constexpr u32 self_hi = 0x100; // must equal S + 0xa4, and be >= 4
		static constexpr u32 self_lo = 0x104; // must equal S + 0xa0, and be <= -8
		static constexpr u32 self_span = 0xa4;
		static constexpr u32 task_object = 0xa0;

		static constexpr u32 phase_min = 4;
	};

	// The seven DMA descriptors, at +0x108 .. +0x120. All seven are read
	// without a swap (`mov r12d, dword ptr [r10 + r11]` with the guest base
	// added) and byte-swapped as one group afterwards at 0x143a14ff0 -
	// 0x143a15003. Their sizes are fixed immediates at the `get` call sites.
	struct dma_desc
	{
		u32 at = 0;      // offset of the pointer inside the parameter block
		u32 order = 0;   // the order the fork reads them in (0..6)
		u32 size = 0;    // bytes the fork transfers
		u32 scratch = 0; // where in scratch_t they land
	};

	// Transcribed from the `get` call sites, in the order the fork issues them:
	// four at 0x143a1504d, 0x143a1506e, 0x143a1508c and 0x143a150aa, then
	// three at 0x143a152e3, 0x143a15301 and 0x143a1531f.
	inline constexpr dma_desc dma_descs[] =
	{
		{ 0x108, 0, 0x5d0,  0x13080 }, // the bone table; the width lives at +0x13084
		{ 0x110, 1, 0x3bf0, 0x13680 }, // the big matrix block, and the only one written back
		{ 0x120, 2, 0x10,   0x17280 }, // the 16-byte bone descriptor
		{ 0x114, 3, 0x120,  0x17300 }, // six sub-descriptors live in here
		{ 0x118, 4, 0x120,  0x17480 },
		{ 0x10c, 5, 0x280,  0x17600 },
		{ 0x11c, 6, 0xa0,   0x17880 },
	};

	// The six sub-descriptors inside the +0x114 buffer. Each is a big-endian
	// 32-bit value assembled from four separate byte loads; its low byte is
	// the destination address and must be 16-byte aligned (`test al, 0xf`),
	// and the transfer is W * 16 bytes wide.
	struct sub_desc
	{
		u32 scratch = 0;     // where the sub-descriptor itself is read from
		u32 destination = 0; // where its payload lands
	};

	inline constexpr sub_desc sub_descs[] =
	{
		{ 0x17320, 0xc680 },
		{ 0x17350, 0xce80 },
		{ 0x17380, 0xd680 },
		{ 0x173b0, 0xde80 },
		{ 0x173e0, 0xe680 },
		{ 0x17410, 0xee80 },
	};

	// Width and count caps. Both are `cmp eax, 0x80 / ja` with 0x80 = 128:
	//
	//   0x143a150ef  cmp eax, 0x80 / ja   -> "W(S+4) > 128"
	//   0x143a1552a  cmp eax, 0x80 / ja   -> "N > 128"
	//
	// and they are hard caps, not hints: the stride below is a shift.
	inline constexpr u32 max_width = 128;
	inline constexpr u32 max_count = 128;

	inline constexpr u32 width_stride = 16; // W is scaled by 16

	// The width's home: byte 4 of the +0x108 buffer, assembled big-endian.
	static constexpr u32 width_offset = 0x13084;

	// The 16-byte bone descriptor the +0x120 buffer holds, and the four words
	// run_launch compares. Two are read as plain big-endian dwords
	// (`bswap dword ptr`) and two are assembled out of four byte loads, which
	// is why the launcher needs two different loaders for one 16-byte buffer.
	//
	//   W0  be32 from bytes   -> guest address of the N * 80 buffer  ([rsp+0x44])
	//   W1  bswap32 dword     -> N, the count, capped at 128        ([rsp+0x2c])
	//   W2  be32 from bytes   -> guest address of the N * 16 buffer  ([rsp+0x28])
	//   W3  bswap32 dword     -> guest address of the other one      ([rsp+0x24])
	//
	// Only W2's buffer is DMA'd in. W3's destination is the 0xf680 buffer,
	// which no `get` ever writes: it is where the three stages put their
	// result, and it is written back over W3 at the end.
	struct descriptor_layout
	{
		static constexpr u32 at = 0x17280;
		static constexpr u32 w0 = 0x17280;
		static constexpr u32 w1 = 0x17284;
		static constexpr u32 w2 = 0x17288;
		static constexpr u32 w3 = 0x1728c;
	};

	// The two extra transfers the second half issues, sized off W1:
	//
	//   0x143a15547  shl   eax, 4              ; W1 * 16
	//   0x143a1554a  lea   r9d, [rax + rax*4]   ; W1 * 80
	//   0x143a15551  get(s, 0x10800, W0, W1 * 80)
	//   0x143a1557a  get(s, 0xfe80,  W2, W1 * 16)
	//
	// detail::get's own arguments, from its thirteen call sites:
	// rcx = the scratch, edx = the destination offset inside it, r8d = the
	// guest address, r9d = the size. Note 0x10800 + 128 * 80 == 0x13000 and
	// 0xfe80 + 128 * 16 == 0x10680, so the caps keep both inside their band.
	inline constexpr u32 count_buffer = 0x10800;
	inline constexpr u32 count_stride5 = 80; // 16 * 5
	inline constexpr u32 count_stride1 = 16;

	// 0x10800 + 128 * 80, the end of the N * 80 buffer, and 0xfe80 - 0x800 =
	// 0xf680, where the *other* N * 16 buffer would start. That second one is
	// never DMA'd in; it is the stage output.
	inline constexpr u32 count_buffer_end = 0x13000;
	inline constexpr u32 rows_spacing = 0x800;

	// The writebacks at the end, from 0x143a15800 and 0x143a15865:
	//
	//   memcpy(scratch + 0x13680, base + desc(0x110), 0x3bf0)
	//   memcpy(scratch + 0xfe80,  base + W2, N * 16)      -- only when N != 0
	//   memcpy(scratch + 0xf680,  base + W3, N * 16)      -- only when N != 0
	//
	// The last two are the `memcpy` at 0x143a15819 and the shared tail at
	// 0x143a1587e, which 0x143a1584f jumps into with the 0xf680 case set up.
	//
	// Note `add ecx, [rip + ...]` adds the guest *base*, not the address: the
	// +0x110 descriptor is an offset, which is why it is range-checked against
	// -0x3bf0 (`cmp ebx, 0xffffc410 / ja`) rather than for alignment.
	inline constexpr u32 writeback_matrix = 0x13680;
	inline constexpr u32 writeback_matrix_size = 0x3bf0;
	inline constexpr u32 writeback_rows = 0xfe80;
	inline constexpr u32 writeback_rows2 = 0xf680;

	// `cmp ebx, 0xffffc410 / ja` - the +0x110 offset plus 0x3bf0 must not wrap.
	inline constexpr u32 matrix_offset_max = 0xffffc410u;

	// -----------------------------------------------------------------------
	// scratch_t
	// -----------------------------------------------------------------------

	// The staging object, allocated once per thread:
	//
	//   0x143a279b5  mov ecx, 0x40040      ; operator new(0x40040, align 0x40)
	//   0x143a279f5  mov r8d, 0x40020     ; memset(scratch, 0, 0x40020)
	//   0x143a279ee  mov qword ptr [rax + 0x608], rsi   ; thread + 0x608
	//
	// and gated on a byte at thread + 0x130 (0x143a1aa68), with the same
	// TLS-index idiom the other subsystems use.
	//
	// The object is 0x40020 bytes - 0x40000 of data and **four** 64-bit dirty
	// maps, one per 0x10000-byte band. detail::clean walks all four, at
	// +0x40000, +0x40008, +0x40010 and +0x40018, with bases 0x00000, 0x10000,
	// 0x20000 and 0x30000:
	//
	//   0x143a1aada  mov  rdi, [rcx + 0x40000]        ; band 0, unfiltered
	//   0x143a1ab23  mov  rdi, [rsi + 0x40008]        ; band 1, filtered
	//   0x143a1ab3e  mov  rdi, [rsi + 0x40010]        ; band 2, unfiltered
	//   0x143a1ab72  add  rcx, 0x20000
	//   0x143a1ab8b  mov  rdi, [rsi + 0x40018]        ; band 3, unfiltered
	//   0x143a1abc2  add  rcx, 0x30000
	struct scratch_t
	{
		u8 data[0x40000] = {};
		u64 dirty_00000 = 0; // +0x40000, blocks of 0x00000 .. 0x0ffff
		u64 dirty_10000 = 0; // +0x40008, blocks of 0x10000 .. 0x1ffff
		u64 dirty_20000 = 0; // +0x40010, blocks of 0x20000 .. 0x2ffff
		u64 dirty_30000 = 0; // +0x40018, blocks of 0x30000 .. 0x3ffff
	};

	static_assert(sizeof(scratch_t) == 0x40020);

	// The dirty-map geometry. A bit covers a 0x400-byte block of a band, so
	// the block index is address >> 10, its bit *within the band* is
	// (address >> 10) & 63 - the fork gets that for free because x86 masks the
	// shift count - and the qword index is address >> 16:
	//
	//   0x143a1acc2  shr  ecx, 0xa                       ; first block
	//   0x143a1ad4b  shl  rdx, cl                        ; ... its bit
	//   0x143a1ad4e  shr  r9d, 0x10                      ; ... its qword
	//   0x143a1ad52  or   [rsi + r9*8 + 0x40000], rdx
	//   0x143a1ad7d  shr  ecx, 6                         ; subsequent blocks
	//   0x143a1ab0b  shl  ecx, 0xa                       ; back to a byte offset
	inline constexpr u32 block_bytes = 0x400;
	inline constexpr u32 block_shift = 10;
	inline constexpr u32 band_shift = 16;

	// Where detail::clean zeroes each band. Only band 1 is filtered: the two
	// ranges below are live buffers, and clearing them would throw away the
	// staged data the run is still using.
	//
	//   0x143a1ac19  or   eax, 0x10000
	//   0x143a1ac1e  cmp  eax, 0x13080   / jb  clear
	//   0x143a1ac25  cmp  eax, 0x13251   / setb
	//   0x143a1ac2d  add  ecx, 0xffffc980
	//   0x143a1ac33  cmp  ecx, 0x37f1    / setb
	struct live_range
	{
		u32 begin = 0;
		u32 end = 0;
	};

	inline constexpr live_range live_13000{ 0x13080, 0x13251 };
	inline constexpr live_range live_03680{ 0x03680, 0x06e71 };

	// Both are band-relative, i.e. the second is really [0x13680, 0x16e71)
	// once band 1's 0x10000 base is added. That is the two buffers a run
	// leaves behind in band 1:
	//
	//   0x13080 .. 0x13251   the +0x108 bone table, 0x5d0 bytes rounded up
	//   0x13680 .. 0x16e71   the +0x110 matrix block, 0x3bf0 bytes
	//
	// and the bone descriptor at 0x17280 is past the second range's end, so
	// it *is* cleared - which is why the launcher re-reads it from the guest
	// through the count-sized gets rather than trusting what survived.

	// The per-thread accessor and the reset. Mirrors detail::scratch() at
	// 0x143a1aa50, which returns thread + 0x608 and constructs it on first use.
	scratch_t& scratch();
	void clean(scratch_t& s);
	void reset();

	// detail::get - complete, from 0x143a1ac50.
	//
	//   if (size == 0)                 -> true, nothing to do
	//   if (addr + size > 2^32)        -> false
	//   walk the page map over [addr>>12 .. (addr+size-1)>>12]; any
	//   granule that is not exactly 0x81 mapped -> false
	//
	// One granule is one byte of the map, and the walk indexes it by
	// `address >> 12`, so a granule is a 0x1000-byte page - not the 0x100 an
	// earlier revision of these notes said. The 0x40 and 0x20 skip bits then
	// cover 0x100 pages (1 MiB) and 0x10 pages (64 KiB).
	//   memcpy(scratch + off, guest + addr, size)
	//   mark every 0x400 block of [scratch+off, scratch+off+size) dirty
	//
	// The marking is not quite what it looks like. It computes
	//
	//   first = off >> 10,  last = (off + size) >> 10
	//
	// and, if first <= last, marks `first` only when `(first + last)` is *even*:
	//
	//   0x143a1ad3a  lea  eax, [r8 + rcx]     ; last + first
	//   0x143a1ad40  test al, 1
	//   0x143a1ad44  jne  <skip the first block's bit>
	//   0x143a1ad5d  cmp  r8d, ecx / je done
	//
	// and when it does skip it, the loop that follows starts from `first + 1`
	// using a register the skip path never wrote. The condition's purpose is
	// not identifiable and the skipped path is not something to reproduce, so
	// the replica marks the whole range - which can only ever clear more.
	bool get(spu_task_hle::ppu::direct_mem& mem, scratch_t& s, u32 guest_addr, u32 size, u32 off,
	         const std::function<u8(u32 granule)>& map_byte);

	// Marks one block dirty, in the band that covers `addr`.
	void mark_dirty(scratch_t& s, u32 addr);

	// The forward window guard every pl_motion_mix range check uses:
	//
	//   mov  eax, lo
	//   shr  eax, 0xc
	//   lea  ecx, [lo + (hi - lo)]
	//   shr  ecx, 0xc
	//   cmp  eax, ecx          / ja  reject-lo-only
	//   <walk eax .. ecx>
	//
	// `hi` is always at or above `lo` here, so the walk runs and every 0x1000
	// granule of the range has to be mapped. The walk itself, at 0x143a1ad03:
	//
	//   movzx ebx, byte ptr [rdi + r11]  / not edi / test dil, 0x81 / jne reject
	//   test bl, 0x40  / jne <(g & ~0xff) + 0x100>       ; 0x143a1acf0
	//   test bl, 0x20  / jne <(g & ~0xf) + 0x10>         ; 0x143a1ad30
	//   inc r10d                                        ; otherwise one granule
	//   cmp r10d, ecx / ja done
	//
	// so the presence test comes *first*: a bare skip bit without 0x81 is
	// rejected before the jump is taken. Both jumps round *up* to the next
	// boundary, so neither can stall below it.
	bool window_ok(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi);

	// -----------------------------------------------------------------------
	// nv_set
	// -----------------------------------------------------------------------

	// detail::set_nv, complete, from 0x143a1adb0.
	//
	// It expands a 0xc0-byte nv_set into the context starting at ctx + 0x90,
	// eleven 16-byte groups of four u32s plus one `vpermilps 0x1b`, and then
	// overwrites ctx + 0x110 .. 0x300 with a single repeated 16-byte constant.
	struct nv_set
	{
		u8 bytes[0xc0] = {};
	};

	// Both tables, transcribed from 0x144b2a154 and 0x144b2a214.
	const nv_set& nv_stage1();
	const nv_set& nv_stage23();

	// The constant set_nv fills ctx + 0x110 .. 0x300 with, read out of the
	// `vmovaps xmm0, [rip + 0x11081fd]` at 0x143a1af5b (0x144b23160).
	const std::array<u8, 16>& nv_fill();

	void set_nv(u8* ctx, const nv_set& set);

	// -----------------------------------------------------------------------
	// The stages
	// -----------------------------------------------------------------------

	// The three lifted guest functions the driver runs, by their guest
	// function offsets - the fork names them for the offset it lifts from:
	//
	//   pm_082c0  0x143a1b1c0   stage 1, after nv_stage1
	//   pm_0a7a8  0x143a1dfb0   stage 2, after nv_stage23
	//   pm_04780  0x143a26410   stage 3, after the first run_launch
	enum class stage
	{
		one,
		two,
		three,
	};

	// mgo_pl_motion_mix::run_launch - complete, from 0x143a263c0.
	//
	// Four big-endian words out of the 16-byte bone descriptor, compared
	// against four words the caller snapshotted before the stage ran:
	//
	//   bswap32(s[0x17280]) == *expect0
	//   bswap32(s[0x17284]) == *expect1
	//   bswap32(s[0x17288]) == *expect2
	//   bswap32(s[0x1728c]) == *expect3
	//
	// A mismatch returns false, and that false is what the launcher reports
	// as `bone_descriptor_changed`. This is the proof obligation: the lift may
	// read the descriptor but must not change it.
	struct descriptor_words
	{
		u32 w0 = 0; // +0x17280
		u32 w1 = 0; // +0x17284
		u32 w2 = 0; // +0x17288
		u32 w3 = 0; // +0x1728c
	};

	descriptor_words read_descriptor(const scratch_t& s);
	bool descriptor_unchanged(const scratch_t& s, const descriptor_words& expected);

	// -----------------------------------------------------------------------
	// The launcher
	// -----------------------------------------------------------------------

	// The MXCSR the fork installs before the first stage and restores after the
	// last:
	//
	//   0x143a1536e  stmxcsr [rsp + 0x70]
	//   0x143a15377  mov  dword ptr [rsp + 0x70], 0xffc0
	//   0x143a1537f  ldmxcsr [rsp + 0x70]
	//
	// 0xffc0 turns on DAZ (bit 6), FZ (bit 12) and round-to-nearest (bit 14)
	// and masks all three, which is what an SPU's denormal behaviour matches.
	// It is saved and restored around the whole run, never left set.
	inline constexpr u32 lift_mxcsr = 0xffc0;

	// The record a stage publishes at scratch + 0x13000, checked after the
	// second run_launch at 0x143a15725 - 0x143a15767:
	//
	//   bswap32(s[0x13000]) == 0x10800
	//   bswap32(s[0x13004]) == the width word saved before the stages
	//   bswap32(s[0x13008]) == 0xfe80
	//   bswap32(s[0x1300c]) == 0xf680
	//
	// and written by the fork at 0x143a15665 - 0x143a15691.
	struct output_record
	{
		static constexpr u32 offset = 0x13000;
		static constexpr u32 expected_size = 0x10800;
		static constexpr u32 expected_2nd = 0xfe80;
		static constexpr u32 expected_3rd = 0xf680;

		// `or byte ptr [rdi + 0x40009], 0x10` at 0x143a15698 - the "lift ran"
		// flag, bit 16 of the middle dirty map.
		static constexpr u32 ran_flag_bit = 16;
	};

	// The launcher's front end, run from the hook body.
	//
	// Reproduced in full through the last writeback, so the guest's DMA ranges,
	// the width cap, the six sub-descriptors, the MXCSR discipline, all three
	// stage/prove cycles and the output record check are the fork's. The stage
	// arithmetic is not, so run_stage() declines with
	// `lifted_code_declined` and result.handled stays false, which runs the
	// guest's own pl_motion_mix.
	void launch(ppu_thread& cpu, spu_task_hle::ppu::direct_mem& mem,
	            const spu_task_hle::ppu::call_regs& regs, spu_task_hle::ppu::call_result& out);
}