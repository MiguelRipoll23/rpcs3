#pragma once

// Metal Gear Online model-setup ("modelsetup") hook.
//
// Recovered from the SaveMGO fork's mgo_modelsetup subsystem. The fork's own
// log channel for it is "ppu.modelsetup" (see MGO_FORK.md), and the handler it
// runs from hook record 7 lives at 0x143a19ec0 (0x8fb bytes).
//
// ---------------------------------------------------------------------------
// What the fork actually does, and what is reproduced here
// ---------------------------------------------------------------------------
//
// The whole subsystem is a *task lifter*: it takes the SPURS image the guest
// has just loaded, verifies it against a hash the fork knows, walks its SPURS
// task queue on the host, and runs the tasks' code - lifted to x86 - instead of
// on an SPU. Around that sit a worker pool, a page-ownership tracker used to
// prove chunks can run in parallel, a cost model, and a splitter.
//
// Everything in that front half is recoverable and is implemented below:
//
//   * the 9-entry status table at 0x144b378e4 (rel32 offsets, default "?"),
//   * the two image records at 0x144b36e20 (0x30 bytes each),
//   * read_spurs_args (0x143ac5380, 0x19a bytes) - complete,
//   * detail::load_image (0x143ac5520, 0x3ba bytes) - complete,
//   * par::page_set / par::tracker (0x143b46a00 / 0x143b46920) - complete,
//   * and the launcher's own argument gates.
//
// The lifters themselves - mgo_modelsetup_bg_lift and
// mgo_modelsetup_chara_lift, plus detail::run's 0xc28-byte body and the two
// task_io DMA callbacks - are compiled code with no recoverable description,
// so run() declines with the fork's own status and the guest always runs its
// original SPURS code.

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

#include <functional>
#include <string_view>
#include <vector>

namespace mgo_modelsetup
{
	// -----------------------------------------------------------------------
	// Status
	// -----------------------------------------------------------------------

	// Why a modelsetup call did not get lifted.
	//
	// Index 0 is a *status*, not a decline: it is the value the fork stores in
	// result::status when everything worked. The table is nine int32 rel32
	// offsets at 0x144b378e4, read by
	//
	//   0x143a1a4e8  lea  rcx, [rip + 0x111d3f5]   ; 0x144b378e4
	//   0x143a1a4ed  movsxd rax, dword ptr [rcx + rax*4]
	//   0x143a1a4f3  add  rax, rcx
	//
	// with the bound `cmp rax, 8 / ja` immediately before, so anything above 8
	// falls to the "?" arm at 0x144b2a931. The string then goes into the
	// fork's decline triple as
	//
	//   mov qword ptr [rcx + 0x1f8], rax          ; message
	//   mov dword ptr [rcx + 0x1f0], 0x69         ; line 105
	//   mov qword ptr [rcx + 0x1e8], <__FILE__>   ; mgo_ppu_hooks.cpp
	enum class status : u8
	{
		none = 0,
		built_without_sse = 1,        // "built without SSE4.1/SSSE3/FMA3"
		not_a_model_setup_image = 2,  // "not a model setup image"
		task_image_differs = 3,       // "task image differs from the lifted one"
		unexpected_spurs_args = 4,   // "unexpected SPURS_TaskStart arguments"
		unmapped_guest_memory = 5,    // "unmapped guest memory"
		taskset_unreadable = 6,       // "SPURS taskset not readable"
		lifted_code_declined = 7,     // "lifted code declined (...)"
		task_did_not_put = 8,         // "task did not PUT its record"
	};

	// The fork's own wording, verbatim. Values above 8 give "?", which is the
	// table's default arm.
	std::string_view status_text(status value);

	// Line the fork blames for a modelsetup decline, read out of
	// `mov dword ptr [rcx + 0x1f0], 0x69` at 0x143a1a520. Exposed because the
	// fork's log output carries it and MGO_FORK.md quotes it.
	constexpr u32 decline_line = 0x69;

	// -----------------------------------------------------------------------
	// The image table
	// -----------------------------------------------------------------------

	// One record of mgo_modelsetup::images, at 0x144b36e20.
	//
	// The stride is not a guess: the launcher indexes it with
	//
	//   0x143a1a1bc  lea rax, [rbx + rbx*2]
	//   0x143a1a1c0  shl eax, 4
	//
	// i.e. index * 48, and the table base is the lea at 0x143a1a1c3
	// (0x143a1a1c3 + 7 + 0x111cc56 = 0x144b36e20). The table holds exactly two
	// records; the third, at +0x60, is the string "thread construction failed".
	struct image_info
	{
		u32 image_base = 0;  // +0x00 guest address the image was loaded at
		u32 entry = 0;      // +0x04
		u32 hash_bytes = 0; // +0x08 length FNV-1a-64 covers, measured from 0x3000
		u32 word_0c = 0;    // +0x0c
		u32 word_10 = 0;    // +0x10
		u32 word_14 = 0;    // +0x14
		u32 word_18 = 0;    // +0x18
		u32 word_1c = 0;    // +0x1c
		u32 chunk_count = 0;// +0x20
		u32 reserved_24 = 0;// +0x24 always zero in both records
		u64 image_hash = 0; // +0x28 FNV-1a-64 of scratch[0x3000 .. hash_bytes)
	};

	static_assert(sizeof(image_info) == 0x30);

	// The two records, transcribed.
	const std::vector<image_info>& images();

	// The two guest addresses the launcher accepts for gpr[5] - the image the
	// guest is asking to be set up. Compared at 0x143a1a0b5 / 0x143a1a0bd:
	//
	//   cmp ebp, 0x100c280
	//   cmp ebp, 0x1009480
	//
	// which are exactly image_info::image_base of the two records, and again
	// inside detail::run at 0x143ac5acc / 0x143ac5adb.
	inline constexpr u32 image_address_chara = 0x0100c280u;
	inline constexpr u32 image_address_bg = 0x01009480u;

	// Index into images() for a guest image address, or -1.
	s32 image_index(u32 image_address);

	// -----------------------------------------------------------------------
	// SPURS argument block
	// -----------------------------------------------------------------------

	// What read_spurs_args fills in. Layout is fixed by the recovered stores:
	//
	//   0x143ac54c7  mov dword ptr [rdx], ecx     ; context
	//   0x143ac5512  mov qword ptr [rsi + 8], rax
	//   0x143ac5504  mov qword ptr [rsi + 0x10], rcx
	struct spurs_args
	{
		u32 context = 0;  // +0x00, must be 128-byte aligned
		u64 qword_68 = 0; // +0x08, bswap64(guest[context + 0x68])
		u64 qword_60 = 0; // +0x10, bswap64(guest[context + 0x60])
	};

	static_assert(sizeof(spurs_args) == 0x18);

	// The guest word holding the SPURS task-queue pointer, read at 0x143ac53a6
	// as `mov r8d, dword ptr [r10 + 0x121aef8]`.
	inline constexpr u32 spurs_task_queue = 0x121aef8u;

	// read_spurs_args rejects more than this many tasks with a plain
	// `cmp ecx, 7 / ja` at 0x143ac5385 - i.e. 8 tasks, the exact number the
	// launcher's thread pool can serve, is already out of range.
	inline constexpr u32 max_spurs_tasks = 7u;

	// Stride of one task inside the block, and the offset of the first one:
	//
	//   0x143ac5439  imul ecx, ecx, 0x3b00
	//   0x143ac5441  add  eax, 0x5c40
	inline constexpr u32 spurs_task_stride = 0x3b00u;
	inline constexpr u32 spurs_task_first = 0x5c40u;

	// Reads the `tasks`-th SPURS task out of the guest's task queue.
	//
	// Complete, from 0x143ac5380. The order of the checks is the fork's:
	//
	//   1. tasks > 7                                  -> false
	//   2. the granule holding 0x121aef8 must be mapped -> false
	//   3. the whole 0x8000-byte window around the queue pointer must be
	//      mapped                                        -> false
	//   4. the task's address must not wrap              -> false
	//   5. the 4-byte task header must be mapped          -> false
	//   6. context & 0x7f                                -> false (alignment)
	//   7. guest[context .. context + 0x10] must be mapped -> false
	//
	// `map_byte` supplies the fork's reproduced-LS byte map; see page_guard_ok.
	bool read_spurs_args(spu_task_hle::ppu::direct_mem& mem, u32 tasks, spurs_args& out,
	                     const std::function<u8(u32 granule)>& map_byte);

	// -----------------------------------------------------------------------
	// The reproduced-LS byte map
	// -----------------------------------------------------------------------

	// One byte of the fork's own allocation map.
	//
	// Every modelsetup guard walks this map before touching guest memory, and
	// the walk is the same everywhere in the fork:
	//
	//   movzx b, byte ptr [granule]
	//   not  b
	//   test b, 0x81          ; reject unless the byte was exactly 0x81
	//   test b, 0x40          ; skip a whole 0x100
	//   test b, 0x20          ; skip the next 0x10
	//   inc
	//
	// reproduced by walk_granules().
	//
	// **Correction**: an earlier revision of this file said the byte covered
	// 0x100 of local store. It does not. Both walks index the byte with
	// `address >> 12` - `shr r10d, 0xc` at 0x143ac53b0 and 0x143a1ac8b - and
	// step with `inc`, so one byte is one 0x1000-byte page and the two skip
	// bits cover 0x100 pages (1 MiB) and 0x10 pages (64 KiB) respectively.
	inline constexpr u8 granule_mapped = 0x81;
	inline constexpr u8 granule_skip_page = 0x40;
	inline constexpr u8 granule_skip_16 = 0x20;

	// Walks granules [lo, hi] inclusive. Returns false as soon as one granule
	// is not exactly 0x81 mapped.
	bool walk_granules(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi);

	// The window guard, in the two shapes the fork actually uses. Both start with
	// the same wrap test, and then walk the map between two *page numbers* -
	// so whether the walk runs at all depends on which way the window points.
	//
	// Forward window, from load_image at 0x143ac5576 and from the launcher's
	// own guards at 0x143a19f61:
	//
	//   mov  eax, lo
	//   shr  eax, 0xc
	//   lea  ecx, [lo + (hi - lo)]     ; 0x33, 0x03, 0x7f
	//   shr  ecx, 0xc
	//   cmp  eax, ecx           / ja  accept
	//   <walk eax .. ecx>
	//
	// `hi >= lo` here, so the walk always runs and covers the window.
	bool window_forward_ok(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi);

	// Backwards window, from read_spurs_args at 0x143ac53b0:
	//
	//   lea   eax, [ptr - 0x8000]
	//   cmp   eax, -4                  / ja  reject
	//   mov   r9d, eax
	//   shr   r9d, 0xc
	//   add   r8d, 0xffff8003          ; ptr - 0x8000 - 0x7ffd
	//   shr   r8d, 0xc
	//   cmp   r9d, r8d                 / ja  accept
	//   <walk r9d .. r8d>
	//
	// The far end here is *behind* the near end, so `first > last` and the
	// walk is skipped - except for the three values of `ptr` in every 4 KB
	// where both ends land in the same page. In other words this guard is
	// almost entirely its first test, and that test rejects only
	// ptr in [0x7ffffffd, 0x7fffffff], where ptr - 0x8000 wraps past
	// 0xfffffffc. Kept exactly as written, walk included, because the walk is
	// what the fork runs when it does run.
	bool window_backwards_ok(const std::function<u8(u32 granule)>& map_byte, u32 ptr);

	// -----------------------------------------------------------------------
	// load_image
	// -----------------------------------------------------------------------

	// The scratch buffer the launcher allocates per image, 0x5c180 bytes:
	//
	//   0x143a1a149  mov ecx, 0x5c180        ; operator new
	//   0x143a1a164  mov r8d, 0x5c180
	//   0x143a1a169  call 0x143ea18b0        ; memset(buf, 0, 0x5c180)
	//   0x143a1a189  mov r8d, 0x40020
	//   0x143a1a194  call 0x143ea18b0        ; memset(buf, 0, 0x40020)
	inline constexpr u32 scratch_bytes = 0x5c180;
	inline constexpr u32 scratch_cleared_bytes = 0x40020;

	// Where the segments land and where the hash starts. Segments are copied
	// to `scratch + p_offset` and the FNV runs from 0x3000, so a segment whose
	// virtual address is below 0x3000 is rejected outright (0x143ac576a).
	inline constexpr u32 scratch_image_origin = 0x3000;

	// The load cache in the tail of the scratch buffer:
	//
	//   0x143ac5535  cmp dword ptr [rcx + 0x5c160], eax
	//   0x143ac553d  movzx ebx, byte ptr [rsi + 0x5c164]
	inline constexpr u32 scratch_cached_image = 0x5c160;
	inline constexpr u32 scratch_cached_ok = 0x5c164;

	inline constexpr u32 scratch_size = scratch_bytes;
	using image_scratch = std::array<u8, scratch_size>;

	// FNV-1a-64 as the fork computes it:
	//
	//   0x143ac5805  movabs rdx, 0xcbf29ce484222325
	//   0x143ac581f  movabs rax, 0x100000001b3
	//   ...          xor rdx, byte / imul rdx, rax
	inline constexpr u64 fnv_offset_basis = 0xcbf29ce484222325ull;
	inline constexpr u64 fnv_prime = 0x100000001b3ull;

	u64 fnv1a64(const u8* data, u32 bytes);

	// detail::load_image: verify the guest's SPURS image at `info.image_base`
	// against the fork's record and copy it into `scratch`.
	//
	// The image is an *ELFCLASS32* big-endian PowerPC64 image - the shape
	// SPURS task images have.
	//
	// Complete, from 0x143ac5520. The image is an *ELFCLASS32* big-endian
	// PowerPC64 image - the shape SPURS task images have - and every field
	// offset below is an Elf32 header offset, which is what the recovered code
	// reads:
	//
	//   +0x00  be32  "\x7f" "ELF"
	//   +0x04  u8    EI_CLASS, must be 1
	//   +0x05  u8    EI_DATA, must be 2
	//   +0x12  be16  e_machine, must be 0x17 (EM_PPC64)
	//   +0x1c  be32  e_phoff
	//   +0x2c  be16  e_phnum, must be <= 16
	//
	// then, per 32-byte program header:
	//
	//   +0x00  be32  p_type, only 1 (PT_LOAD) is copied
	//   +0x04  be32  p_offset, where the segment lands in the scratch buffer
	//   +0x08  be32  p_vaddr, must be >= 0x3000
	//   +0x10  be32  p_filesz
	//   +0x14  be32  p_memsz, p_filesz must be <= p_memsz
	//
	// with (p_vaddr | p_flags_high_byte) + p_memsz <= 0x40000 and
	// p_offset + image_base + p_filesz not wrapping 2^32.
	//
	// Returns false and caches false in scratch[scratch_cached_ok] on any
	// failure; caches the result of the check on a repeat call for the same
	// image_base.
	bool load_image(spu_task_hle::ppu::direct_mem& mem, image_scratch& scratch, const image_info& info,
	                const std::function<u8(u32 granule)>& map_byte);

	// -----------------------------------------------------------------------
	// The SPURS_TaskStart argument gates
	// -----------------------------------------------------------------------

	// gpr[6] must equal this. Recovered three times - at 0x143a1a0c9 in the
	// launcher and at 0x143ac5b49 / 0x143ac5b62 inside detail::run:
	//
	//   mov eax, r13d
	//   xor eax, 0x10000
	//   mov ecx, r15d
	//   and ecx, 0xf
	//   or  ecx, eax
	//   jne  <decline>
	//
	// i.e. (gpr[6] ^ 0x10000) | (gpr[3] & 0xf) must be zero.
	inline constexpr u32 spurs_option_word = 0x10000u;

	// detail::run rejects anything above this before it looks at the image,
	// with `cmp edi, -0x80 / jbe` at 0x143ac5b71 - i.e. gpr[3] must be at or
	// below 0xffffff80. Combined with the alignment mask above, gpr[3] is a
	// 16-byte aligned address in the top 64 MB of the guest's space.
	inline constexpr u32 spurs_arg_max = 0xffffff80u;

	bool spurs_args_ok(u32 gpr3, u32 gpr6);

	// -----------------------------------------------------------------------
	// Conflict tracking
	// -----------------------------------------------------------------------

	// par::page_set - the open-addressed set the fork uses to answer "which
	// 4 KB pages did this task touch". Complete, from 0x143b46a00 / 0x143b46bb0.
	//
	// The table stores page + 1 so that zero means empty, and the probe starts
	// at ((page * 0x9e3779b1) >> 12) & (capacity - 1):
	//
	//   0x143b46a43  imul edx, edi, 0x9e3779b1
	//   0x143b46a49  shr  edx, 0xc
	//   0x143b46a50  and  edx, mask
	//   0x143b46a56  mov  r8d, dword ptr [rax + rdx*4]
	//   0x143b46a5a  cmp  r8d, edi          ; already present
	//   0x143b46a5f  test r8d, r8d          ; empty slot
	//   0x143b46a64  inc  edx                ; linear probe
	class page_set
	{
	public:
		// Capacity is kept at least twice the load, so this never probes a
		// full table:
		//
		//   0x143b46a0e  lea edx, [rax*2 + 2]
		void insert(u32 page);

		// Rehashes into a table twice as large and reinserts everything from
		// the slot list at +0x18.
		//
		// The new slot count is `(end - begin) / 2` at 0x143b46c85, which
		// looks like a halving until you notice `end - begin` is a *byte*
		// difference: for a vector<u32> of N elements it is 4N, so the count
		// that reaches assign() is 2N. Read the other way it would shrink
		// the table under a full load and the probe loop would never find an
		// empty slot.
		void grow();

		bool contains(u32 page) const;

		u32 size() const { return m_count; }
		u32 capacity() const { return static_cast<u32>(m_table.size()); }

	private:
		std::vector<u32> m_table; // page + 1, or 0 for an empty slot
		std::vector<u32> m_slots; // indices of occupied slots, for rehashing
		u32 m_count = 0;
	};

	// One recorded access, {addr, size} - the element the tracker appends.
	struct access
	{
		u32 addr = 0;
		u32 size = 0;
	};

	// par::tracker - the per-task record of what it read and wrote, used by
	// par::conflicts() to decide whether two chunks may run at the same time.
	//
	// Layout recovered from the two callbacks:
	//
	//   +0x00  page_set        read pages      (on_get inserts here)
	//   +0x38  page_set        written pages   (on_put inserts here)
	//   +0x70  vector<access>  reads           (8 bytes per entry)
	//   +0x88  vector<access>  writes          (8 bytes per entry)
	//   +0xa0  u32*            pages of interest
	//   +0xa8  u64*            their timestamps
	//   +0xb0  u32             capacity of those two arrays
	//   +0xb4  u32             how many are filled
	class tracker
	{
	public:
		// Arms one slot of the watch arrays at +0xa0 / +0xa8. The fork fills
		// those in from par::conflicts' `read_pages`, so this is the only way
		// the rdtsc stamp inside on_get is ever taken.
		void watch(u32 addr)
		{
			m_watch_pages.push_back(addr);
			m_watch_stamps.push_back(0);
			m_watch_cap = static_cast<u32>(m_watch_pages.size());
		}

		// on_get (0x143b46920): records {addr, size}, inserts every 4 KB page
		// of [addr, addr + size) into the read set, and stamps the access when
		// the page is the one the caller asked about:
		//
		//   0x143b4693a  mov  rcx, qword ptr [rdi + 0xa0]
		//   0x143b46941  cmp  esi, dword ptr [rcx + rax*4]
		//   0x143b46946  rdtsc
		void on_get(u32 addr, u32 size);

		// on_put (0x143b46d30): the same, against the written set at +0x38.
		void on_put(u32 addr, u32 size);

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
		u32 m_watch_cap = 0;   // +0xb0
		u32 m_watch_count = 0; // +0xb4
		u64 m_watch_clock = 0;
	};

	// -----------------------------------------------------------------------
	// The launcher
	// -----------------------------------------------------------------------

	// The three call sites the fork's handler switches on. Two are compared
	// against lr directly:
	//
	//   0x143a19f4d  cmp esi, 0x14ce2c     ; call site 0x14ce28
	//   0x143a19f55  cmp esi, 0x14cea4     ; call site 0x14cea0
	//   0x143a19ffc  xor esi, esi          ; neither -> not this handler
	//
	// and the third, 0x14cdb0, is not compared at all and so always falls into
	// the "not mine" arm. `lea r12d, [rsi - 4]` at 0x143a19f49 is the call
	// site the hook table keys on.
	inline constexpr u32 site_chara = 0x0014cea0u; // lr 0x14cea4
	inline constexpr u32 site_bg = 0x0014ce28u;    // lr 0x14ce2c
	inline constexpr u32 site_other = 0x0014cdb0u; // not special-cased

	// Which of the three fired, or none.
	enum class site_kind
	{
		none,
		chara,
		bg,
		other,
	};

	site_kind classify_site(u32 call_site);

	// The launcher's result block. Recovered as the zeroing at 0x143a19ef5
	// through 0x143a1a0f3 and as the three stores detail::run makes into it:
	//
	//   0x143a1a0ea  vmovups xmmword ptr [rsp + 0xa0], xmm0   ; +0x04 .. +0x14
	//   0x143ac5bc7  mov dword ptr [r12 + 0xc], ebp
	//   0x143ac5c11  mov dword ptr [r12 + 0x10], eax
	//
	// The 8-byte store at +0x14 (`mov qword ptr [r12 + 0x14], 0`) is unaligned
	// in the fork's own layout too, so the padding between +0x14 and +0x18 is
	// reproduced rather than guessed at: the block is 0x48 bytes as declared.
	struct result
	{
		status code = status::none; // +0x00, the 9-entry status table's index
		u8 reserved_01 = 0;         // +0x01, run's 0/1/2 "sub" code
		u32 word_04 = 0;            // +0x04
		u32 word_08 = 0;            // +0x08
		u32 word_0c = 0;            // +0x0c, a guest header word
		u32 word_10 = 0;            // +0x10, a guest header word
		u32 qword_14_lo = 0;        // +0x14, the low half of the fork's
		u32 qword_14_hi = 0;        // +0x18, unaligned 8-byte store
		u64 qword_1c = 0;           // +0x20 (the fork stores it at +0x1c)
		u8 reserved_28[0x20] = {};  // +0x28 .. +0x48
	};

	static_assert(sizeof(result) == 0x48);

	// The launcher's front end, run from the hook body.
	//
	// Reproduced in full: the level gate, the site switch, the two page-map
	// guards, the SPURS_TaskStart argument checks, the 0x5c180 scratch
	// allocation, read_spurs_args, load_image and the reporting of the status
	// string into the fork's decline triple. detail::run - the lifter - is not
	// reproduced, so this always reports `lifted_code_declined` and leaves
	// result.handled false, which runs the guest's own modelsetup.
	void launch(ppu_thread& cpu, spu_task_hle::ppu::direct_mem& mem,
	            const spu_task_hle::ppu::call_regs& regs, spu_task_hle::ppu::call_result& out);

	// Frees the per-image scratch buffers. Called from spu_task_hle::reset().
	void reset();
}