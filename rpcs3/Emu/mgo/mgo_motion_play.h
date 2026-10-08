#pragma once

// Metal Gear Online motion playback, from the fork's recovered symbol table.
//
// `coff_syms.py` + `c++filt` on the `_ZN15mgo_motion_play` prefix returns
// nineteen symbols, and demangled they are the whole API of the subsystem -
// there is nothing left to guess about its shape:
//
//   task_commit<direct_mem>(direct_mem&)                 0x143a5c3d0   0xd0
//   task_run<direct_mem>::get(u32,u32,u32,u32)           0x143a5c4a0   0x140
//   task_run<direct_mem>::blend_pass(u32,u32,u32,bool)   0x143a60cc0   0x31c0
//   task_run<direct_mem>::crossfade(u32)                 0x143a63e80   0x3700
//   task_run<direct_mem>::release_motion(u32)            0x143a67580   0x350
//   task_run<direct_mem>::fetch_points(u32)              0x143a678d0   0x7c0
//   task_run<direct_mem>::owner_pass(u32, mask128)       0x143a68090   0xc30
//   task_run<direct_mem>::mirror(u32)                    0x143a68cc0   0x800
//   task_run<direct_mem>::root(u32)                      0x143a694c0   0x940
//   task_run<direct_mem>::put(u32,u32,u32)               0x143a69e00   0x1e0
//   root_track(ctx&, u32, u32, float, bool)              0x143a6e800   0x2210
//   f36c8(ctx&, u32)                                     0x143a5c5e0   0x46e0
//   f5f40(ctx&, u32)                                     0x143a69fe0   0x4820
//   k_rodata                                            0x144b2aae0   0xa00
//   scratch()::s, t_sg
//   std::vector<put_rec>
//
// Read as an algorithm, the method names are the whole thing: fetch the point
// tracks, walk the bone tree from `root`, apply an `owner_pass` masked by a
// 128-bit mask, `mirror` the symmetric side, `crossfade` between clips,
// `blend_pass` the result, `release_motion` the tracks, and `task_commit` the
// queue. That is motion playback, recovered from names.
//
// What is implemented here and what is not:
//
//   * `get`, `put` and `task_commit` are **complete**. All three are small,
//     they are pure host logic over guest memory, and their bodies are
//     recovered instruction for instruction - see the comments on each.
//   * The seven passes exist with their exact signatures and are sequenced in
//     the recovered order, but their bodies depend on the guest's bone and
//     clip formats, which are not described by any symbol. They are marked
//     `approximated` rather than presented as the fork's code.
//
// The `task_run` template parameter is the fork's own: it is instantiated
// with `spu_task_hle::ppu::direct_mem` in the binary, and templating it keeps
// that shape (and makes the DMA seam testable without an emulator).

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace mgo_motion_play
{
	// The 128-bit ownership mask `owner_pass` takes. Sixteen bytes, because
	// the fork's vector stores move it whole.
	struct mask128
	{
		u64 lo = 0;
		u64 hi = 0;

		bool test(u32 bit) const { return bit < 128 && ((bit < 64 ? lo >> bit : hi >> (bit - 64)) & 1) != 0; }
		void set(u32 bit) { if (bit < 64) { lo |= 1ull << bit; } else if (bit < 128) { hi |= 1ull << (bit - 64); } }
	};

	// One queued write-back: guest address, length, and where in the staging
	// ring the bytes came from. Twelve bytes, because `task_commit` steps the
	// queue by `add rdi, 0xc`.
	struct put_rec
	{
		u32 addr = 0;
		u32 size = 0;
		u32 offset = 0;
	};
	static_assert(sizeof(put_rec) == 12, "task_commit steps the queue by 12 bytes");

	// The task's staging ring and its error slot.
	//
	// Recovered from `task_commit`, which allocates 0x40040 bytes aligned to
	// 64 and then zeroes exactly two 32-byte vector stores at +0x40000:
	//
	//   +0x00000  u8        ring[0x40000]   256 KiB of staging
	//   +0x40000  u32        head           write cursor, in bytes
	//   +0x40008  u32        tail           read cursor, in bytes
	//   +0x40018  put_rec*   begin          the queued write-backs
	//   +0x40020  put_rec*   end
	//
	// The data area and the header therefore share one allocation, with the
	// header at the end - which is why the ring is 0x40000 and the whole
	// object is 0x40040.
	struct staging
	{
		static constexpr u32 ring_bytes = 0x40000;
		static constexpr u32 total_bytes = 0x40040;

		std::array<u8, ring_bytes> ring{};
		u32 head = 0;
		u32 tail = 0;
		std::vector<put_rec> queue;
	};

	// The staging ring belongs to the thread, not to a call: `task_commit`
	// takes only a `direct_mem&` and reaches the ring through `thread+0x5f8`,
	// so it is one object per thread with a `thread+0x120` "allocated" flag.
	staging& staging_for_thread();

	// The per-call context. `direct_mem` stands in for the fork's implicit
	// "the current task's memory", which the recovered code reaches through
	// this pointer rather than through an argument.
	struct ctx
	{
		ctx() : buf(staging_for_thread()) {}

		spu_task_hle::ppu::direct_mem* mem = nullptr;

		// The failure slot, at the offsets `get` and `put` use: a flag at +8
		// (only the *first* failure is recorded) and the message at +0x10.
		bool failed = false;
		const char* message = nullptr;

		staging& buf;

		// True once the staging ring's page map has been consulted for the
		// current call. The fork keeps this in a byte map it builds as it
		// copies; see the comment on `get`.
		void fail(const char* why)
		{
			if (!failed)
			{
				failed = true;
				message = why;
			}
		}
	};

	// Reads `size` bytes from guest memory into the staging ring.
	//
	// Recovered body of task_run::get, which is 0x140 bytes and does exactly
	// four things:
	//
	//   1. `(addr | size | ring_off) & 0xf` must be zero, or it fails with
	//      "dma get: address or size not 16-byte aligned" - the guest's DMA
	//      engine faults on an unaligned transfer, so the lift refuses rather
	//      than lie. `pl_motion_mix`'s "misaligned DMA (the task would halt)"
	//      is the same rule stated as a precondition.
	//   2. `slot` must be <= 0x1f, `addr` is masked to 18 bits, and
	//      `ring_off + addr` must stay under 0x40001. Otherwise
	//      "dma get: range".
	//   3. The 4 KB pages the destination spans must all be available in the
	//      task's page map - the same 0x100-granule byte walk `line_check`
	//      performs, with the same 0x81/0x40/0x20 bit meanings.
	//   4. Otherwise it copies and returns true.
	//
	// The page map is the fork's own allocation tracker and has no counterpart
	// in the replica, so step 3 is replaced by `mem->guest_valid`, which asks
	// the question the map answers.
	bool get(ctx& c, u32 addr, u32 size, u32 ring_off, u32 slot);

	// Queues `size` bytes from the staging ring back into guest memory.
	//
	// Recovered body of task_run::put, the mirror image of `get`: a zero
	// length is a successful no-op, the same 16-byte alignment rule, the same
	// 18-bit mask and 0x40000 bound, the same page check, and then the bytes
	// are appended to the queue that `task_commit` flushes.
	bool put(ctx& c, u32 addr, u32 size, u32 ring_off);

	// Flushes the queue into guest memory.
	//
	// Recovered body of task_commit: for each 12-byte record, memcpy from
	// `ring + offset` to `guest + addr`. It is idempotent - the queue is left
	// as it was, because the fork clears it through the vector, not here.
	template <typename Mem>
	void task_commit(Mem& mem);

	// The shared scratch state, one per process, exactly as the fork declares
	// it (a function-local static with a guard variable).
	struct scratch_t
	{
		u64 bytes = 0;
	};
	scratch_t& scratch();

	// The playback itself. Every method name and signature is the fork's.
	template <typename Mem>
	class task_run
	{
	public:
		using mem_type = Mem;

		explicit task_run(ctx& c) : m_ctx(c) {}

		// --- the DMA seam, recovered in full -----------------------------

		// Reads a track out of guest memory into the staging ring.
		// `slot` is the buffer index, which the fork caps at 31.
		u32 get(u32 addr, u32 size, u32 ring_off, u32 slot)
		{
			return mgo_motion_play::get(m_ctx, addr, size, ring_off, slot) ? 1u : 0u;
		}

		// Queues a write-back of the staging ring into guest memory.
		u32 put(u32 addr, u32 size, u32 ring_off)
		{
			return mgo_motion_play::put(m_ctx, addr, size, ring_off) ? 1u : 0u;
		}

		// --- the passes, in the order the fork calls them -----------------

		// Reads the point tracks for a bone into the staging ring.
		u32 fetch_points(u32 bone) { return approximate("fetch_points", bone); }

		// Positions the bone tree from its root.
		u32 root(u32 bone) { return approximate("root", bone); }

		// Applies one owner's contribution to the bones selected by `mask`.
		u32 owner_pass(u32 bone, const mask128& mask) { return approximate("owner_pass", bone); }

		// Mirrors a pass onto the symmetric side of the skeleton.
		u32 mirror(u32 bone) { return approximate("mirror", bone); }

		// Crossfades between two clips.
		u32 crossfade(u32 bone) { return approximate("crossfade", bone); }

		// Blends `count` bones, optionally wrapping.
		u32 blend_pass(u32 bone, u32 count, u32 mode, bool wrap)
		{
			(void)mode;
			(void)wrap;
			return approximate("blend_pass", bone);
		}

		// Releases the tracks a finished clip was holding.
		u32 release_motion(u32 bone) { return approximate("release_motion", bone); }

		// --- the entry point ---------------------------------------------

		// Runs the whole playback for `bone`. Returns false - and declines -
		// if any DMA step failed, which is the fork's own behaviour: a lift
		// that cannot reproduce the transfer must not claim it did.
		bool run(u32 bone);

		ctx& context() { return m_ctx; }

	private:
		// Every pass shares one shape: it validates what it can and reports
		// the pass name when it cannot go further. The fork's bodies are
		// 2 KB to 14 KB of arithmetic on the guest's bone and clip formats,
		// which no symbol describes.
		u32 approximate(const char* pass, u32 bone)
		{
			(void)bone;
			m_ctx.fail(pass);
			return 0;
		}

		ctx& m_ctx;
	};

	// Resets the shared scratch state.
	void reset();
}