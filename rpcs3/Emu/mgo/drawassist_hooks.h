#pragma once

// Metal Gear Online draw-assist acceleration: the SPU module hook side.
//
// Two module hooks live on the same embedded SPU image
// (SPU-9aa78281dd97ec8c28423426165ebf42d00dd44e, module
// spu/spurs_drawassist.spu.task):
//
//   drawassist.3120   0x143cdf890   0x2880 bytes   the back-end kernel
//   drawassist.4f20   0x143ce2110   0x0bb0 bytes   the command-stream front end
//
// Both take a single `task_env&`. That type is the fork's per-task environment
// for module hooks; the binary never names it outside these two functions, so
// this header models only the fields the recovered code actually reads.
//
// 4f20 is fully decoded at the front end. It walks an array of 16-byte records,
// reads one command word per record, dispatches on the command's top byte
// through a 31-entry jump table, and afterwards proves it did not disturb the
// module's code. The 30 per-command bodies and the whole of 3120 are ordinary
// compiled C++ that reimplement SPURS drawassist; they are not recoverable from
// a symbol table, so the replica dispatches the records it can account for,
// declines every other one with the fork's own wording, and lets the guest run
// its original microcode unchanged.

#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

// The fork's two module-hook entry points, with the fork's own names and
// signatures. They are the functions the module hook table points at
// (+0x28 = 0x143cdf890 and 0x143ce2110), and both take the per-task
// environment by reference.
void mgo_drawassist_4f20(mgo_da4f20_detail::task_env& env);
void mgo_drawassist_3120(mgo_da4f20_detail::task_env& env);

namespace mgo_da4f20_detail
{
	// One record's payload: four big-endian u32s, copied as a single 16-byte
	// vector by the fork (`vmovdqu xmm0, [rax + rbp]` /
	// `vmovdqa [rsp+0x90], xmm0`), so it is 16-byte aligned and has no
	// padding. The fork's type for this is in an anonymous namespace
	// (`NS_7payload` in the mangling) and so has no linkage name.
	struct payload
	{
		u32 word[4] = {};
	};

	// A record is the command word plus its payload. The two live in
	// *separate* arrays: the fork reads the command from `[task + commands +
	// 4*i]` and the payload from `[task + 0x10*i]`, walking both with
	// independent indices. Command words are big-endian, like every other
	// guest word the fork reads.
	struct record
	{
		u32 command = 0;
		payload args = {};
	};

	// Why the hook declined. Every string is the fork's own, quoted verbatim
	// from drawassist_4f20.h; all of them are reported through the same
	// (file, line, message) triple as every other decline, at line 1881.
	enum class error : u8
	{
		none,
		record_count,                    // "record count"
		context_misaligned,              // "context misaligned or too high"
		stack_pointer,                   // "stack pointer"
		ctx_stack_code_overlap,          // "context, stack and code overlap"
		records_overlap,                 // "record arrays overlap the stack or code"
		record_arrays,                   // "record arrays"
		palette_row,                     // "op22: palette row > 1"
		code_modified,                   // "code or .rodata modified"
		ea_ptr_failed,                   // "PUT: ea_ptr failed"
	};

	// The fork's wording, or "declined" for `none`.
	const char* error_text(error err);

	// The per-task environment, as far as the recovered code reads it.
	//
	// The module's code and read-only data are held twice: once live, once as
	// a pristine copy. 4f20 compares them block by block when it finishes, and
	// treats any difference as fatal, so both must be at least
	// `integrity_window` bytes of image.
	struct task_env
	{
		// The deployed image. `image + integrity_base` is where the integrity
		// scan starts, and `image + bitmap_offset` holds the two bytes the
		// fork expands into the 41-bit block map.
		u8* image = nullptr;

		// A pristine copy of the same region, or null to skip the scan.
		const u8* pristine = nullptr;

		// The record arrays, as two parallel spans of `count` entries.
		const u32* commands = nullptr;
		const payload* payloads = nullptr;
		u32 count = 0;

		// The SPU task context pointer and the guest stack pointer. 4f20
		// requires the context to be aligned and below the top of the local
		// store, requires the stack pointer to be sane, and requires the
		// context, the stack and the code to be pairwise disjoint.
		//
		// `code_base`/`code_size` and `records_base` are *guest* addresses.
		// They are separate fields rather than image offsets because comparing
		// a guest pointer against an image offset would silently succeed or
		// fail for reasons that have nothing to do with aliasing.
		u32 context = 0;
		u32 stack = 0;
		u32 code_base = 0;
		u32 code_size = 0;
		u32 records_base = 0;

		// Palette rows live at `image + palette_offset + row * 16`, and the
		// fork refuses any row >= palette_rows.
		static constexpr u32 palette_offset = 0x8f0;
		u32 palette_rows = 2;

		// Image layout constants, all recovered as immediates.
		static constexpr u32 integrity_base = 0x3000;
		static constexpr u32 bitmap_offset = 0xcf4b;
		static constexpr u32 bitmap_first_bit = 12;
		static constexpr u32 bitmap_last_bit = 0x34;  // 41 blocks
		static constexpr u32 block_bytes = 0x400;
		static constexpr u32 integrity_window = integrity_base + (bitmap_last_bit + 1) * block_bytes;

		// How much space the context and the stack need. Not recovered as
		// immediates - the fork compares addresses, not extents - so these are
		// the page each is assumed to occupy.
		static constexpr u32 region_bytes = 0x1000;
	};

	// True when the live image still matches the pristine copy across every
	// block the bitmap selects, i.e. the fork's post-run integrity proof.
	// `modified_block` receives the first offending block index.
	bool integrity_holds(const task_env& env, u32* modified_block = nullptr);

	// Runs one record. Returns true when the record was fully accounted for.
	//
	// Opcode 22 ("set palette row") is handled here rather than through a
	// function pointer, which is why the fork has no `op22` symbol at all. The
	// other 29 named opcodes are real compiled bodies that the replica cannot
	// reproduce, so they set `err` and return false.
	bool run_record(task_env& env, const record& rec, error& err);

	// The whole command stream. Walks every record, keeps the first error, and
	// then runs the integrity scan. Returns the number of records handled.
	usz dispatch(task_env& env, error& err);

	// mgo_drawassist_4f20: validate, dispatch, verify, report.
	void drawassist_4f20(task_env& env);

	// mgo_drawassist_3120: the back-end kernel. The recovered function
	// references no strings except its own __FILE__, so there is nothing to
	// report; it is called from the record bodies, which the replica does not
	// have, so it is only reachable as a stub.
	void drawassist_3120(task_env& env);
}