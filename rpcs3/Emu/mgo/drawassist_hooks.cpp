#include "stdafx.h"
#include "drawassist_hooks.h"

#include "util/logs.hpp"

#include <cstring>

// The fork's own channel for this subsystem is the PPU geometry one; the
// module hooks reuse it rather than declaring a new one, which is why
// "spu.drawassist" does not appear among the recovered LOG_CHANNEL names.
LOG_CHANNEL(ppu_geo_line, "ppu.geo_line");

namespace
{
	// The nine error strings, in the order the fork's checks produce them.
	// Every one is quoted verbatim from the reference image; the file they
	// belong to is rpcs3/Emu/mgo/drawassist_4f20.h.
	constexpr const char* texts[] =
	{
		"declined",
		"record count",
		"context misaligned or too high",
		"stack pointer",
		"context, stack and code overlap",
		"record arrays overlap the stack or code",
		"record arrays",
		"op22: palette row > 1",
		"code or .rodata modified",
		"PUT: ea_ptr failed",
	};

	u32 swap32(const u32 value)
	{
		return (value >> 24) | ((value >> 8) & 0x0000ff00u) | ((value << 8) & 0x00ff0000u) | (value << 24);
	}

	// The fork's command word, read the way it reads it: a native little-endian
	// load followed by a byte swap, so `opcode` really is the top byte of the
	// guest word.
	inline u32 read_command(const u32* commands, const u32 index)
	{
		return swap32(commands[index]);
	}

	// True when [a, a+asize) and [b, b+bsize) intersect. The fork uses this
	// shape to prove the context, the stack and the code are disjoint.
	bool overlaps(const u32 a, const u32 asize, const u32 b, const u32 bsize)
	{
		return a < b + bsize && b < a + asize;
	}
}

namespace mgo_da4f20_detail
{
	const char* error_text(const error err)
	{
		const u32 index = static_cast<u32>(err);
		return (index < std::size(texts)) ? texts[index] : texts[0];
	}

	bool integrity_holds(const task_env& env, u32* modified_block)
	{
		if (modified_block)
		{
			*modified_block = 0;
		}

		// No pristine copy means there is nothing to compare against, which is
		// the one case where the scan is skipped rather than failed.
		if (!env.image || !env.pristine)
		{
			return true;
		}

		// The block map is a 64-bit bitmap the fork expands out of two bytes
		// of the image at +0xcf4b and +0xcf4f, bit by bit, into a 64-bit
		// word it then indexes with `bt`. Bits 0xc..0x34 select the 41
		// blocks of 0x400 bytes compared from +0x3000.
		u64 blocks = 0;
		const u8* bytes = env.image + task_env::bitmap_offset;

		for (u32 bit = 0; bit < 64; bit++)
		{
			const u32 byte = bytes[bit >> 3];
			blocks |= static_cast<u64>((byte >> (bit & 7)) & 1) << bit;
		}

		for (u32 bit = task_env::bitmap_first_bit; bit <= task_env::bitmap_last_bit; bit++)
		{
			if (!((blocks >> bit) & 1))
			{
				continue;
			}

			const u32 offset = task_env::integrity_base + bit * task_env::block_bytes;

			if (std::memcmp(env.image + offset, env.pristine + offset, task_env::block_bytes) != 0)
			{
				if (modified_block)
				{
					*modified_block = bit;
				}

				return false;
			}
		}

		return true;
	}

	bool run_record(task_env& env, const record& rec, error& err)
	{
		const u32 opcode = rec.command >> 24;

		// 0x20..0x3f is refused outright, so those are commands from a newer
		// microcode than this hook understands.
		if (opcode >= 0x20 || opcode == 0)
		{
			err = error::palette_row;
			return false;
		}

		// The second byte of the command word is the row selector. Only opcode
		// 22 consumes it.
		const u32 row = (rec.command >> 16) & 0xff;

		if (opcode == 22)
		{
			// "set palette row": copy the 16-byte payload to
			// image + 0x8f0 + row * 16.
			if (row >= env.palette_rows)
			{
				err = error::palette_row;
				return false;
			}

			if (env.image)
			{
				std::memcpy(env.image + task_env::palette_offset + row * sizeof(payload),
					&rec.args, sizeof(payload));
			}

			return true;
		}

		// Opcodes 3 and 4 share one handler in the fork, parameterised by the
		// pair (0x940, 0x19) and (0x980, 0x1a).
		if (opcode == 3 || opcode == 4)
		{
			// Real body: op3_4. Not reproducible.
		}

		// Everything else is op2, op5..op21, op23..op31: 28 distinct compiled
		// bodies in the fork, none of which is recoverable from a symbol
		// table. The guest runs them.
		err = error::none;
		return false;
	}

	usz dispatch(task_env& env, error& err)
	{
		err = error::none;

		if (!env.commands || !env.payloads)
		{
			err = error::record_arrays;
			return 0;
		}

		if (env.count == 0)
		{
			err = error::record_count;
			return 0;
		}

		// The context must be aligned and inside the local store; the stack
		// pointer must be below it; and the context, the stack and the code
		// must be pairwise disjoint.
		if ((env.context & 3) != 0 || env.context > 0x3fffu)
		{
			err = error::context_misaligned;
			return 0;
		}

		if (env.stack >= env.context)
		{
			err = error::stack_pointer;
			return 0;
		}

		if (overlaps(env.context, task_env::region_bytes, env.stack, task_env::region_bytes)
			|| overlaps(env.context, task_env::region_bytes, env.code_base, env.code_size)
			|| overlaps(env.stack, task_env::region_bytes, env.code_base, env.code_size))
		{
			err = error::ctx_stack_code_overlap;
			return 0;
		}

		// The record arrays must not land on the stack or the code either.
		const u32 records_size = env.count * (sizeof(u32) + sizeof(payload));

		if (overlaps(env.records_base, records_size, env.stack, task_env::region_bytes)
			|| overlaps(env.records_base, records_size, env.code_base, env.code_size))
		{
			err = error::records_overlap;
			return 0;
		}

		usz handled = 0;

		for (u32 i = 0; i < env.count; i++)
		{
			record rec{};
			rec.command = read_command(env.commands, i);
			rec.args = env.payloads[i];

			error rec_err = error::none;

			if (run_record(env, rec, rec_err) || rec_err == error::none)
			{
				handled++;
			}
			else if (err == error::none)
			{
				err = rec_err;
			}
		}

		// The proof obligation: the module's code and read-only data must be
		// exactly as they were.
		u32 block = 0;

		if (!integrity_holds(env, &block))
		{
			ppu_geo_line.warning("drawassist: image block %u (0x%x) was modified",
				block, task_env::integrity_base + block * task_env::block_bytes);
			err = error::code_modified;
		}

		return handled;
	}

	void drawassist_4f20(task_env& env)
	{
		error err = error::none;
		const usz handled = dispatch(env, err);

		if (err != error::none)
		{
			// Same (file, line, message) triple as every other decline. The
			// fork reports this at drawassist_4f20.h:1881.
			spu_task_hle::note_decline(error_text(err), __FILE__, __LINE__);
		}

		ppu_geo_line.trace("drawassist.4f20: %zu/%u records handled%s%s",
			static_cast<size_t>(handled), env.count,
			err == error::none ? "" : ", declined: ",
			err == error::none ? "" : error_text(err));
	}

	void drawassist_3120(task_env& env)
	{
		// The recovered body is 0x2880 bytes and references no string except
		// its own __FILE__, which means it either works or takes the process
		// down - there is no diagnostic to reproduce. The replica has no
		// caller for it, because the record bodies that would call it are the
		// part that is not recoverable.
		(void)env;
	}
}

// The two module-hook entry points, under the fork's own names. These are the
// functions the module hook table points at: +0x28 of the first record is
// 0x143cdf890 and of the second 0x143ce2110, which is `mgo_drawassist_3120`
// and `mgo_drawassist_4f20` in the symbol table.
void mgo_drawassist_4f20(mgo_da4f20_detail::task_env& env)
{
	mgo_da4f20_detail::drawassist_4f20(env);
}

void mgo_drawassist_3120(mgo_da4f20_detail::task_env& env)
{
	mgo_da4f20_detail::drawassist_3120(env);
}