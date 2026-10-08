// Unit test for the drawassist 4f20 front end.
//
// The dispatch is the part of mgo_drawassist_4f20 that is fully recovered from
// the reference image, so it can be tested without the emulator: the record
// walk, the opcode table, the inline op22 palette store, the preconditions and
// the integrity scan are all host logic over a plain buffer.
//
// Build and run (no RPCS3 headers needed):
//   g++ -std=c++20 -O1 -o mgo_drawassist_test buildfiles/mgo_drawassist_test.cpp
//   ./mgo_drawassist_test

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using usz = std::size_t;

namespace mgo_da4f20_detail
{
	struct payload
	{
		u32 word[4] = {};
	};

	enum class error : u8
	{
		none,
		record_count,
		context_misaligned,
		stack_pointer,
		ctx_stack_code_overlap,
		records_overlap,
		record_arrays,
		palette_row,
		code_modified,
		ea_ptr_failed,
	};

	struct task_env
	{
		u8* image = nullptr;
		const u8* pristine = nullptr;
		const u32* commands = nullptr;
		const payload* payloads = nullptr;
		u32 count = 0;
		u32 context = 0;
		u32 stack = 0;
		u32 code_base = 0;
		u32 code_size = 0;
		u32 records_base = 0;
		static constexpr u32 palette_offset = 0x8f0;
		u32 palette_rows = 2;
		static constexpr u32 integrity_base = 0x3000;
		static constexpr u32 bitmap_offset = 0xcf4b;
		static constexpr u32 bitmap_first_bit = 12;
		static constexpr u32 bitmap_last_bit = 0x34;
		static constexpr u32 block_bytes = 0x400;
		static constexpr u32 integrity_window = integrity_base + (bitmap_last_bit + 1) * block_bytes;
		static constexpr u32 region_bytes = 0x1000;
	};

	// ---- the code under test, mirrored from drawassist_hooks.cpp ----------

	static u32 swap32(const u32 value)
	{
		return (value >> 24) | ((value >> 8) & 0x0000ff00u) | ((value << 8) & 0x00ff0000u) | (value << 24);
	}

	bool overlaps(const u32 a, const u32 asize, const u32 b, const u32 bsize)
	{
		return a < b + bsize && b < a + asize;
	}

	bool integrity_holds(const task_env& env, u32* modified_block = nullptr)
	{
		if (modified_block)
		{
			*modified_block = 0;
		}

		if (!env.image || !env.pristine)
		{
			return true;
		}

		u64 blocks = 0;
		const u8* bytes = env.image + task_env::bitmap_offset;

		for (u32 bit = 0; bit < 64; bit++)
		{
			blocks |= static_cast<u64>((bytes[bit >> 3] >> (bit & 7)) & 1) << bit;
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

	bool run_record(task_env& env, const u32 command, const payload& args, error& err)
	{
		const u32 opcode = command >> 24;

		if (opcode >= 0x20 || opcode == 0)
		{
			err = error::palette_row;
			return false;
		}

		const u32 row = (command >> 16) & 0xff;

		if (opcode == 22)
		{
			if (row >= env.palette_rows)
			{
				err = error::palette_row;
				return false;
			}

			if (env.image)
			{
				std::memcpy(env.image + task_env::palette_offset + row * sizeof(payload), &args, sizeof(payload));
			}

			return true;
		}

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
			error rec_err = error::none;

			if (run_record(env, swap32(env.commands[i]), env.payloads[i], rec_err) || rec_err == error::none)
			{
				handled++;
			}
			else if (err == error::none)
			{
				err = rec_err;
			}
		}

		u32 block = 0;

		if (!integrity_holds(env, &block))
		{
			err = error::code_modified;
		}

		return handled;
	}
}

// ---- the test -----------------------------------------------------------

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

// A well-formed environment: a zeroed image big enough for the integrity
// window, with every block bit set so the scan actually compares something.
static std::vector<u8> make_image()
{
	using te = mgo_da4f20_detail::task_env;
	std::vector<u8> image(te::integrity_window + 0x1000, 0);

	for (u32 bit = 0; bit < 64; bit++)
	{
		image[te::bitmap_offset + (bit >> 3)] |= static_cast<u8>(1u << (bit & 7));
	}

	return image;
}

int main()
{
	using te = mgo_da4f20_detail::task_env;
	using mgo_da4f20_detail::error;

	std::printf("== preconditions\n");

	{
		std::vector<u32> commands(1, 0x00000016u); // opcode 22, row 0
		mgo_da4f20_detail::payload payloads[1]{};
		te env{};
		env.commands = commands.data();
		env.payloads = payloads;
		env.count = 0;
		error err = error::none;

		check(mgo_da4f20_detail::dispatch(env, err) == 0 && err == error::record_count,
			"an empty record array is refused");
	}

	{
		std::vector<u32> commands(1, 0x00160000u);
		mgo_da4f20_detail::payload payloads[1]{};
		te env{};
		env.commands = commands.data();
		env.payloads = payloads;
		env.count = 1;
		env.context = 0x1002; // misaligned
		env.stack = 0x100;
		error err = error::none;

		check(mgo_da4f20_detail::dispatch(env, err) == 0 && err == error::context_misaligned,
			"a misaligned context is refused");
	}

	{
		std::vector<u32> commands(1, 0x00160000u);
		mgo_da4f20_detail::payload payloads[1]{};
		te env{};
		env.commands = commands.data();
		env.payloads = payloads;
		env.count = 1;
		env.context = 0x1000;
		env.stack = 0x2000; // above the context
		error err = error::none;

		check(mgo_da4f20_detail::dispatch(env, err) == 0 && err == error::stack_pointer,
			"a stack pointer above the context is refused");
	}

	std::printf("\n== opcode 22, the inline palette row\n");

	{
		std::vector<u8> image = make_image();
		std::vector<u32> commands;
		mgo_da4f20_detail::payload payloads[3]{};

		// Three op22 records: rows 0, 1 and 2. The guest word is
		// [opcode][row][-][-], and the array holds it byte-swapped, because
		// the dispatch swaps on the way in - so the row sits in the array's
		// second byte, not its third.
		commands = {0x00000016u, 0x00000116u, 0x00000216u};

		for (u32 i = 0; i < 3; i++)
		{
			payloads[i].word[0] = 0x1000 + i;
			payloads[i].word[3] = 0x2000 + i;
		}

		te env{};
		env.image = image.data();
		env.commands = commands.data();
		env.payloads = payloads;
		env.count = 3;
		env.context = 0x2000;
		env.stack = 0x1000;
		env.code_base = 0x8000;
		env.code_size = 0x10000;
		env.records_base = 0x100;
		error err = error::none;

		const usz handled = mgo_da4f20_detail::dispatch(env, err);

		std::printf("        [debug] handled=%llu err=%d first=%02x %02x %02x %02x",
			static_cast<unsigned long long>(handled), static_cast<int>(err),
			image.data()[te::palette_offset], image.data()[te::palette_offset + 1],
			image.data()[te::palette_offset + 2], image.data()[te::palette_offset + 3]);

		check(handled == 2, "two of three palette rows are accepted");
		check(err == error::palette_row, "row 2 is refused with the fork's own reason");

		// The command words are stored big-endian, so the file's array holds
		// them byte-swapped on a little-endian host. Reading them back must
		// give back the same opcode and row.
		u32 row0 = 0, row1 = 0;
		std::memcpy(&row0, image.data() + te::palette_offset, 4);
		std::memcpy(&row1, image.data() + te::palette_offset + 16, 4);

		check(row0 == 0x1000, "row 0 payload landed at ctx + 0x8f0");
		check(row1 == 0x1001, "row 1 payload landed at ctx + 0x8f0 + 16");
		check(image[te::palette_offset + 32] == 0, "row 2 wrote nothing");
	}

	{
		std::vector<u32> commands(1, 0x00000020u); // opcode 0x20: refused
		mgo_da4f20_detail::payload payloads[1]{};
		te env{};
		env.commands = commands.data();
		env.payloads = payloads;
		env.count = 1;
		env.context = 0x2000;
		env.stack = 0x1000;
		env.code_base = 0x8000;
		env.code_size = 0x10000;
		env.records_base = 0x100;
		error err = error::none;

		mgo_da4f20_detail::dispatch(env, err);
		check(err != error::none, "opcode 0x20 is outside the table and is refused");
	}

	std::printf("\n== the integrity scan\n");

	{
		std::vector<u8> live = make_image();
		std::vector<u8> pristine = live;

		te env{};
		env.image = live.data();
		env.pristine = pristine.data();

		u32 block = 0;
		check(mgo_da4f20_detail::integrity_holds(env, &block), "an untouched image passes");

		// Flip one byte inside block 0x20, which the bitmap selects.
		live[te::integrity_base + 0x20 * te::block_bytes + 7] ^= 0xff;

		check(!mgo_da4f20_detail::integrity_holds(env, &block), "a modified code block fails the scan");
		check(block == 0x20, "the failing block index is reported");
	}

	{
		// The bitmap is *self-referential*: the fork expands it out of the
		// live image at +0xcf4b, and 0xcf4b lies inside the very window the
		// scan compares. So editing the map is itself a code modification and
		// the scan catches it.
		std::vector<u8> live = make_image();
		std::vector<u8> pristine = live;
		live[te::bitmap_offset + (0x20 >> 3)] &= static_cast<u8>(~(1u << (0x20 & 7)));

		te env{};
		env.image = live.data();
		env.pristine = pristine.data();

		u32 block = 0;
		check(!mgo_da4f20_detail::integrity_holds(env, &block),
			"editing the block map trips the scan, because the map is inside the window");
		check(block == 39, "the map's own block is the one reported");
	}

	{
		// Clearing a bit in *both* copies skips that block, which is the only
		// way the map can legitimately shrink.
		std::vector<u8> live = make_image();
		std::vector<u8> pristine = live;
		for (u8* image : { live.data(), pristine.data() })
		{
			image[te::bitmap_offset + (0x20 >> 3)] &= static_cast<u8>(~(1u << (0x20 & 7)));
		}

		live[te::integrity_base + 0x20 * te::block_bytes + 7] ^= 0xff;

		te env{};
		env.image = live.data();
		env.pristine = pristine.data();

		check(mgo_da4f20_detail::integrity_holds(env),
			"a block excluded from the map in both copies is not compared");
	}

	std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}