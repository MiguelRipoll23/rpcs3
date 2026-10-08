#include "stdafx.h"
#include "mgo_modelsetup.h"

#include "util/logs.hpp"

#include <cstring>
#include <memory>

// The fork's own channel for this subsystem.
LOG_CHANNEL(ppu_modelsetup, "ppu.modelsetup");

namespace
{
	using namespace spu_task_hle::ppu;

	u32 swap32(u32 v)
	{
		return (v >> 24) | ((v >> 8) & 0x0000ff00u) | ((v << 8) & 0x00ff0000u) | (v << 24);
	}

	u64 swap64(u64 v)
	{
		return (static_cast<u64>(swap32(static_cast<u32>(v))) << 32) | swap32(static_cast<u32>(v >> 32));
	}

	u16 swap16(u16 v)
	{
		return static_cast<u16>((v >> 8) | (v << 8));
	}

	// A granule is one 0x1000-byte page: both walks index the map with
	// `address >> 12`, so the byte's address is the page's, not the page's
	// sixteenth.
	inline constexpr u32 granule_bytes = 0x1000;

	// The granule map the replica supplies to the guards.
	//
	// The fork walks a map it maintains itself, where a byte is exactly 0x81
	// when the granule is mapped and something else otherwise. The replica has
	// no such tracker, so a granule reads as mapped when its first four bytes
	// are readable - the same question, answered from the VM instead of from a
	// side table. The walk itself is unchanged, so the skip bits (0x40, 0x20)
	// still work for any caller that does have a finer map.
	std::function<u8(u32)> granule_map(direct_mem& mem)
	{
		return [&mem](u32 granule) -> u8
		{
			const u32 addr = granule * granule_bytes;
			return mem.guest_valid(addr, 4) ? mgo_modelsetup::granule_mapped : u8(0);
		};
	}

	// Big-endian loads. The guest is a big-endian PowerPC machine, so every
	// word the fork reads out of guest memory is byte-swapped before use - that
	// is what `bswap` at 0x143ac538d and its many siblings are.
	bool load32(direct_mem& mem, u32 addr, u32& out)
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

	// A word read *without* a byte swap. Two of the launcher's tests are
	// `cmp dword ptr [rcx + rax], 0` with no swap between, because the field
	// is only ever tested against zero.
	bool raw32(direct_mem& mem, u32 addr, u32& out)
	{
		const u8* ptr = mem.guest_ptr(addr, sizeof(u32));
		if (!ptr)
		{
			return false;
		}

		std::memcpy(&out, ptr, sizeof(out));
		return true;
	}

	bool load64(direct_mem& mem, u32 addr, u64& out)
	{
		const u8* ptr = mem.guest_ptr(addr, sizeof(u64));
		if (!ptr)
		{
			return false;
		}

		std::memcpy(&out, ptr, sizeof(out));
		out = swap64(out);
		return true;
	}

	u8 load8(direct_mem& mem, u32 addr)
	{
		const u8* ptr = mem.guest_ptr(addr, 1);
		return ptr ? *ptr : u8(0);
	}

	u16 load16(direct_mem& mem, u32 addr)
	{
		const u8* ptr = mem.guest_ptr(addr, sizeof(u16));
		if (!ptr)
		{
			return 0;
		}

		u16 value = 0;
		std::memcpy(&value, ptr, sizeof(value));
		return swap16(value);
	}

	// The per-image scratch buffers the launcher allocates, indexed the same
	// way the fork indexes them: `rbx = (image != 0x100c280)` at 0x143a1a119,
	// so 0 is the first record and 1 is the second.
	std::unique_ptr<mgo_modelsetup::image_scratch> s_scratch[2];
}

namespace mgo_modelsetup
{
	// -----------------------------------------------------------------------
	// Status
	// -----------------------------------------------------------------------

	std::string_view status_text(status value)
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

	// -----------------------------------------------------------------------
	// The image table
	// -----------------------------------------------------------------------

	const std::vector<image_info>& images()
	{
		// Verbatim from 0x144b36e20. Only image_base, hash_bytes and
		// image_hash are read by the recovered code; the rest is transcribed so
		// the record can be compared byte for byte against the reference.
		static const std::vector<image_info> table
		{
			// 80 c2 00 01 18 9f 00 00 00 ac 00 00 c0 c1 01 00
			// 80 ab 00 00 80 ac 00 00 40 ab 00 00 80 fd 03 00
			// 00 01 00 00 00 00 00 00 a3 aa e3 49 5a 49 3c 74
			{ 0x0100c280u, 0x00009f18u, 0x0000ac00u, 0x0001c1c0u, 0x0000ab80u, 0x0000ac80u, 0x0000ab40u, 0x0003fd80u, 0x00000100u, 0u, 0x743c495a49e3aaa3ull },

			// 80 94 00 01 f0 4c 00 00 80 58 00 00 40 29 01 00
			// 00 58 00 00 00 59 00 00 90 57 00 00 e0 fd 03 00
			// 80 00 00 00 00 00 00 00 ae de ca 9d f9 77 25 d8
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

	// -----------------------------------------------------------------------
	// The reproduced-LS byte map
	// -----------------------------------------------------------------------

	bool walk_granules(const std::function<u8(u32 granule)>& map_byte, u32 lo, u32 hi)
	{
		// The loop as recovered, e.g. at 0x143a1a3f0:
		//
		//   and  ecx, 0xffffff00
		//   add  ecx, 0x100
		//   cmp  ecx, edx
		//   ja   <done>
		//   mov  r8d, ecx
		//   movzx r8d, byte ptr [r8 + rdx]     ; rdx = the map
		//   movzx r9d, r8b
		//   not  r9d
		//   test r9b, 0x81
		//   jne  <reject>
		//   test r8b, 0x40
		//   jne  <next page>
		//   test r8b, 0x20
		//   jne  <next 16>
		//   inc  ecx
		//
		// Reproduced as a walk over [lo, hi] with the three skip rules.
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
		// `cmp eax, -4 / ja reject`, reproduced with the same unsigned wrap the
		// guest's own 32-bit arithmetic would have produced.
		if (lo > 0xfffffffcu)
		{
			return false;
		}

		const u32 first = lo >> 12;
		const u32 last = hi >> 12;

		// hi >= lo, so this never fires and the walk always runs.
		if (first > last)
		{
			return true;
		}

		return walk_granules(map_byte, first, last);
	}

	bool window_backwards_ok(const std::function<u8(u32 granule)>& map_byte, u32 ptr)
	{
		// 0x143ac53b0. The near end is 0x8000 below the pointer and the far end
		// is a further 0x7ffd below that, so `first > last` and the walk is
		// skipped for every pointer but the three per page where both ends
		// share a page.
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

	// -----------------------------------------------------------------------
	// read_spurs_args
	// -----------------------------------------------------------------------

	bool read_spurs_args(direct_mem& mem, u32 tasks, spurs_args& out,
	                     const std::function<u8(u32 granule)>& map_byte)
	{
		// 0x143ac5385: more than seven tasks is out of range. Note this is one
		// short of the eight the pool can serve, so an eight-task launch is
		// rejected by the fork too.
		if (tasks > max_spurs_tasks)
		{
			return false;
		}

		// The fork checks the granule holding the queue pointer before reading
		// it: `movzx eax, byte ptr [map + 0x121a]` at 0x143ac538e, where 0x121a
		// is exactly 0x121aef8 >> 8.
		const u32 queue_granule = spurs_task_queue >> 8;

		if (!walk_granules(map_byte, queue_granule, queue_granule))
		{
			return false;
		}

		// 0x143ac53a6: the queue pointer itself, byte-swapped.
		u32 queue = 0;

		if (!load32(mem, spurs_task_queue, queue))
		{
			return false;
		}

		// The 0x8000-byte window centred just below the queue pointer. The fork
		// spells the far end as `add r8d, 0xffff8003`.
		if (!window_backwards_ok(map_byte, queue))
		{
			return false;
		}

		// 0x143ac5431: the block header word, at (queue - 0x8000).
		u32 header = 0;

		if (!load32(mem, queue - 0x8000u, header))
		{
			return false;
		}

		const u32 addr = header + tasks * spurs_task_stride + spurs_task_first;

		// 0x143ac5446: the computed address must not wrap.
		if (addr > 0xfffffffcu)
		{
			return false;
		}

		// The task's four header bytes must be mapped.
		if (!walk_granules(map_byte, addr >> 12, (addr + 3) >> 12))
		{
			return false;
		}

		// 0x143ac54bf: the task context word.
		u32 context = 0;

		if (!load32(mem, addr, context))
		{
			return false;
		}

		out.context = context;

		// 0x143ac54c9: `test cl, 0x7f / je ok` - the context must be 128-byte
		// aligned.
		if (context & 0x7fu)
		{
			return false;
		}

		// 0x143ac54d9: `or ecx, 0x60 / mov edx, 0x10 / xor r8d, r8d / call
		// translate` - the sixteen bytes at context + 0x60 must be readable.
		// The `or 0x60` looks odd until the alignment test above is accounted
		// for: bits 5 and 6 are known clear, so this is a plain add.
		if (!mem.guest_valid(context | 0x60u, 0x10, false))
		{
			return false;
		}

		// 0x143ac54f1 and 0x143ac5508: the two qwords, stored +0x68 first and
		// +0x60 second.
		if (!load64(mem, context + 0x68u, out.qword_68) ||
		    !load64(mem, context + 0x60u, out.qword_60))
		{
			return false;
		}

		return true;
	}

	// -----------------------------------------------------------------------
	// load_image
	// -----------------------------------------------------------------------

	u64 fnv1a64(const u8* data, u32 bytes)
	{
		u64 hash = fnv_offset_basis;

		for (u32 i = 0; i < bytes; i++)
		{
			hash = (hash ^ data[i]) * fnv_prime;
		}

		return hash;
	}

	bool load_image(direct_mem& mem, image_scratch& scratch, const image_info& info,
	                const std::function<u8(u32 granule)>& map_byte)
	{
		const u32 base = info.image_base;

		// The load cache. 0x143ac5535 reads the image address the buffer holds
		// and 0x143ac553d returns the cached verdict unchanged when it matches.
		u32 cached = 0;
		std::memcpy(&cached, &scratch[scratch_cached_image], sizeof(cached));

		if (cached == base)
		{
			return scratch[scratch_cached_ok] != 0;
		}

		std::memcpy(&scratch[scratch_cached_image], &base, sizeof(base));
		scratch[scratch_cached_ok] = 0;

		// 0x143ac555b: only the low 0x40020 of the 0x5c180 buffer is cleared.
		std::memset(scratch.data(), 0, scratch_cleared_bytes);

		// The whole ELF header must be mapped. `cmp edx, -0x34 / ja reject`
		// catches the wrap and `lea ecx, [edx + 0x33]` is the far end of the
		// 0x34-byte header.
		if (base > 0xfffffffcu)
		{
			return false;
		}

		if (!window_forward_ok(map_byte, base, base + 0x33u))
		{
			return false;
		}

		u32 magic = 0;

		if (!load32(mem, base, magic) || magic != 0x7f454c46u)
		{
			return false;
		}

		// EI_CLASS 1 (ELFCLASS32) and EI_DATA 2 (ELFDATA2MSB). SPURS task
		// images are 32-bit-class big-endian PowerPC64 images, which is why
		// every offset below is an Elf32 one.
		if (load8(mem, base + 0x04) != 1 || load8(mem, base + 0x05) != 2)
		{
			return false;
		}

		// e_machine, byte-swapped as a half word: `rol cx, 8 / cmp cx, 0x17`.
		if (load16(mem, base + 0x12) != 0x17)
		{
			return false;
		}

		const u16 phnum = load16(mem, base + 0x2c);

		// `cmp r10w, 0x10 / jbe accept`.
		if (phnum > 0x10)
		{
			return false;
		}

		u32 phoff = 0;

		if (!load32(mem, base + 0x1c, phoff))
		{
			return false;
		}

		for (u32 i = 0; i < phnum; i++)
		{
			const u32 phdr = phoff + i * 0x20u + base;

			// `lea r9d, [rax + rcx] / cmp r9d, -0x20 / ja reject` and the walk
			// over the 32-byte header.
			if (phdr > 0xffffffe0u || !window_forward_ok(map_byte, phdr, phdr + 0x1fu))
			{
				return false;
			}

			u32 type = 0;

			if (!load32(mem, phdr, type) || type != 1)
			{
				// Not PT_LOAD. The fork does `jne` back to the loop head, so
				// this is not a failure.
				continue;
			}

			// p_vaddr, assembled as a 24-bit big-endian load plus the fourth
			// byte: `movzx r14d, [phdr + 0xa] / movzx edx, [phdr + 9] /
			// movzx r8d, [phdr + 8]` and the three shifts.
			u32 vaddr = static_cast<u32>(load8(mem, phdr + 0x08)) << 24 |
			            static_cast<u32>(load8(mem, phdr + 0x09)) << 16 |
			            static_cast<u32>(load8(mem, phdr + 0x0a)) << 8;

			// `cmp r14d, 0x3000 / jb reject` - nothing may land below the
			// image origin, because the hash starts there.
			if (vaddr < scratch_image_origin)
			{
				return false;
			}

			u32 filesz = 0, memsz = 0;

			if (!load32(mem, phdr + 0x10, filesz) || !load32(mem, phdr + 0x14, memsz))
			{
				return false;
			}

			// `cmp edx, r8d / ja reject`.
			if (filesz > memsz)
			{
				return false;
			}

			// `movzx r9d, [phdr + 0xb] / or r14d, r9d` completes the address,
			// then `add r8, r14 / cmp r8, 0x40000 / ja reject` - the segment
			// must fit inside the cleared part of the buffer.
			vaddr |= load8(mem, phdr + 0x0b);

			if (vaddr + memsz > scratch_cleared_bytes)
			{
				return false;
			}

			u32 offset = 0;

			if (!load32(mem, phdr + 0x04, offset))
			{
				return false;
			}

			// The segment's bytes live at (image_base + p_offset) in the
			// guest's flat copy and land at p_vaddr in the buffer:
			//
			//   0x143ac57b1  add  ecx, r15d          ; ecx = base + p_offset
			//   0x143ac57ee  add  r15d, [rdi]
			//   0x143ac5688  add  r14, rsi          ; r14 = p_vaddr, rsi = scratch
			//   0x143ac568b  mov  edx, ecx
			//   0x143ac568d  add  rdx, rbp          ; + the guest base
			const u32 src = base + offset;

			if (filesz != 0)
			{
				// `mov rax, 0x100000000 / cmp rax, r8 / ja reject`, then a
				// readability check on the source range.
				if (static_cast<u64>(src) + filesz > 0x100000000ull)
				{
					return false;
				}

				if (!mem.guest_valid(src, filesz, false))
				{
					return false;
				}

				const u8* from = mem.guest_ptr(src, filesz);

				if (!from)
				{
					return false;
				}

				std::memcpy(&scratch[vaddr], from, filesz);
			}
		}

		// The hash: FNV-1a-64 over the buffer from 0x3000 to `hash_bytes`,
		// measured as `add r8d, 0xffffd000` at 0x143ac580f.
		u32 hash_bytes = 0;
		std::memcpy(&hash_bytes, &info.hash_bytes, sizeof(hash_bytes));

		if (hash_bytes < scratch_image_origin)
		{
			scratch[scratch_cached_ok] = 0;
			return false;
		}

		const u64 hash = fnv1a64(&scratch[scratch_image_origin], hash_bytes - scratch_image_origin);

		// 0x143ac58c7: `cmp rdx, qword ptr [rdi + 0x28] / sete bl / sete
		// byte ptr [rsi + 0x5c164]`. The verdict is cached alongside the
		// address so a second call for the same image is a single byte read.
		const bool ok = hash == info.image_hash;
		scratch[scratch_cached_ok] = ok ? 1 : 0;

		return ok;
	}

	// -----------------------------------------------------------------------
	// The SPURS_TaskStart argument gates
	// -----------------------------------------------------------------------

	bool spurs_args_ok(u32 gpr3, u32 gpr6)
	{
		// `cmp edi, -0x80 / jbe ok` at 0x143ac5b71.
		if (gpr3 > spurs_arg_max)
		{
			return false;
		}

		// `(gpr6 ^ 0x10000) | (gpr3 & 0xf)`, 0x143a1a0c9.
		return ((gpr6 ^ spurs_option_word) | (gpr3 & 0xfu)) == 0;
	}

	// -----------------------------------------------------------------------
	// Conflict tracking
	// -----------------------------------------------------------------------

	void page_set::insert(u32 page)
	{
		// Keep the table at least half empty:
		//   0x143b46a0e  lea edx, [rax*2 + 2]
		if (m_table.size() < static_cast<usz>(m_count) * 2 + 2)
		{
			grow();
		}

		if (m_table.empty())
		{
			return;
		}

		const u32 mask = static_cast<u32>(m_table.size()) - 1;

		// `imul edx, edi, 0x9e3779b1 / shr edx, 0xc` - the golden-ratio hash,
		// which lands in the top of the word rather than the bottom.
		u32 slot = (page * 0x9e3779b1u) >> 12;
		const u32 key = page + 1;

		while (true)
		{
			slot &= mask;

			const u32 found = m_table[slot];

			if (found == key)
			{
				// Already present: `cmp r8d, edi / je ret`.
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

	void page_set::grow()
	{
		// 0x143b46c7e: `mov rdx, [rsi + 8] / sub rdx, [rsi] / sar rdx, 1`
		// reaches assign() as (4 * old_count) / 2 == 2 * old_count, i.e. the
		// table doubles. Reading the halving literally would leave the probe
		// loop with no empty slot to find.
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

	bool page_set::contains(u32 page) const
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

	void tracker::on_get(u32 addr, u32 size)
	{
		m_reads.push_back({ addr, size });

		const u32 first = addr >> 12;
		const u32 last = (addr + size - 1) >> 12;

		for (u32 page = first; page <= last; page++)
		{
			m_read_pages.insert(page);
		}

		// 0x143b4692c: `cmp eax, [rdi + 0xb0] / jae skip` and
		// 0x143b46941: `cmp esi, [rcx + rax*4]` - note esi still holds the
		// *address*, not the page: the fork has not shifted it yet at
		// 0x143b469b5. So the watched value is compared against the address,
		// and the rdtsc stamp at 0x143b46946 is only taken on a match.
		//
		// The replica stamps with a monotonic counter; the value is only ever
		// read as a relative order.
		if (m_watch_count < m_watch_cap && m_watch_pages[m_watch_count] == addr)
		{
			m_watch_stamps[m_watch_count++] = m_watch_clock++;
		}
	}

	void tracker::on_put(u32 addr, u32 size)
	{
		m_writes.push_back({ addr, size });

		const u32 first = addr >> 12;
		const u32 last = (addr + size - 1) >> 12;

		for (u32 page = first; page <= last; page++)
		{
			m_written_pages.insert(page);
		}
	}

	// -----------------------------------------------------------------------
	// The launcher
	// -----------------------------------------------------------------------

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

	void launch(ppu_thread& cpu, direct_mem& mem, const call_regs& regs, call_result& out)
	{
		(void)cpu;

		const site_kind site = classify_site(regs.call_site);

		if (site == site_kind::none)
		{
			// 0x143a19ffc: `xor esi, esi` - not reached through this record.
			return;
		}

		const auto map = granule_map(mem);

		const u32 gpr3 = static_cast<u32>(regs.gpr[3]);
		const u32 gpr4 = static_cast<u32>(regs.gpr[4]);
		const u32 gpr5 = static_cast<u32>(regs.gpr[5]);
		const u32 gpr6 = static_cast<u32>(regs.gpr[6]);
		const u32 block = static_cast<u32>(regs.gpr[24]);

		// 0x143a19f61 (chara) and 0x143a19fc1 (bg): the same two byte-map
		// windows out of the block gpr[24] points at.
		//
		// The walks cannot reject here - every failure branch lands on the
		// same `mov sil, 1` that a clean walk leaves behind - so what the two
		// sites actually test is which of the block's two argument words is
		// non-zero.
		window_forward_ok(map, block + 0x84u, block + 0x87u);
		window_forward_ok(map, block + 0x114u, block + 0x117u);

		u32 word_84 = 0, word_114 = 0;

		if (!raw32(mem, block + 0x84u, word_84) ||
		    !raw32(mem, block + 0x114u, word_114))
		{
			word_84 = 0;
			word_114 = 0;
		}

		// 0x143a19ffe: `cmp r12d, 0x14cea0 / sete al / jne skip` and
		// 0x143a1a020: `and al, sil / cmp al, 1 / jne reject`. The bg site
		// therefore only ever looks at +0x114, while the chara site accepts
		// either word.
		const bool armed = site == site_kind::chara ? (word_84 != 0 || word_114 != 0)
		                                           : (site == site_kind::bg && word_114 != 0);

		if (!armed)
		{
			// The fork leaves this path with esi cleared, which is the same
			// "not my call" state as an unmatched site.
			return;
		}

		// 0x143a1a0b5: the guest must be asking for one of the two images the
		// fork knows how to lift.
		const s32 img = image_index(gpr5);

		if (img < 0)
		{
			spu_task_hle::note_decline(status_text(status::not_a_model_setup_image), __FILE__, decline_line);
			ppu_modelsetup.trace("MGO: ppu.modelsetup declined: image %#x is not a model setup image", gpr5);
			return;
		}

		// 0x143a1a0c9: the SPURS_TaskStart arguments have to be exactly what
		// the lifters were built against.
		if (!spurs_args_ok(gpr3, gpr6))
		{
			spu_task_hle::note_decline(status_text(status::unexpected_spurs_args), __FILE__, decline_line);
			ppu_modelsetup.trace("MGO: ppu.modelsetup declined: gpr3 %#x gpr6 %#x are not the expected SPURS_TaskStart arguments",
				gpr3, gpr6);
			return;
		}

		// 0x143a1a117 onwards: one 0x5c180 scratch buffer per image, cleared
		// on every launch.
		const usz slot = static_cast<usz>(img);

		if (!s_scratch[slot])
		{
			s_scratch[slot] = std::make_unique<image_scratch>();
		}

		image_scratch& scratch = *s_scratch[slot];

		// 0x143a1a1af: read the SPURS task queue out of the guest.
		spurs_args args;

		if (!read_spurs_args(mem, gpr4, args, map))
		{
			spu_task_hle::note_decline(status_text(status::taskset_unreadable), __FILE__, decline_line);
			ppu_modelsetup.trace("MGO: ppu.modelsetup declined: SPURS task %u of the queue at %#x is not readable",
				gpr4, spurs_task_queue);
			return;
		}

		// 0x143a1a1d0: verify the image the guest loaded against the fork's
		// record.
		if (!load_image(mem, scratch, images()[slot], map))
		{
			spu_task_hle::note_decline(status_text(status::task_image_differs), __FILE__, decline_line);
			ppu_modelsetup.trace("MGO: ppu.modelsetup declined: image at %#x is not the one the lifters were built against",
				gpr5);
			return;
		}

		// Everything above is the fork's own front end and is reproduced.
		// detail::run is not: it is the 0xc28-byte body that drives
		// mgo_modelsetup_bg_lift / mgo_modelsetup_chara_lift, and those are
		// compiled native kernels with no recoverable description. Status 1 is
		// the fork's own wording for exactly this case.
		spu_task_hle::note_decline(status_text(status::built_without_sse), __FILE__, decline_line);
		ppu_modelsetup.trace("MGO: ppu.modelsetup: image %#x and task %#x are valid, but this build has no native lift kernel",
			gpr5, args.context);

		// Not handled: the guest's own modelsetup runs.
		out.handled = false;
	}

	// Frees the per-image scratch buffers. Called from spu_task_hle::reset().
	void reset()
	{
		s_scratch[0].reset();
		s_scratch[1].reset();
	}
}