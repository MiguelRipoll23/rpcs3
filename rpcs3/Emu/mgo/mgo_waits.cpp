#include "stdafx.h"
#include "Emu/mgo/mgo_waits.h"
#include "Emu/Cell/SPUTaskHLE/ppu_task_hle.h"

#include "Emu/Cell/PPUThread.h"
#include "Emu/Cell/SPUThread.h"

#include "Emu/Memory/vm_reservation.h"
#include "Emu/System.h"
#include "util/atomic.hpp"
#include "util/logs.hpp"

#include <array>
#include <cstring>
#include <iterator>

// Named apart from the enclosing namespace on purpose: a LOG_CHANNEL called
// `mgo_waits` inside `namespace mgo_waits` resolves to the namespace, and the
// call below silently stops compiling.
LOG_CHANNEL(mgo_waits_log, "mgo.waits");

namespace spu_task_hle::mgo_waits
{
	namespace
	{
		// Verbatim from 0x144a25cf0, three 12-byte records 12 bytes apart.
		// Order is the order of the fork's branch arms.
		constexpr lwarx_site s_sites[] =
		{
			{ 0x00337070u, 0x00337080u, 0u },
			{ 0x001b01f8u, 0x001b0240u, 2u },
			{ 0x001999a8u, 0x001999d8u, 3u },
		};

		// The two titles the fork's reporter accepts, from the constants
		// 0x31303030474d504e / 0x32303030474d504e plus a ninth byte of 0x30.
		// Those are "NPMG00010" and "NPMG00020" in plain ASCII.
		constexpr std::string_view mgo1_title = "NPMG00010";
		constexpr std::string_view mgo2_title = "NPMG00020";

		// `cmp r8, 9` at 0x1434af219 / 0x1434af22e: the holder's length field,
		// which is bits 1 and up of its tag byte, has to be exactly nine.
		constexpr usz title_length = 9;

		// 0x146127ef8 in the reference build is `vm::g_resrv_waiters_count`
		// (COFF: `_ZL21g_resrv_waiters_count.llvm.1733...`), not a private
		// array, and the index reaches 119 - so it bumps a byte of the shared
		// reservation-waiter table rather than keeping its own counter.
		//
		// It is a waiters count, not a re-entrancy flag: the reservation
		// notifier (vm_reservation.cpp) reads these bytes to decide how many
		// threads are parked, so the bump is how this wait announces itself.
		// `guard_buckets` is 120 because popcount(addr & 0xfffffe00) is 23 at
		// most and the other term tops out at 0x60 - 23 | 0x60 == 119.

		// atomic_t<u64>::wait's 8-byte overload is `[[deprecated]]` because
		// waiting on a 64-bit atomic with a 32-bit sequence number is a
		// fallback - but it is exactly what the fork calls at 0x1434af343,
		// down to the `old >> 32` extended entry it builds, and a reservation
		// word is not something this code can narrow. Hence the local
		// suppression rather than a different API.
		void wait_on_reservation(u32 addr, u64 rtime)
		{
			const auto& slot = *utils::bless<atomic_t<u64>>(vm::g_reservations + reservation_slot_offset(addr));

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
			slot.wait(rtime, atomic_wait_timeout{wait_timeout});
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
		}

		// `lock inc byte ptr [rdx + rdi]` / `lock dec` at 0x1434af2f2 and
		// 0x1434af348, where rdi is `vm::g_resrv_waiters_count` (0x146127ef8)
		// and rdx is guard_bucket(addr).
		//
		// A byte of that table is `waiters_count` inside a
		// `reservation_waiter_t` (u32 wait_flag, u32 waiters_count), and the
		// fork bumps a *byte* of it rather than the u32 - so it is reproduced
		// as a byte add on the same address, not as a field increment. Doing it
		// through the u32 would change what the reservation notifier observes.
		void bump_waiter_count(u32 addr, bool up)
		{
			// Not reservation_notifier(): that indexes the table differently
			// (popcount clamped to 31, times 32, plus rtime and low-address
			// bits). The fork's own hash is guard_bucket() and is used raw, so
			// this deliberately does not reuse reservation_notifier().
			const usz index = guard_bucket(addr);
			auto* slot = reinterpret_cast<u8*>(&vm::g_resrv_waiters_count[0]) + index;

			if (up)
			{
				utils::bless<atomic_t<u8>>(slot)->fetch_add(1);
			}
			else
			{
				utils::bless<atomic_t<u8>>(slot)->fetch_sub(1);
			}
		}
	}

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
		// The fork's sequence, transcribed:
		//
		//   r9b  = (value < budget)      cmp r8d, eax / setb r9b
		//   r10b = (value != 0)         test r8d, r8d / setne r10b
		//   if (budget != 0) r10b = r9b test eax, eax / cmovne r10d, r9d
		//   proceed iff r10b == 1       cmp r10b, 1 / jne end
		//
		// The cmovne is what makes a zero budget mean "any non-zero value"
		// rather than "never": with budget 0, (value < 0) is always false, so
		// without the cmov the third record could never fire.
		const bool under = value < budget;
		const bool non_zero = value != 0;

		return (budget != 0) ? under : non_zero;
	}

	bool title_supported(const char* title_id)
	{
		if (!title_id)
		{
			return false;
		}

		const std::string_view id{title_id};

		if (id.size() != title_length)
		{
			// The holder's length check at 0x1434af219 / 0x1434af22e. Both
			// accepted ids are nine characters, so this rejects nothing that
			// would otherwise pass - it is reproduced because it is what the
			// fork does, and because a nine-character title that is not one of
			// the two is rejected by the same pair of compares anyway.
			return false;
		}

		return id == mgo1_title || id == mgo2_title;
	}

	bool ppu_lwarx_wait(ppu_thread& ppu, u32 addr, u32 value)
	{
		// The caller's gate, in the caller's order: the PC switch first (it is
		// a binary search over six constants), then the configuration byte.
		const u32 pc = static_cast<u32>(ppu.cia);
		const lwarx_site* site = find_lwarx_site(pc);

		if (!site)
		{
			return false;
		}

		if (!level_at_least(min_level))
		{
			return false;
		}

		// The reporter's own gates, re-reading the PC out of the thread.
		if (!budget_gate(value, site->budget))
		{
			return false;
		}

		if (!title_supported(Emu.GetTitleID().c_str()))
		{
			return false;
		}

		// 0x1434af28c: `lock or dword ptr [rcx + 0x14], 4`. Bit 2 of the
		// thread's state word is set before the wait so that anything which
		// looks at the thread while it is parked knows to re-check it - and
		// the fork tests that word again on the way out (0x1434af34c) and
		// calls cpu_thread::check_state() if it is still set.
		ppu.state += cpu_flag::wait;

		// 0x1434af2f2 / 0x1434af348: announce the wait to the notifier.
		bump_waiter_count(addr, true);

		try
		{
			wait_on_reservation(addr, ppu.rtime);
		}
		catch (...)
		{
			// A throw out of the wait would otherwise leave the waiter count
			// stuck, and every later spin at this address would look like a
			// permanently-parked thread to vm_reservation's notifier.
			bump_waiter_count(addr, false);
			throw;
		}

		bump_waiter_count(addr, false);

		if (static_cast<bool>(ppu.state.load()))
		{
			// 0x1434af356. check_state() consumes whatever the wait left
			// behind (a pending syscall, a stop request) and reports whether
			// the caller has to return to the interpreter loop.
			static_cast<void>(ppu.check_state());
		}

		mgo_waits_log.trace("lwarx: parked at pc=%#x (site %#x-%#x budget %u) addr=%#x value=%#x",
			pc, site->pc_lo, site->pc_hi, site->budget, addr, value);

		return true;
	}

	bool geo_getllar_ignore_gpr1(const spu_thread& spu)
	{
		// The fork reads the local store through the thread at +0xfd8, which
		// is spu_thread::ls, and compares four words at +0x3000 with no other
		// check - no bounds test, no page validation. It gets away with that
		// because the caller has already established the local store is
		// mapped, and so does this: an unmapped local store is not a state a
		// running SPU thread can be in.
		const u8* ls = spu.ls;

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