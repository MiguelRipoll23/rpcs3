#include "stdafx.h"
#include "mgo_integrity.h"

#include "mgo_integrity_hash.h"

#include "util/logs.hpp"
#include "util/types.hpp"

#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <Windows.h>
#endif

LOG_CHANNEL(mgo_integrity_log, "MGO_INT");

// The reference build's digest, reproduced here so the constant is at least the
// right *shape* and the same algorithm is exercised.  It is NOT the digest of
// this tree: `.text` differs by construction.  Regenerate with
// buildfiles/mgo_digest.py and replace this array.
const u8 mgo_integrity::expected_digest[32] = {
	0xc9, 0x31, 0x5b, 0x20, 0x2d, 0xe3, 0x20, 0x1d,
	0xaf, 0x7f, 0x77, 0x23, 0xd8, 0x6a, 0x3e, 0x3f,
	0x15, 0x2c, 0xa8, 0xe2, 0x85, 0x40, 0x72, 0xf6,
	0xe9, 0x15, 0x4f, 0x8b, 0xf7, 0xfd, 0xa1, 0x58,
};

namespace
{
	u8 g_override[32]{};
	bool g_has_override = false;

#ifdef _WIN32
	// Locates the running image's ".text" the way the fork does: GetModuleHandle
	// for the base, then walk the section table looking for the 8-byte name.
	struct text_section
	{
		const u8* base = nullptr;
		size_t length = 0;
	};

	// Returns false when the image is not a PE or has no .text section, which
	// the caller treats as a failure rather than silently skipping.
	bool find_text_section(text_section& out, std::string& path)
	{
		HMODULE mod = GetModuleHandleW(nullptr);
		if (!mod)
		{
			return false;
		}

		auto* base = reinterpret_cast<const u8*>(mod);

		wchar_t buf[MAX_PATH]{};
		if (GetModuleFileNameW(mod, buf, MAX_PATH) != 0)
		{
			const int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
			if (n > 1)
			{
				path.resize(size_t(n - 1));
				WideCharToMultiByte(CP_UTF8, 0, buf, -1, path.data(), n, nullptr, nullptr);
			}
		}

		const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}

		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
		{
			return false;
		}

		const auto* sec = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
		{
			if (std::memcmp(sec->Name, ".text", 8) == 0 || std::memcmp(sec->Name, ".tex", 8) == 0)
			{
				const size_t len = size_t(sec->Misc.VirtualSize < sec->SizeOfRawData
				                              ? sec->Misc.VirtualSize : sec->SizeOfRawData);
				if (base + sec->VirtualAddress == nullptr || len == 0)
				{
					return false;
				}

				out.base = base + sec->VirtualAddress;
				out.length = len;
				return true;
			}
		}

		return false;
	}
#endif
}

namespace mgo_integrity
{
	void compute_sha256(const void* data, std::size_t length, u8 out[32])
	{
		mgo_hash::sha256(data, length, out);
	}

	void set_expected_digest(const u8* digest)
	{
		if (digest)
		{
			std::memcpy(g_override, digest, 32);
			g_has_override = true;
		}
		else
		{
			g_has_override = false;
		}
	}

	result check()
	{
		result res{};

#ifdef _WIN32
		text_section text{};
		if (!find_text_section(text, res.module_path))
		{
			res.enabled = true;
			res.ok = false;
			res.disk_error = "could not locate .text in the running image";
			return res;
		}

		res.enabled = true;
		res.hashed_length = u32(text.length);
		mgo_hash::sha256(text.base, text.length, res.memory_digest);

		// Second pass: the same range read back from the file on disk, so a
		// patch applied only to the mapped image is still caught.
		if (res.module_path.empty())
		{
			res.disk_error = "could not determine the module path";
		}
		else if (std::FILE* f = std::fopen(res.module_path.c_str(), "rb"))
		{
			// The PE header gives us .text's file offset, which is not the same
			// as its RVA once the section has been mapped.
			const auto* base = reinterpret_cast<const u8*>(GetModuleHandleW(nullptr));
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
			const auto* sec = IMAGE_FIRST_SECTION(nt);

			u32 file_off = 0;
			u32 file_len = 0;
			for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
			{
				if (std::memcmp(sec->Name, ".tex", 8) == 0)
				{
					file_off = sec->PointerToRawData;
					file_len = sec->SizeOfRawData;
					break;
				}
			}

			const u32 len = u32(text.length) < file_len ? u32(text.length) : file_len;
			std::vector<u8> buf(len);

			if (std::fseek(f, long(file_off), SEEK_SET) == 0
			    && std::fread(buf.data(), 1, len, f) == len)
			{
				mgo_hash::sha256(buf.data(), len, res.disk_digest);
			}
			else
			{
				res.disk_error = "short read from the module file";
			}

			std::fclose(f);
		}
		else
		{
			res.disk_error = "could not open the module file";
		}

		const u8* want = g_has_override ? g_override : expected_digest;
		res.has_expected = true;

		res.ok = std::memcmp(res.memory_digest, want, 32) == 0
		      && (res.disk_error.empty() && std::memcmp(res.disk_digest, want, 32) == 0);
#else
		// The reference check is Windows-only; elsewhere there is nothing to
		// inspect, so report disabled rather than pretending to have passed.
		res.enabled = false;
		res.ok = true;
#endif

		return res;
	}

	void verify(const char* reason)
	{
		const result res = check();

		if (!res.enabled)
		{
			return;
		}

		if (res.ok)
		{
			mgo_integrity_log.notice("Build integrity OK (%u bytes of .text hashed%s)",
				res.hashed_length, reason ? reason : "");
			return;
		}

		auto hex = [](const u8* d)
		{
			std::string s;
			static const char* digits = "0123456789abcdef";
			for (int i = 0; i < 32; i++)
			{
				s.push_back(digits[(d[i] >> 4) & 0xf]);
				s.push_back(digits[d[i] & 0xf]);
			}
			return s;
		};

		mgo_integrity_log.error("Build integrity FAILED%s", reason ? reason : "");
		mgo_integrity_log.error("  module:  %s", res.module_path.c_str());
		mgo_integrity_log.error("  hashed:  %u bytes of .text", res.hashed_length);
		mgo_integrity_log.error("  memory:  %s", hex(res.memory_digest).c_str());
		mgo_integrity_log.error("  on disk: %s", res.disk_error.empty() ? hex(res.disk_digest) : res.disk_error);

		std::fflush(stdout);
		std::abort();
	}
}