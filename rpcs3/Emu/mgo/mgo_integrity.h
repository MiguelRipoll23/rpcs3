#pragma once

#include <cstddef>
#include <string>

#include "util/types.hpp"

// The SaveMGO fork's build-integrity check.
//
// `rt_support_init()` (a file-static function at .text 0x140f6a910 in the
// reference build) runs before main() and:
//
//   1. `GetModuleHandle(NULL)`, then walks the PE headers to find the section
//      named ".text".
//   2. SHA-256s min(VirtualSize, SizeOfRawData) bytes of .text **in memory**.
//   3. `fopen`/`fseek`/`fread`s the same range **from the file on disk** and
//      SHA-256s that too, so an in-memory-only patch is caught as well.
//   4. Compares both digests, byte by byte, against a 32-byte expected digest.
//   5. On any mismatch: calls `rt_abort()` -> `TerminateProcess`.
//
// Every one of those facts was re-derived from the reference binary rather than
// taken on trust.  In the reference build `.text` has VirtualSize 0x3eae816 and
// SizeOfRawData 0x3eaea00, so the hashed length is the VirtualSize, and
//
//   sha256(.text[0x400 : 0x400+0x3eae816])
//     = c9315b202de3201daf7f7723d86a3e3f152ca8e2854072f6e9154f8bf7fda158
//
// which appears exactly once in the binary, at .data + 0x50 (VA 0x144e2c050,
// file offset 0x4e29c50).  The digest lives in `.data`, which is *not* part of
// the hashed range -- that is what makes the check checkable rather than
// circular, and it is why the fork can re-stamp it after modifying `.text`.
//
// `expected_digest` here is that same idea, but as a build-time constant that
// must be regenerated for every build: see buildfiles/mgo_digest.py.  A stale
// digest aborts at startup, which is the intended behaviour and also means the
// digest has to be re-stamped as part of the build whenever `.text` changes.
class patch_engine;

namespace mgo_integrity
{
	// Result of one run, so callers and tests can inspect it without aborting.
	struct result
	{
		bool enabled{};
		bool ok{};
		bool has_expected{};
		u32 hashed_length{};
		u8 memory_digest[32]{};
		u8 disk_digest[32]{};
		std::string disk_error{};   // non-empty if the on-disk pass could not run
		std::string module_path{};
	};

	// The digest this build expects.  Regenerate with buildfiles/mgo_digest.py
	// after any change that alters `.text`.
	extern const u8 expected_digest[32];

	// Performs the check without aborting.  Returns false when the build does
	// not match `expected_digest`, or when the module could not be inspected at
	// all (which is also treated as a failure by verify()).
	result check();

	// check(), then abort the process on failure, the way the fork does.
	// `reason` is logged before the process dies.
	void verify(const char* reason);

	// Overrides the expected digest.  Used by the test harness and by tooling;
	// pass nullptr to restore the built-in one.
	void set_expected_digest(const u8* digest);

	// The SHA-256 this file uses, exposed so it can be checked against the
	// standard test vectors.  A hand-rolled hash that is subtly wrong would make
	// the integrity check pass or fail at random, which is worse than no check.
	void compute_sha256(const void* data, std::size_t length, u8 out[32]);
}