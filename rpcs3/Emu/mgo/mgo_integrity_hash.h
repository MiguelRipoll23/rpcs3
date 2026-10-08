#pragma once

// SHA-256, in its own translation unit and with no dependencies at all.
//
// The integrity check has to run before the rest of the emulator is up, and it
// has to hash tens of megabytes of its own image, so it cannot afford to pull
// in OpenSSL or the logging system.  Keeping it here also means it can be
// tested directly against the standard vectors -- see
// buildfiles/mgo_integrity_test.cpp -- which matters, because a subtly wrong
// hand-rolled hash would make the build abort at random.

#include <cstddef>
#include <cstdint>

namespace mgo_hash
{
	using byte = std::uint8_t;

	// Streams a buffer through SHA-256.  Safe to call with length 0.
	void sha256(const void* data, std::size_t length, byte out[32]);
}