// Checks the integrity check's SHA-256 against the standard vectors, and checks
// that hashing the reference binary's .text really does reproduce the digest the
// fork stores.  A broken hand-rolled hash would make the build abort at random,
// so this has to be tested rather than assumed.
//
//   g++ -std=c++20 -O1 -I. -Irpcs3 buildfiles/mgo_integrity_test.cpp \
//       rpcs3/Emu/mgo/mgo_integrity_hash.cpp -o buildfiles/mgo_integrity_test.exe

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "Emu/mgo/mgo_integrity_hash.h"

#include "Emu/mgo/mgo_integrity.h"

static int passed = 0;
static int failed = 0;

static void check(bool ok, const std::string& what)
{
	if (ok)
	{
		passed++;
	}
	else
	{
		failed++;
		std::printf("  FAIL  %s\n", what.c_str());
	}
}

static std::string to_hex(const u8* d, size_t n)
{
	static const char* digits = "0123456789abcdef";
	std::string s;
	for (size_t i = 0; i < n; i++)
	{
		s.push_back(digits[(d[i] >> 4) & 0xf]);
		s.push_back(digits[d[i] & 0xf]);
	}
	return s;
}

static std::string sha_of(const std::string& in)
{
	u8 out[32]{};
	mgo_hash::sha256(in.data(), in.size(), out);
	return to_hex(out, 32);
}

int main()
{
	// NIST/RFC test vectors, including the empty string and both lengths that
	// straddle the 64-byte block and the 55/56-byte padding boundary -- the
	// padding is where a hand-rolled implementation usually goes wrong.
	struct { const char* input; const char* expect; } vectors[] = {
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqrst",
		 "1c57c64f706e3acb30199746f15088d9bae0e74d186f0e8a0a85f27a152eba1a"},
	};

	for (const auto& v : vectors)
	{
		check(sha_of(v.input) == v.expect,
			"sha256 of a " + std::to_string(std::strlen(v.input)) + "-byte input");
	}

	// The padding boundaries, which is where a hand-rolled implementation breaks:
	// 55 fits with the 0x80 in one block, 56 forces a second, 63/64 straddle the
	// block edge, 65 forces a third.
	struct { int len; const char* expect; } lengths[] = {
		{55,  "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
		{56,  "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
		{63,  "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
		{64,  "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
		{65,  "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
		{1000,"41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"},
	};

	for (const auto& l : lengths)
	{
		check(sha_of(std::string(size_t(l.len), 'a')) == l.expect,
			"sha256 of " + std::to_string(l.len) + " x 'a'");
	}

	// The reference build: sha256 over min(VirtualSize, SizeOfRawData) of .text
	// must equal the digest the fork stores in .data.  Read straight off the
	// file so the test needs no running image.
	{
		std::FILE* f = std::fopen(
			"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak", "rb");
		check(f != nullptr, "the reference binary is readable");
		if (f)
		{
			// .text: file offset 0x400, length 0x3eae816 (.text VirtualSize)
			std::fseek(f, 0x400, SEEK_SET);
			std::vector<u8> buf(0x3eae816);
			const size_t got = std::fread(buf.data(), 1, buf.size(), f);
			std::fclose(f);

			check(got == buf.size(), "read all of .text");

			u8 out[32]{};
			mgo_hash::sha256(buf.data(), buf.size(), out);

			const std::string expect = "c9315b202de3201daf7f7723d86a3e3f152ca8e2854072f6e9154f8bf7fda158";
			check(to_hex(out, 32) == expect,
				"hashing the reference .text reproduces the fork's stored digest");

			// The digest the fork stores lives in .data, not in the hashed range,
			// which is what makes the check non-circular.  Confirm it is really
			// there at .data + 0x50.
			std::FILE* d = std::fopen(
				"C:/Users/migue/Desktop/research/MGO2/rpcs3.exe.bak", "rb");
			check(d != nullptr, "reopened the reference binary for .data");
			if (d)
			{
				// .data raw offset 0x4e29c00, digest at +0x50
				std::fseek(d, 0x4e29c00 + 0x50, SEEK_SET);
				u8 stored[32]{};
				const size_t got = std::fread(stored, 1, 32, d);
				std::fclose(d);
				check(got == 32, "read the stored digest");
				check(to_hex(stored, 32) == expect,
					"and the digest stored in .data matches what we just computed");
			}
		}
	}

	std::printf("%d passed, %d failed\n", passed, failed);
	return failed == 0 ? 0 : 1;
}