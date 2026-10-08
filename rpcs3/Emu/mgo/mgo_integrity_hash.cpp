#include "mgo_integrity_hash.h"

#include <cstring>

namespace
{
	struct ctx
	{
		std::uint32_t h[8]{};
		std::uint64_t total = 0;
		mgo_hash::byte buf[64]{};
		std::size_t buffered = 0;
	};

	const std::uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	inline std::uint32_t ror(std::uint32_t x, std::uint32_t n)
	{
		return (x >> n) | (x << (32 - n));
	}

	void compress(ctx& c, const mgo_hash::byte* p)
	{
		std::uint32_t w[64];
		for (int i = 0; i < 16; i++)
		{
			w[i] = (std::uint32_t(p[i * 4 + 0]) << 24)
			     | (std::uint32_t(p[i * 4 + 1]) << 16)
			     | (std::uint32_t(p[i * 4 + 2]) << 8)
			     |  std::uint32_t(p[i * 4 + 3]);
		}
		for (int i = 16; i < 64; i++)
		{
			const std::uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
			const std::uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		std::uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
		std::uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];

		for (int i = 0; i < 64; i++)
		{
			const std::uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
			const std::uint32_t ch = (e & f) ^ (~e & g);
			const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
			const std::uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
			const std::uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
			const std::uint32_t t2 = S0 + maj;
			h = g; g = f; f = e; e = d + t1;
			d = cc; cc = b; b = a; a = t1 + t2;
		}

		c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
		c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
	}

	void update(ctx& c, const mgo_hash::byte* p, std::size_t len)
	{
		c.total += len;

		if (c.buffered)
		{
			const std::size_t need = 64 - c.buffered;
			const std::size_t take = len < need ? len : need;
			std::memcpy(c.buf + c.buffered, p, take);
			c.buffered += take;
			p += take;
			len -= take;

			if (c.buffered == 64)
			{
				compress(c, c.buf);
				c.buffered = 0;
			}
		}

		while (len >= 64)
		{
			compress(c, p);
			p += 64;
			len -= 64;
		}

		if (len)
		{
			std::memcpy(c.buf, p, len);
			c.buffered = len;
		}
	}
}

namespace mgo_hash
{
	void sha256(const void* data, std::size_t length, byte out[32])
	{
		ctx c;
		static const std::uint32_t iv[8] = {
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		};
		std::memcpy(c.h, iv, sizeof(iv));

		update(c, static_cast<const byte*>(data), length);

		// Finalise.  The bit count has to be taken before the padding is fed in,
		// and the length field has to land in the last 8 bytes of the block, so
		// the padding is built by hand rather than through update().
		const std::uint64_t bits = c.total * 8;

		c.buf[c.buffered++] = 0x80;
		if (c.buffered > 56)
		{
			std::memset(c.buf + c.buffered, 0, 64 - c.buffered);
			compress(c, c.buf);
			c.buffered = 0;
		}
		std::memset(c.buf + c.buffered, 0, 56 - c.buffered);

		for (int i = 0; i < 8; i++)
		{
			c.buf[56 + i] = byte((bits >> (56 - i * 8)) & 0xff);
		}
		compress(c, c.buf);

		for (int i = 0; i < 8; i++)
		{
			out[i * 4 + 0] = byte((c.h[i] >> 24) & 0xff);
			out[i * 4 + 1] = byte((c.h[i] >> 16) & 0xff);
			out[i * 4 + 2] = byte((c.h[i] >> 8) & 0xff);
			out[i * 4 + 3] = byte((c.h[i]) & 0xff);
		}
	}
}