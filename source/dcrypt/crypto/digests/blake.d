module dcrypt.crypto.digests.blake;

import dcrypt.bitmanip: rol;

struct Blake(uint bitlength) {

	static if(bitLength <= 256) {
		alias uint Word;
	} else {
		alias ulong Word;
	}

	Word[8] h = iv;

	Word[16]	state;
	Word[4]		salt;
	Word[2]		counter;

	// initial values
	static if(bitLength == 256) {
		static immutable Word[8] iv = [
			0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
			0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
		];

		static immutable Word c = [
			0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
			0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
			0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
			0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917];

	} else static if(bitLength == 384) {
		enum Word
			iv1 = 0xcbbb9d5dc1059ed8,
			iv2 = 0x629a292a367cd507,
			iv3 = 0x9159015a3070dd17,
			iv4 = 0x152fecd8f70e5939,
			iv5 = 0x67332667ffc00b31,
			iv6 = 0x8eb44a8768581511,
			iv7 = 0xdb0c2e0d64f98fa7,
			iv8 = 0x47b5481dbefa4fa4;
	} else static if(bitLength == 512) {
		enum Word
			iv1 = 0x6a09e667f3bcc908,
			iv2 = 0xbb67ae8584caa73b,
			iv3 = 0x3c6ef372fe94f82b,
			iv4 = 0xa54ff53a5f1d36f1,
			iv5 = 0x510e527fade682d1,
			iv6 = 0x9b05688c2b3e6c1f,
			iv7 = 0x1f83d9abfb41bd6b,
			iv8 = 0x5be0cd19137e2179;
	} else {
		static assert(false, "invalid bitlength");
	}

	static immutable uint[][] perm = [
		[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
		[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
		[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
		[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
		[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
		[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
		[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
		[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
		[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
		[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
		[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
		[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]
	];

	private void compress(ref Word[8] h, in ref Word[16] m, in ref Word[4] salt, in ref Word[2] ctr) pure {
		Word[16] state;

		// initialize
		state[0..8] = h;
		state[8..16] = c;
		state[8..12] ^= s;
		state[12..14] ^= ctr[0];
		state[14..16] ^= ctr[1];

		foreach(r; 0..14) {
			G(0)(r, m, state[0], state[4], state[8], state[12]);
			G(1)(r, m, state[1], state[5], state[9], state[13]);
			G(2)(r, m, state[2], state[6], state[10], state[14]);
			G(3)(r, m, state[3], state[7], state[11], state[15]);

			G(4)(r, m, state[0], state[5], state[10], state[15]);
			G(5)(r, m, state[1], state[6], state[11], state[12]);
			G(6)(r, m, state[2], state[7], state[8], state[13]);
			G(7)(r, m, state[3], state[4], state[9], state[14]);
		}

		// finalize
		h ^= state[0..8];
		h ^= state[8..16];
		h[0..4] ^= salt;
		h[4..8] ^= salt;
	}

	private static void G(uint i, Word)(in size_t r, in ref Word[16] msg, ref Word a, ref Word b, ref Word c, ref Word d) pure nothrow @nogc @safe {
		a += b + m[perm[r][2*i]] ^ c[perm[r][2*i+1]]; 
		d = ror(d^a, 16);
		c += d;  b = ror(b^c, 12);
		a += b + m[perm[r][2*i+1]] ^ c[perm[r][2*i]];
		d = ror(d^a, 8);
		c += d;  b = ror(b^c, 7);
	}

	unittest {
		Word v;
	}
}