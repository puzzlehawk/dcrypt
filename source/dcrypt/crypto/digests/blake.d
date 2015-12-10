module dcrypt.crypto.digests.blake;

import dcrypt.bitmanip: ror, fromBigEndian;

struct Blake(uint bitLength) {

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

		static immutable Word[16] cst = [
			0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
			0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
			0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
			0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
		];

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

	static immutable uint[16][14] perm = [
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

	private static void compress(ref Word[8] h, in ref Word[16] m, in ref Word[4] salt, in ref Word[2] ctr) {
		Word[16] state;

		// initialize
		state[0..8] = h;
		state[8..16] = cst[0..8];
		state[8..12] ^= salt[];
		state[12..14] ^= ctr[0];
		state[14..16] ^= ctr[1];

		foreach(r; 0..14) {
			round(r, m, state);
		}

		// finalize
		h[] ^= state[0..8];
		h[] ^= state[8..16];
		h[0..4] ^= salt[];
		h[4..8] ^= salt[];
	}

	private static void round(in size_t r, in ref Word[16] m, ref Word[16] state) pure nothrow @nogc @safe {
		G!0(r, m, state[0], state[4], state[8], state[12]);
		G!1(r, m, state[1], state[5], state[9], state[13]);
		G!2(r, m, state[2], state[6], state[10], state[14]);
		G!3(r, m, state[3], state[7], state[11], state[15]);
		
		G!4(r, m, state[0], state[5], state[10], state[15]);
		G!5(r, m, state[1], state[6], state[11], state[12]);
		G!6(r, m, state[2], state[7], state[8], state[13]);
		G!7(r, m, state[3], state[4], state[9], state[14]);
	}

	private static void G(uint i, Word)(in size_t r, in ref Word[16] msg, ref Word a, ref Word b, ref Word c, ref Word d) pure nothrow @nogc @safe {
		a += b + (msg[perm[r][2*i]] ^ cst[perm[r][2*i+1]]); 
		d = ror(d^a, 16);
		c += d; 
		b = ror(b^c, 12);
		a += b + (msg[perm[r][2*i+1]] ^ cst[perm[r][2*i]]);
		d = ror(d^a, 8);
		c += d; 
		b = ror(b^c, 7);
	}


}

/// Test BLAKE round function.
private unittest {
	alias uint Word;

	Word[16] msg;
	fromBigEndian!Word(cast(const ubyte[]) x"
			00800000  00000000  00000000  00000000  00000000  00000000  00000000  00000000
			00000000  00000000  00000000  00000000  00000000  00000001  00000000  00000008", 
			msg
		);

	Word[16] v0;
	fromBigEndian!Word(cast(const ubyte[]) x"
			6A09E667  BB67AE85  3C6EF372  A54FF53A  510E527F  9B05688C  1F83D9AB  5BE0CD19
			243F6A88  85A308D3  13198A2E  03707344  A409382A  299F31D8  082EFA98  EC4E6C89", 
			v0
		);

	Word[16] expected1;
	fromBigEndian!Word(cast(const ubyte[]) x"
			E78B8DFE  150054E7  CABC8992  D15E8984  0669DF2A  084E66E3  A516C4B3  339DED5B
			26051FB7  09D18B27  3A2E8FA8  488C6059  13E513E6  B37ED53E  16CAC7B9  75AF6DF6", 
			expected1
		);

	Word[16] expected2;
	fromBigEndian!Word(cast(const ubyte[]) x"
			9DE875FD  8286272E  ADD20174  F1B0F1B7  37A1A6D3  CF90583A  B67E00D2  943A1F4F
			E5294126  43BD06BF  B81ECBA2  6AF5CEAF  4FEB3A1F  0D6CA73C  5EE50B3E  DC88DF91", 
			expected2
		);

	Word[16] v = v0;

	Blake!256.round(0, msg, v);
	assert(v== expected1, "BLAKE round failed!");

	Blake!256.round(1, msg, v);
	assert(v== expected2, "BLAKE round failed!");

	Word[4] salt;
	Word[2] counter = [0x00000008, 0x00000000];
	Word[8] h = Blake!256.iv;

	Blake!256.compress(h, msg, salt, counter);

	Word[8] expectedH;
	fromBigEndian!Word(cast(const ubyte[]) x"
			0CE8D4EF 4DD7CD8D 62DFDED9 D4EDB0A7 74AE6A41 929A74DA 23109E8F 11139C87", 
			expectedH
		);

	assert(h == expectedH, "BLAKE round failed!");
}