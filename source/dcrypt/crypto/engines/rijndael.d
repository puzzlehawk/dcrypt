module dcrypt.crypto.engines.rijndael;

import dcrypt.crypto.blockcipher;

import std.conv:text;

unittest {
	
	// test vectors from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
	string[] test_keys = [
		// sp800-38a.pdf
		x"2b7e151628aed2a6abf7158809cf4f3c",
		x"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	];
	
	string[] test_plaintexts = [
		x"6bc1bee22e409f96e93d7e117393172a",
		x"6bc1bee22e409f96e93d7e117393172a",
		x"6bc1bee22e409f96e93d7e117393172a",
	];
	
	string[] test_ciphertexts = [
		x"3ad77bb40d7a3660a89ecaf32466ef97",
		x"bd334f1d6e45f25ff712a214571fa5cc",
		x"f3eed1bdb5d2a03c064b5a7e3db181f8",
	];
	
	blockCipherTest(new Rijndael128Engine, test_keys, test_plaintexts, test_ciphertexts);
	
	// test all block sizes (128, 160, 192, 244, 256)
	
	string []keys = [
		x"01010101010101010101010101010101",
		x"0101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
		x"01010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
	];
	string[] plains128 = [
		x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
	];
	string[] ciphers128 = [
		x"5e77e59f8f85943489a24149c75f4ec9",
		x"9ff7852b6881845bbb93e90261db12de",
		x"98b895a145ca4e0bf83e693281c1a097",
		x"168d2318e4fc720c8ee355771574fe58",
		x"9cac94c6b48561f8ffaaa78616ba4892",
	];
	
	blockCipherTest(new Rijndael128Engine, keys, plains128, ciphers128);
	
	string[] plains160 = [
		x"0101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101",
	];
	string[] ciphers160 = [
		x"0506b1bf13143240557b6356110a7ef75429535c",
		x"d69122f92262abfc4ccc79233635e64e4ab8d720",
		x"88219b6c6546e2d823323206ffb280035d28e615",
		x"8436e3478b3dbecbf789fede44c1b170e1e6442c",
		x"fef4057ed10ee8afcbae93d99591b39ba01758bd",
	];
	
	
	blockCipherTest(new Rijndael160Engine, keys, plains160, ciphers160);
	
	string[] plains192 = [
		x"010101010101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
	];
	string[] ciphers192 = [
		x"a64984768b532f6cec04216a3f858bb9c4a9f1469caa407f",
		x"8700141eba45ec66d1b386a5baaea6b9f1c996788e220ebc",
		x"c5c85078f586df206b6234a147facc9bf015f108f5da1200",
		x"c12d1c4fa4119aa539f8f637d73b6c27319734e8cf1f499f",
		x"18c0c2c37c137075749352ebec999f7c52d0e64cf15c3af5",
	];
	
	blockCipherTest(new Rijndael192Engine, keys, plains192, ciphers192);
	
	string[] plains224 = [
		x"01010101010101010101010101010101010101010101010101010101",
		x"01010101010101010101010101010101010101010101010101010101",
		x"01010101010101010101010101010101010101010101010101010101",
		x"01010101010101010101010101010101010101010101010101010101",
		x"01010101010101010101010101010101010101010101010101010101",
	];
	string[] ciphers224 = [
		x"4858261dd42a3b457102796e46586aac7d0b37e037a643e76ad27d34",
		x"4fdc0df3213efaf1fd5d44ca66fd04954d2370cd8beb596626da4d8c",
		x"69b308803d2ceca37a7ce4832761d4f027371df7451ca7458ca64f85",
		x"d2ab997da7cb0ccdbaa049715f8c17d3fbecd7e95b40ab814bfad96e",
		x"e6ff389d1fd554c3cbb3f72e62d76d146a4ab2f5fa24ec9d29a543de",
	];
	
	blockCipherTest(new Rijndael224Engine, keys, plains224, ciphers224);
	
	string[] plains256 = [
		x"0101010101010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
	];
	string[] ciphers256 = [
		x"3ae837205c68ae9bec81d302601cc069cb0a3d712604a46b170377c981190143",
		x"e8c91ad4babd2909a575a866229a088ac9d9fad8c9e341a8bfbf647182c4ed7f",
		x"b4bc9135c8b8d291cd202700ce35bfa3a26b84cbdbff3817cb28b8f03283b608",
		x"821e0022e8864d31ba140e50c5c52e6c96b8bcb8c6f1173f57e1429ec9b1b43a",
		x"f6f97c6772f20488e3c0eec5482981b2bd00b15bbdf940069fbf5142ceb39688",
	];
	
	
	blockCipherTest(new Rijndael256Engine, keys, plains256, ciphers256);
}

alias BlockCipherWrapper!(Rijndael!128) Rijndael128Engine; /// Rijndael with 128 bit blocks
alias BlockCipherWrapper!(Rijndael!160) Rijndael160Engine; /// Rijndael with 160 bit blocks
alias BlockCipherWrapper!(Rijndael!192) Rijndael192Engine; /// Rijndael with 192 bit blocks
alias BlockCipherWrapper!(Rijndael!224) Rijndael224Engine; /// Rijndael with 192 bit blocks
alias BlockCipherWrapper!(Rijndael!256) Rijndael256Engine; /// Rijndael with 256 bit blocks

@safe
public struct Rijndael(uint blockBits) {

	static assert(blockBits == 128 || blockBits == 160 || blockBits == 192 || blockBits == 224 || blockBits == 256, "unknown blocksize. Must be 128, 192, 224 or 256.");

	alias ulong[4][MAXROUNDS+1] workingkey_t;

	public {
	
		/// Params:
		/// forEncryption = `false`: decrypt, `true`: encrypt
		/// userKey = Secret key.
		/// iv = Not used.
		void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc
		{
			this.forEncryption = forEncryption;
			workingKey = generateWorkingKey(userKey);
			initialized = true;
		}

		@property
		string name() pure nothrow
		{
			return text("Rijndael-", blockBits);
		}

		uint processBlock(in ubyte[] input, ubyte[] output) nothrow @nogc
		in {
			assert(initialized, "Rijndael engine not initialized");
			assert(blockSize <= input.length, "input buffer too short");
			assert(blockSize <= output.length, "output buffer too short");
		}
		body {
			if (forEncryption)
			{
				unpackBlock(input);
				encryptBlock();
				packBlock(output);
			}
			else
			{
				unpackBlock(input);
				decryptBlock();
				packBlock(output);
			}

			return blockSize;
		}

		void reset() nothrow @nogc
		{
		}

	}

	
	// begin of private section
private:

	
	/**
	 * multiply two elements of GF(2^m)
	 * needed for MixColumn and InvMixColumn
	 */
	@nogc
	private ubyte mul0x2(int b) pure nothrow
	{
		if (b != 0)
		{
			return aLogtable[25 + logtable[b]];
		}
		else
		{
			return 0;
		}
	}

	@nogc
	private ubyte mul0x3(int b) pure nothrow
	{
		if (b != 0)
		{
			return aLogtable[1 + logtable[b]];
		}
		else
		{
			return 0;
		}
	}

	@nogc
	private ubyte mul0x9(int b) pure nothrow
	{
		if (b >= 0)
		{
			return aLogtable[199 + b];
		}
		else
		{
			return 0;
		}
	}

	@nogc
	private ubyte mul0xb(int b) pure nothrow
	{
		if (b >= 0)
		{
			return aLogtable[104 + b];
		}
		else
		{
			return 0;
		}
	}

	@nogc
	private ubyte mul0xd(int b) pure nothrow
	{
		if (b >= 0)
		{
			return aLogtable[238 + b];
		}
		else
		{
			return 0;
		}
	}

	@nogc
	private ubyte mul0xe(int b) pure nothrow
	{
		if (b >= 0)
		{
			return aLogtable[223 + b];
		}
		else
		{
			return 0;
		}
	}

	/**
	 * xor corresponding text input and round key input bytes
	 */
	@nogc
	private void KeyAddition(in ulong[] rk) pure nothrow
	{
		A0 ^= rk[0];
		A1 ^= rk[1];
		A2 ^= rk[2];
		A3 ^= rk[3];
	}

	@nogc
	private ulong shift(ulong r, uint shift) pure nothrow
	{
		return (((r >>> shift) | (r << (BC - shift)))) & BC_MASK;
	}

	/**
	 * Row 0 remains unchanged
	 * The other three rows are shifted a variable amount
	 */
	@nogc
	private void ShiftRow(in ubyte[] shiftsSC) pure nothrow
	{
		A1 = shift(A1, shiftsSC[1]);
		A2 = shift(A2, shiftsSC[2]);
		A3 = shift(A3, shiftsSC[3]);
	}

	@nogc
	private ulong applyS(ulong r, in ubyte[]  box) pure nothrow
	{
		ulong    res = 0;

		for (uint j = 0; j < BC; j += 8)
		{
			res |= cast(ulong)(box[((r >> j) & 0xff)] & 0xff) << j;
		}

		return res;
	}

	/**
	 * Replace every byte of the input by the byte at that place
	 * in the nonlinear S-box
	 */
	@nogc
	private void Substitution(in ubyte[] box) pure nothrow
	{
		A0 = applyS(A0, box);
		A1 = applyS(A1, box);
		A2 = applyS(A2, box);
		A3 = applyS(A3, box);
	}

	/**
	 * Mix the bytes of every column in a linear way
	 */
	@nogc
	private void MixColumn() pure nothrow
	{
		ulong r0, r1, r2, r3;

		r0 = r1 = r2 = r3 = 0;

		for (uint j = 0; j < BC; j += 8)
		{
			uint a0 = cast(uint)((A0 >> j) & 0xff);
			uint a1 = cast(uint)((A1 >> j) & 0xff);
			uint a2 = cast(uint)((A2 >> j) & 0xff);
			uint a3 = cast(uint)((A3 >> j) & 0xff);

			r0 |= cast(ulong)((mul0x2(a0) ^ mul0x3(a1) ^ a2 ^ a3) & 0xff) << j;

			r1 |= cast(ulong)((mul0x2(a1) ^ mul0x3(a2) ^ a3 ^ a0) & 0xff) << j;

			r2 |= cast(ulong)((mul0x2(a2) ^ mul0x3(a3) ^ a0 ^ a1) & 0xff) << j;

			r3 |= cast(ulong)((mul0x2(a3) ^ mul0x3(a0) ^ a1 ^ a2) & 0xff) << j;
		}

		A0 = r0;
		A1 = r1;
		A2 = r2;
		A3 = r3;
	}

	/**
	 * Mix the bytes of every column in a linear way
	 * This is the opposite operation of Mixcolumn
	 */
	@nogc
	private void InvMixColumn() pure nothrow
	{
		ulong r0, r1, r2, r3;

		r0 = r1 = r2 = r3 = 0;
		for (uint j = 0; j < BC; j += 8)
		{
			uint a0 = cast(uint)((A0 >> j) & 0xff);
			uint a1 = cast(uint)((A1 >> j) & 0xff);
			uint a2 = cast(uint)((A2 >> j) & 0xff);
			uint a3 = cast(uint)((A3 >> j) & 0xff);

			//
			// pre-lookup the log table
			//
			a0 = (a0 != 0) ? (logtable[a0 & 0xff]) : -1;
			a1 = (a1 != 0) ? (logtable[a1 & 0xff]) : -1;
			a2 = (a2 != 0) ? (logtable[a2 & 0xff]) : -1;
			a3 = (a3 != 0) ? (logtable[a3 & 0xff]) : -1;

			r0 |= cast(ulong)((mul0xe(a0) ^ mul0xb(a1) ^ mul0xd(a2) ^ mul0x9(a3)) & 0xff) << j;

			r1 |= cast(ulong)((mul0xe(a1) ^ mul0xb(a2) ^ mul0xd(a3) ^ mul0x9(a0)) & 0xff) << j;

			r2 |= cast(ulong)((mul0xe(a2) ^ mul0xb(a3) ^ mul0xd(a0) ^ mul0x9(a1)) & 0xff) << j;

			r3 |= cast(ulong)((mul0xe(a3) ^ mul0xb(a0) ^ mul0xd(a1) ^ mul0x9(a2)) & 0xff) << j;
		}

		A0 = r0;
		A1 = r1;
		A2 = r2;
		A3 = r3;
	}

	/**
	 * Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */
	private workingkey_t generateWorkingKey(in ubyte[] key) pure nothrow @nogc
	{
		uint         KC;
		uint         t, rconpointer = 0;
		uint         keyBits = cast(uint)(key.length * 8);
		ubyte[MAXKC][4]    tk;
		workingkey_t    W;

		switch (keyBits)
		{
			case 128:
				KC = 4;
				break;
			case 160:
				KC = 5;
				break;
			case 192:
				KC = 6;
				break;
			case 224:
				KC = 7;
				break;
			case 256:
				KC = 8;
				break;
			default :
				assert(false, "Key length not 128/160/192/224/256 bits.");
		}

		if (keyBits >= blockBits)
		{
			ROUNDS = KC + 6;
		}
		else
		{
			ROUNDS = (BC / 8) + 6;
		}

		//
		// copy the key into the processing area
		//
		uint index = 0;

		for (uint i = 0; i < key.length; i++)
		{
			tk[i % 4][i / 4] = key[index++];
		}

		t = 0;

		//
		// copy values into round key array
		//
		for (uint j = 0; (j < KC) && (t < (ROUNDS+1)*(BC / 8)); j++, t++)
		{
			for (uint i = 0; i < 4; i++)
			{
				W[t / (BC / 8)][i] |= cast(ulong)(tk[i][j] & 0xff) << ((t * 8) % BC);
			}
		}

		//
		// while not enough round key material calculated
		// calculate new values
		//
		while (t < (ROUNDS+1)*(BC/8))
		{
			for (uint i = 0; i < 4; i++)
			{
				tk[i][0] ^= S[tk[(i+1)%4][KC-1] & 0xff];
			}
			tk[0][0] ^= rcon[rconpointer++];

			if (KC <= 6)
			{
				for (uint j = 1; j < KC; j++)
				{
					for (uint i = 0; i < 4; i++)
					{
						tk[i][j] ^= tk[i][j-1];
					}
				}
			}
			else
			{
				for (uint j = 1; j < 4; j++)
				{
					for (uint i = 0; i < 4; i++)
					{
						tk[i][j] ^= tk[i][j-1];
					}
				}
				for (uint i = 0; i < 4; i++)
				{
					tk[i][4] ^= S[tk[i][3] & 0xff];
				}
				for (uint j = 5; j < KC; j++)
				{
					for (uint i = 0; i < 4; i++)
					{
						tk[i][j] ^= tk[i][j-1];
					}
				}
			}

			//
			// copy values into round key array
			//
			for (uint j = 0; (j < KC) && (t < (ROUNDS+1)*(BC/8)); j++, t++)
			{
				for (uint i = 0; i < 4; i++)
				{
					W[t / (BC/8)][i] |= cast(ulong)(tk[i][j] & 0xff) << ((t * 8) % (BC));
				}
			}
		}

		return W;
	}

private:

	uint         ROUNDS;
	workingkey_t    workingKey;
	ulong        A0, A1, A2, A3;
	bool forEncryption;
	bool initialized = false;

	
	// set constants according to the block size
	static if(blockBits == 128) {
		enum BC = 32;
		enum BC_MASK = 0xffffffffL;
		immutable (ubyte)[] shifts0SC = [ 0, 8, 16, 24 ];
		immutable (ubyte)[] shifts1SC = [ 0, 24, 16, 8 ];
	} else 
	static if(blockBits == 160) {
		enum BC = 40;
		enum BC_MASK = 0xffffffffffL;
		immutable (ubyte)[] shifts0SC = [ 0, 8, 16, 24 ];
		immutable (ubyte)[] shifts1SC = [ 0, 32, 24, 16 ];
	} else 
	static if(blockBits == 192) {
		enum BC = 48;
		enum BC_MASK = 0xffffffffffffL;
		immutable (ubyte)[] shifts0SC = [ 0, 8, 16, 24 ];
		immutable (ubyte)[] shifts1SC = [ 0, 40, 32, 24 ];
	} else 
	static if(blockBits == 224) {
		enum BC = 56;
		enum BC_MASK = 0xffffffffffffffL;
		immutable (ubyte)[] shifts0SC = [ 0, 8, 16, 32 ];
		immutable (ubyte)[] shifts1SC = [ 0, 48, 40, 24 ];
	} else 
	static if(blockBits == 256) {
		enum BC = 64;
		enum BC_MASK = 0xffffffffffffffffL;
		immutable (ubyte)[] shifts0SC = [ 0, 8, 24, 32 ];
		immutable (ubyte)[] shifts1SC = [ 0, 56, 40, 32 ];
	} else {
		static assert(false, "invalid block size");
	}
	public enum blockSize = BC/2;

	private nothrow @nogc:

	void unpackBlock(in ubyte[] bytes)
	{
		uint     index = 0;

		A0 = cast(ulong)(bytes[index++] & 0xff);
		A1 = cast(ulong)(bytes[index++] & 0xff);
		A2 = cast(ulong)(bytes[index++] & 0xff);
		A3 = cast(ulong)(bytes[index++] & 0xff);

		for (uint j = 8; j != BC; j += 8)
		{
			A0 |= cast(ulong)(bytes[index++] & 0xff) << j;
			A1 |= cast(ulong)(bytes[index++] & 0xff) << j;
			A2 |= cast(ulong)(bytes[index++] & 0xff) << j;
			A3 |= cast(ulong)(bytes[index++] & 0xff) << j;
		}
	}
	
	@nogc
	void packBlock(ubyte[] bytes)
	{
		uint     index = 0;

		for (uint j = 0; j != BC; j += 8)
		{
			bytes[index++] = cast(ubyte)(A0 >> j);
			bytes[index++] = cast(ubyte)(A1 >> j);
			bytes[index++] = cast(ubyte)(A2 >> j);
			bytes[index++] = cast(ubyte)(A3 >> j);
		}
	}

	void encryptBlock()
	{
		alias workingKey rk;
		uint r;

		//
		// begin with a key addition
		//
		KeyAddition(rk[0]);

		//
		// ROUNDS-1 ordinary rounds
		//
		for (r = 1; r < ROUNDS; r++)
		{
			Substitution(S);
			ShiftRow(shifts0SC);
			MixColumn();
			KeyAddition(rk[r]);
		}

		//
		// Last round is special: there is no MixColumn
		//
		Substitution(S);
		ShiftRow(shifts0SC);
		KeyAddition(rk[ROUNDS]);
	}
	
	void decryptBlock()
	{
		alias workingKey rk;
		uint r;

		// To decrypt: apply the inverse operations of the encrypt routine,
		//             in opposite order
		//
		// (KeyAddition is an involution: it 's equal to its inverse)
		// (the inverse of Substitution with table S is Substitution with the inverse table of S)
		// (the inverse of Shiftrow is Shiftrow over a suitable distance)
		//

		// First the special round:
		//   without InvMixColumn
		//   with extra KeyAddition
		//
		KeyAddition(rk[ROUNDS]);
		Substitution(Si);
		ShiftRow(shifts1SC);

		//
		// ROUNDS-1 ordinary rounds
		//
		for (r = ROUNDS-1; r > 0; r--)
		{
			KeyAddition(rk[r]);
			InvMixColumn();
			Substitution(Si);
			ShiftRow(shifts1SC);
		}

		//
		// End with the extra key addition
		//
		KeyAddition(rk[0]);
	}

	// tables & constants

	static immutable:
	
	enum MAXROUNDS = 14;
	
	enum MAXKC = (256/4);
	
	ubyte[256] logtable = [
		0,    0,    25,   1,    50,   2,    26,   198,
		75,   199,  27,   104,  51,   238,  223,  3,
		100,  4,    224,  14,   52,   141,  129,  239,
		76,   113,  8,    200,  248,  105,  28,   193,
		125,  194,  29,   181,  249,  185,  39,   106,
		77,   228,  166,  114,  154,  201,  9,    120,
		101,  47,   138,  5,    33,   15,   225,  36,
		18,   240,  130,  69,   53,   147,  218,  142,
		150,  143,  219,  189,  54,   208,  206,  148,
		19,   92,   210,  241,  64,   70,   131,  56,
		102,  221,  253,  48,   191,  6,    139,  98,
		179,  37,   226,  152,  34,   136,  145,  16,
		126,  110,  72,   195,  163,  182,  30,   66,
		58,   107,  40,   84,   250,  133,  61,   186,
		43,   121,  10,   21,   155,  159,  94,   202,
		78,   212,  172,  229,  243,  115,  167,  87,
		175,  88,   168,  80,   244,  234,  214,  116,
		79,   174,  233,  213,  231,  230,  173,  232,
		44,   215,  117,  122,  235,  22,   11,   245,
		89,   203,  95,   176,  156,  169,  81,   160,
		127,  12,   246,  111,  23,   196,  73,   236,
		216,  67,   31,   45,   164,  118,  123,  183,
		204,  187,  62,   90,   251,  96,   177,  134,
		59,   82,   161,  108,  170,  85,   41,   157,
		151,  178,  135,  144,  97,   190,  220,  252,
		188,  149,  207,  205,  55,   63,   91,   209,
		83,   57,   132,  60,   65,   162,  109,  71,
		20,   42,   158,  93,   86,   242,  211,  171,
		68,   17,   146,  217,  35,   32,   46,   137,
		180,  124,  184,  38,   119,  153,  227,  165,
		103,  74,   237,  222,  197,  49,   254,  24,
		13,   99,   140,  128,  192,  247,  112,  7
	];
	
	ubyte[511] aLogtable = [
		0,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1,
		3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1,
	];
	
	ubyte[256] S = [
		99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
		202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
		183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
		4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
		9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
		83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
		208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
		81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
		205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
		96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
		224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
		231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
		186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
		112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
		225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
		140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22,
	];
	
	ubyte[256] Si = [
		82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
		124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
		84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
		8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
		114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
		108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
		144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
		208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
		58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
		150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
		71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
		252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
		31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
		96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
		160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
		23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125,
	];
	
	ubyte[30] rcon = [
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 ];

}