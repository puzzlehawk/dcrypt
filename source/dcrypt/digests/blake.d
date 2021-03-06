﻿module dcrypt.digests.blake;

/// Implementation of the BLAKE SHA-3 proposal.
/// https://131002.net/blake/blake.pdf

public import dcrypt.digest;
import dcrypt.bitmanip: ror, fromBigEndian, toBigEndian;
import dcrypt.util: wipe;
import std.conv: text;

alias Blake!224 Blake224;
alias Blake!256 Blake256;
alias Blake!384 Blake384;
alias Blake!512 Blake512;

alias WrapperDigest!Blake224 Blake224Digest;
alias WrapperDigest!Blake256 Blake256Digest;
alias WrapperDigest!Blake384 Blake384Digest;
alias WrapperDigest!Blake512 Blake512Digest;

static assert(isDigest!Blake224, "Blake224 does not fullfill requirements of isDigest.");
static assert(isDigest!Blake256, "Blake256 does not fullfill requirements of isDigest.");
static assert(isDigest!Blake384, "Blake384 does not fullfill requirements of isDigest.");
static assert(isDigest!Blake512, "Blake512 does not fullfill requirements of isDigest.");

@safe
struct Blake(uint bitLength)
if(bitLength == 224 || bitLength == 256 || bitLength == 384 || bitLength == 512) {

	enum digestLength = bitLength / 8;
	enum name = text("Blake", bitLength);
	enum blockSize = 0;

	private {

		static if(bitLength <= 256) {
			alias uint Word;
		} else {
			alias ulong Word;
		}

		// Set IV.
		static if(bitLength == 224) {

			static immutable Word[8] iv = [
				0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
				0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
			];

		} else static if(bitLength == 256) {

			static immutable Word[8] iv = [
				0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
				0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
			];
			
		} else static if(bitLength == 384) {

			static immutable Word[8] iv = [
				0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
				0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
			];

		} else static if(bitLength == 512) {

			static immutable Word[8] iv = [
				0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
				0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
			];

		} else {
			static assert(false, "Invalid bit length.");
		}

		// Set constants and number of rounds.
		static if(bitLength == 224 || bitLength == 256) {
			
			enum rounds = 14;

			static immutable Word[16] cst = [
				0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
				0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
				0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
				0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
			];

		} else static if(bitLength == 384 || bitLength == 512) {
			
			enum rounds = 16;

			static immutable Word[16] cst = [
				0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
				0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
				0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
				0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69
			];

		} else {
			static assert(false, "Invalid bit length.");
		}
		
		static immutable uint[16][16] perm = [
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
			[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
			[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
			[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]
		];

		Word[8] 	h = iv;
		Word[4]		salt = 0;
		Word[2]		counter = 0;

		ubyte[Word.sizeof * 16] buf = 0;
		size_t bufPtr = 0;
	}

	public void start() nothrow @nogc @safe {
		h = iv;
		salt[] = 0;
		counter[] = 0;
		buf[] = 0;
		bufPtr = 0;
	}

	~this() {
		wipe(buf);
	}

	invariant {
		assert(bufPtr <= buf.length, "bufPtr out of range.");
	}

	public void put(const (ubyte)[] input...) nothrow @nogc @safe {
		// TODO optimize
		while(input.length >= buf.length-bufPtr) {
			buf[bufPtr..$] = input[0..buf.length-bufPtr];
			input = input[buf.length-bufPtr..$];
			absorb(buf.length*8);
		}
		if(input.length > 0) {
			assert(input.length < buf.length-bufPtr);
			buf[bufPtr..bufPtr+input.length] = input[];
			bufPtr += input.length;
		}
	}

	public ubyte[digestLength] finish() nothrow @nogc @safe {

		// pad to 447 bits (message || 1 || 0...0 || 1) 
		// at least 1 byte padding + 2*Word.sizeof bytes for length

		enum counterSize = counter.length*Word.sizeof;
		enum requiredSpace = 1 + counterSize;

		assert(bufPtr < buf.length, "There's not a single free byte in the buffer.");

		buf[bufPtr] = 0b10000000;

		if(buf.length-bufPtr < requiredSpace) {
			// must add a block
			buf[bufPtr+1..$] = 0;
			absorb(cast(uint) bufPtr*8);
			assert(bufPtr == 0);
		}
		assert(buf.length-bufPtr >= requiredSpace, "Whoops...");
		assert((buf[bufPtr] & 0b01111111) == 0, "Byte must be either 0 or 0x80");

		buf[bufPtr+1..$] = 0;

		static if(bitLength == 256 || bitLength == 512) {
			buf[$-requiredSpace] |= 0b1;
		} else {
			// This padding bit is 0 for 224 and 384 bits.
		}

		incCounter(cast(uint) bufPtr*8);

		toBigEndian(counter[1], buf[$-counterSize..$-Word.sizeof]);
		toBigEndian(counter[0], buf[$-Word.sizeof..$]);

		// Set counter to zero if last block contains no message bit.
		counter[0] &= -cast(Word)(bufPtr != 0);
		counter[1] &= -cast(Word)(bufPtr != 0);

		absorb();

		ubyte[digestLength] hn;
		toBigEndian(h[0..digestLength/Word.sizeof], hn[]);
		start();
		return hn;
	}

	private void absorb(in uint bits = 0) nothrow @nogc @safe {
		Word[16] msg;
		fromBigEndian(buf, msg);

		incCounter(bits);

		compress(h, msg, salt, counter);

		bufPtr = 0;
		buf[] = 0;	// TODO: clear in finish() if necessary
	}

	private void incCounter(in Word i) nothrow @nogc @safe {
		counter[0] += i;
		counter[1] += counter[0] < i; // detect carry
	}

	// Test incCounter function.
	private unittest {
		immutable Word max = -1;

		Blake!bitLength blake;
		assert(blake.counter == [0, 0]);
		blake.incCounter(0);
		assert(blake.counter == [0, 0]);
		blake.incCounter(1);
		assert(blake.counter == [1, 0]);
		blake.incCounter(2);
		assert(blake.counter == [3, 0]);
		blake.incCounter(4);
		assert(blake.counter == [7, 0]);
		blake.incCounter(max - 7 + 1);
		assert(blake.counter == [0, 1]);
		blake.incCounter(max);
		assert(blake.counter == [max, 1]);
		blake.incCounter(1);
		assert(blake.counter == [0, 2]);
		blake.incCounter(max);
		assert(blake.counter == [max, 2]);
		blake.incCounter(43);
		assert(blake.counter == [42, 3]);
	}

	private static void compress(ref Word[8] h, in ref Word[16] m, in ref Word[4] salt, in ref Word[2] ctr) pure nothrow @nogc @safe {
		Word[16] state;

		// initialize
		state[0..8] = h;
		state[8..16] = cst[0..8];
		state[8..12] ^= salt[];
		state[12..14] ^= ctr[0];
		state[14..16] ^= ctr[1];

		foreach(r; 0..rounds) {
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

	private static void G(uint i)(in size_t r, in ref Word[16] msg, ref Word a, ref Word b, ref Word c, ref Word d) pure nothrow @nogc @safe {

		static if(Word.sizeof == 4) {
			// rotation distances for Blake224 and Blake256
			enum r0 = 16, r1 = 12, r2 = 8, r3 = 7;
		} else static if (Word.sizeof == 8) {
			// rotation distances for Blake384 and Blake512
			enum r0 = 32, r1 = 25, r2 = 16, r3 = 11;
		} else {
			static assert(false, "Word consist of 4 or 8 bytes.");
		}

		a += b + (msg[perm[r][2*i]] ^ cst[perm[r][2*i+1]]); 
		d = ror(d^a, r0);
		c += d; 
		b = ror(b^c, r1);
		a += b + (msg[perm[r][2*i+1]] ^ cst[perm[r][2*i]]);
		d = ror(d^a, r2);
		c += d; 
		b = ror(b^c, r3);
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



unittest {
	Blake!224 blake;
	
	ubyte[576/8] msg;
	
	blake.put(msg);
	auto hash = blake.finish();
	assert(hash == x"f5aa00dd1cb847e3140372af7b5c46b4888d82c8c0a917913cfb5d04");
}


unittest {
	Blake!256 blake;

	ubyte[576/8] msg;

	blake.put(msg);
	auto hash = blake.finish();
	assert(hash == x"d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41");
}

unittest {
	Blake!384 blake;
	
	ubyte[1152/8] msg;
	
	blake.put(msg);
	auto hash = blake.finish();
	assert(hash == x"
		0B9845DD429566CD  AB772BA195D271EF  FE2D0211F16991D7  66BA749447C5CDE5
		69780B2DAA66C4B2  24A2EC2E5D09174C"
		);
}


unittest {
	Blake!512 blake;
	
	ubyte[1152/8] msg;
	
	blake.put(msg);
	auto hash = blake.finish();
	assert(hash == x"
		313717D608E9CF75  8DCB1EB0F0C3CF9F  C150B2D500FB33F5  1C52AFC99D358A2F
		1374B8A38BBA7974  E7F6EF79CAB16F22  CE1E649D6E01AD95  89C213045D545DDE"
		);
}

unittest {
	
	immutable string[] plaintexts = [
		x"",
		x"00"
	];
	
	immutable string[] hashes = [
		x"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed",
		x"4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5"
	];
	
	testDigest(new Blake224Digest, plaintexts, hashes);
}

unittest {
	
	immutable string[] plaintexts = [
		x"00",
		"The quick brown fox jumps over the lazy dog",
		// 54 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		00000000000000000000000000000000000000000000",
		// 55 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000",
		// 56 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		000000000000000000000000000000000000000000000000",
		// 57 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		00000000000000000000000000000000000000000000000000",
		// 63 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		00000000000000000000000000000000000000000000000000000000000000",
		// 64 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000",
	];
	
	immutable string[] hashes = [
		x"0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87",
		x"7576698EE9CAD30173080678E5965916ADBB11CB5245D386BF1FFDA1CB26C9D7",
		x"8b7b134b0450f2ee19935dc82df3e4fa7f990b320b1a9afbf1e40914c6fb67cc",
		x"dc980544f4181cc43505318e317cdfd4334dab81ae035a28818308867ce23060",
		x"26ae7c289ebb79c9f3af2285023ab1037a9a6db63f0d6b6c6bbd199ab1627508",
		x"363446fac666e859deae9e81c458662371b6fdd0793712735911071c2be9456b",
		x"254b522be8c966d8a2c44a2bffce8469f8223ea3371e14e6387d60fc790361f1",
		x"6d994042954f8dc5633626cd50b2bc66d733a313d67fd9702c5a8149a8028c98"
	];
	
	testDigest(new Blake256Digest, plaintexts, hashes);
}

unittest {
	
	immutable string[] plaintexts = [
		x"",
		x"00",
		// 127 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		00000000000000000000000000000000000000000000000000000000000000"
	];
	
	immutable string[] hashes = [
		x"c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706",
		x"10281f67e135e90ae8e882251a355510a719367ad70227b137343e1bc122015c29391e8545b5272d13a7c2879da3d807",
		x"980a24df8bfdfa1e2dfcd19c945f9ee8e7e64487bd0a3a63c44a5879a83b45622dc19b5e0f2c63c57a65f405e31c7f3f"
	];
	
	testDigest(new Blake384Digest, plaintexts, hashes);
}

/// Test vectors generated with reference implementation.
/// 
/// Generate the reference hash:
/// ./blake512 <(perl -e 'print "\x00"x127')
/// 
/// Generate the input data as hex:
/// perl -e 'print "\x00"x127' | xxd -ps -c 32
/// 
unittest {
	
	immutable string[] plaintexts = [
		x"",
		x"00",
		"The quick brown fox jumps over the lazy dog",
		// 127 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		00000000000000000000000000000000000000000000000000000000000000",
		// 128 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000",
		// 129 zeros
		x"0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		0000000000000000000000000000000000000000000000000000000000000000
		00"
	];
		
	immutable string[] hashes = [
		x"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
		x"97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3",
		x"1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451",
		x"d6bd99cb8f201c5e777f25859cca7b21b4659fce0e19d04de85be6566cae87b9b15e4b82f9e80eea894aaaea15e26f08ce6cd2af9f0fef1a15486cdf9c8ca8df",
		x"0f6f3a3a91f752d37e3d37141d5459aca9a88ed2d5b88f71120fbe39387b635ecf6402a5bcb7b18f216ea9a8137d28954098e586014c4d435c979d8860d3a977",
		x"c75df1083f0cff9a4b423b0f5cdcee6526133513198f897c89901d0ab80995bf9cefe01c992563b5dd4a8f76f22f16859615c30b309efe329f7462eb280df34c"
	];
	
	testDigest(new Blake512Digest, plaintexts, hashes);
}