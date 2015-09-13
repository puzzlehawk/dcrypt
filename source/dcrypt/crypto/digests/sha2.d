module dcrypt.crypto.digests.sha2;

/// Implementation of SHA256, SHA384 and SHA512 hash algorithms.

public import dcrypt.crypto.digest;

import dcrypt.bitmanip;
import std.conv: text;

alias SHA!256 SHA256;
alias SHA!384 SHA384;
alias SHA!512 SHA512;

// OOP Wrapper
alias WrapperDigest!SHA256 SHA256Digest;
alias WrapperDigest!SHA384 SHA384Digest;
alias WrapperDigest!SHA512 SHA512Digest;

static assert(isDigest!SHA256, "SHA256 does not fullfill requirements of isDigest.");
static assert(isDigest!SHA384, "SHA384 does not fullfill requirements of isDigest.");
static assert(isDigest!SHA512, "SHA512 does not fullfill requirements of isDigest.");


@safe
public struct SHA(uint bitLength)
if(bitLength == 256 || bitLength == 384 || bitLength == 512) {

	public enum	name = text("SHA", bitLength);
	public enum digestLength = bitLength / 8;

	/// Reset the digest to its initial state. It is not necessary to call start after finish or doFinal.
	public void start() nothrow @nogc {

		H1 = initH1;
		H2 = initH2;
		H3 = initH3;
		H4 = initH4;
		H5 = initH5;
		H6 = initH6;
		H7 = initH7;
		H8 = initH8;

		byteCount1 = 0;

		static if(bitLength > 256) {
			byteCount2 = 0;
		}

		xBufOff = 0;
		xBuf[] = 0;

		xOff = 0;
		X[] = 0;
	};

	alias put update; /// ensure compatibility to older code

	void put(const (ubyte)[] input...) nothrow @nogc
	{
		// fill the current word
		while(xBufOff != 0 && input.length > 0) {
			putSingleByte(input[0]);
			input = input[1..$];
		}
		
		// process whole words
		while(input.length > xBuf.length) {
			processWord(input);
			byteCount1 += xBuf.length;
			input = input[xBuf.length..$];
		}
		
		// process remainder
		foreach(ubyte b; input) {
			putSingleByte(b);
		}
	}

	/// Calculate the final hash value.
	/// Returns: the hash value
	ubyte[digestLength] finish() nothrow @nogc {
		ubyte[digestLength] output;
		_finish();
		
		// pack the integers into a byte array
		// toBigEndian!ulong([H1,H2,H3,H4,H5,H6,H7,H8], output);
		
		enum wordBytes = Word.sizeof;
		
		toBigEndian!Word(H1, output[0*wordBytes..1*wordBytes]);
		toBigEndian!Word(H2, output[1*wordBytes..2*wordBytes]);
		toBigEndian!Word(H3, output[2*wordBytes..3*wordBytes]);
		toBigEndian!Word(H4, output[3*wordBytes..4*wordBytes]);
		toBigEndian!Word(H5, output[4*wordBytes..5*wordBytes]);
		toBigEndian!Word(H6, output[5*wordBytes..6*wordBytes]);
		
		static if(bitLength == 256 || bitLength == 512) {
			toBigEndian!Word(H7, output[6*wordBytes..7*wordBytes]);
			toBigEndian!Word(H8, output[7*wordBytes..8*wordBytes]);
		}
		
		start();
		
		return output;
	}

	
private:

	static if(bitLength == 256) {
		alias uint Word;
	} else {
		alias ulong Word;
	}

	void putSingleByte(ubyte input) nothrow @nogc
	{
		xBuf[xBufOff++] = input;
		
		if (xBufOff == xBuf.length)
		{
			processWord(xBuf);
			xBufOff = 0;
		}
		
		byteCount1++;
	}

	/// process one word of input (4 bytes for sha256, 8 bytes for longer hashes)
	void processWord(in ubyte[] input) nothrow @nogc
	{
		X[xOff] = fromBigEndian!Word(input);
		
		if (++xOff == 16)
		{
			processBlock();
		}
	}

	void processLength(Word lowW, Word hiW) nothrow @nogc
	{
		if (xOff > 14)
		{
			processBlock();
		}

		X[14] = hiW;
		X[15] = lowW;
	}

	void processBlock() nothrow @nogc
	{
		static if(bitLength > 256){
			adjustByteCounts();
		}
		
		//
		// expand 16 word block into 80 word blocks.
		//
		foreach (size_t t; 16..X.length)
		{
			X[t] = Sigma1(X[t - 2]) + X[t - 7] + Sigma0(X[t - 15]) + X[t - 16];
		}
		
		//
		// set up working variables.
		//
		Word     a = H1;
		Word     b = H2;
		Word     c = H3;
		Word     d = H4;
		Word     e = H5;
		Word     f = H6;
		Word     g = H7;
		Word     h = H8;
		
		size_t t = 0;

		static if(bitLength == 256) {
			enum rounds = 8;
		} else {
			enum rounds = 10;
		}

		foreach(size_t i; 0..rounds)
		{
			// t = 8 * i
			h += Sum1(e) + Ch(e, f, g) + K[t] + X[t];
			d += h;
			h += Sum0(a) + Maj(a, b, c);
			++t;
			
			// t = 8 * i + 1
			g += Sum1(d) + Ch(d, e, f) + K[t] + X[t];
			c += g;
			g += Sum0(h) + Maj(h, a, b);
			++t;
			
			// t = 8 * i + 2
			f += Sum1(c) + Ch(c, d, e) + K[t] + X[t];
			b += f;
			f += Sum0(g) + Maj(g, h, a);
			++t;
			
			// t = 8 * i + 3
			e += Sum1(b) + Ch(b, c, d) + K[t] + X[t];
			a += e;
			e += Sum0(f) + Maj(f, g, h);
			++t;
			
			// t = 8 * i + 4
			d += Sum1(a) + Ch(a, b, c) + K[t] + X[t];
			h += d;
			d += Sum0(e) + Maj(e, f, g);
			++t;
			
			// t = 8 * i + 5
			c += Sum1(h) + Ch(h, a, b) + K[t] + X[t];
			g += c;
			c += Sum0(d) + Maj(d, e, f);
			++t;
			
			// t = 8 * i + 6
			b += Sum1(g) + Ch(g, h, a) + K[t] + X[t];
			f += b;
			b += Sum0(c) + Maj(c, d, e);
			++t;
			
			// t = 8 * i + 7
			a += Sum1(f) + Ch(f, g, h) + K[t] + X[t];
			e += a;
			a += Sum0(b) + Maj(b, c, d);
			++t;
		}

		H1 += a;
		H2 += b;
		H3 += c;
		H4 += d;
		H5 += e;
		H6 += f;
		H7 += g;
		H8 += h;
		
		//
		// reset the offset and clean out the word buffer.
		//
		xOff = 0;
		X[] = 0;
	}

	private void _finish() nothrow @nogc
	{
		static if(bitLength == 256) {
			ulong bitlen = byteCount1 << 3;

			// Word = uint
			Word    lowBitLength = cast(uint)(bitlen);
			Word    hiBitLength = cast(uint)(bitlen >>> 32);

		} else {
			adjustByteCounts();

			
			// Word = ulong
			Word    lowBitLength = byteCount1 << 3;
			Word    hiBitLength = byteCount2;
		}

		//
		// add the pad bytes.
		//
		put(128);
		
		while (xBufOff != 0)
		{
			put(0);
		}
		
		//processLength(bitLength);

		processLength(lowBitLength, hiBitLength);
		
		processBlock();
	}

	pure nothrow @nogc {

		// SHA functions

		static if(bitLength == 256) {
			/* SHA-256 functions */
			uint Ch(uint x, uint y, uint z) 
			{
				return (x & y) ^ ((~x) & z);
			}
			
			uint Maj(uint x, uint y, uint z) 
			{
				return (x & y) ^ (x & z) ^ (y & z);
			}
			
			uint Sum0(uint x) 
			{
				return ror(x,2) ^ ror(x,13) ^ ror(x,22);
			}
			
			uint Sum1(uint x) 
			{
				return ror(x,6) ^ ror(x,11) ^ ror(x,25);
			}
			
			uint Theta0(uint x) 
			{
				return ror(x,7) ^ ror(x,18) ^ (x >>> 3);
			}
			
			uint Theta1(uint x) 
			{
				return ror(x,17) ^ ror(x,19) ^ (x >>> 10);
			}

			alias Theta0 Sigma0;
			alias Theta1 Sigma1;
		} else {

			/* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */

			ulong Ch(ulong x, ulong y, ulong z)
			{
				return ((x & y) ^ ((~x) & z));
			}
			
			ulong Maj(ulong x, ulong y, ulong z)
			{
				return ((x & y) ^ (x & z) ^ (y & z));
			}
			
			ulong Sum0(ulong x)
			{
				return ((x << 36)|(x >>> 28)) ^ ((x << 30)|(x >>> 34)) ^ ((x << 25)|(x >>> 39));
			}
			
			ulong Sum1(ulong x)
			{
				return ((x << 50)|(x >>> 14)) ^ ((x << 46)|(x >>> 18)) ^ ((x << 23)|(x >>> 41));
			}
			
			ulong Sigma0(ulong x)
			{
				return ((x << 63)|(x >>> 1)) ^ ((x << 56)|(x >>> 8)) ^ (x >>> 7);
			}
			
			ulong Sigma1(ulong x)
			{
				return ((x << 45)|(x >>> 19)) ^ ((x << 3)|(x >>> 61)) ^ (x >>> 6);
			}
		}

	}

	static if(bitLength > 256) {
		/// adjust the byte counts so that byteCount2 represents the
		/// upper long (less 3 bits) word of the byte count.
		
		void adjustByteCounts() nothrow @nogc
		{
			if (byteCount1 > 0x1fffffffffffffffL)
			{
				byteCount2 += (byteCount1 >>> 61);
				byteCount1 &= 0x1fffffffffffffffL;
			}
		}
	}

	// constants

	static if(bitLength == 256) {
		/* SHA-256 Constants
		 * (represent the first 32 bits of the fractional parts of the
		 * cube roots of the first sixty-four prime numbers)
		 */
		enum uint[64] K = [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		];

		public enum blockSize = 64;

		uint[64]	X;
	} else {

		/* SHA-384 and SHA-512 Constants
		 * (represent the first 64 bits of the fractional parts of the
		 * cube roots of the first sixty-four prime numbers)
		 */
		enum ulong[80] K = [
			0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
			0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
			0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
			0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
			0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
			0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
			0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
			0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
			0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
			0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
			0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
			0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
			0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
			0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
			0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
			0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
			0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
			0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
			0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
			0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
		];

		public enum blockSize = 128;

		ulong    byteCount2;

		ulong[80]  X;
	}

	Word
		H1 = initH1,
		H2 = initH2,
		H3 = initH3,
		H4 = initH4,
		H5 = initH5,
		H6 = initH6,
		H7 = initH7,
		H8 = initH8;

	// define initial values for H1 - H8
	static if(bitLength == 256) {
		enum Word
			initH1 = 0x6a09e667,
			initH2 = 0xbb67ae85,
			initH3 = 0x3c6ef372,
			initH4 = 0xa54ff53a,
			initH5 = 0x510e527f,
			initH6 = 0x9b05688c,
			initH7 = 0x1f83d9ab,
			initH8 = 0x5be0cd19;
	} else static if(bitLength == 384) {
		enum Word
			initH1 = 0xcbbb9d5dc1059ed8,
			initH2 = 0x629a292a367cd507,
			initH3 = 0x9159015a3070dd17,
			initH4 = 0x152fecd8f70e5939,
			initH5 = 0x67332667ffc00b31,
			initH6 = 0x8eb44a8768581511,
			initH7 = 0xdb0c2e0d64f98fa7,
			initH8 = 0x47b5481dbefa4fa4;
	} else static if(bitLength == 512) {
		enum Word
			initH1 = 0x6a09e667f3bcc908,
			initH2 = 0xbb67ae8584caa73b,
			initH3 = 0x3c6ef372fe94f82b,
			initH4 = 0xa54ff53a5f1d36f1,
			initH5 = 0x510e527fade682d1,
			initH6 = 0x9b05688c2b3e6c1f,
			initH7 = 0x1f83d9abfb41bd6b,
			initH8 = 0x5be0cd19137e2179;
	} else {
		static assert(false, "invalid bitlength");
	}

	ulong    byteCount1;

	ubyte[Word.sizeof]  xBuf;
	size_t     			xBufOff;
	size_t				xOff;
}


/// testing SHA256 algorithm
unittest {
	
	immutable string[] plaintexts = [
		x"",
		x"",	// twice the same to test start()
		x"616263",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
		
	];
	
	immutable string[] hexHashes = [
		x"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		x"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		x"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		x"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
	];

	testDigest(new SHA256Digest, plaintexts, hexHashes);
}

/// testing SHA384 algorithm
unittest {

	immutable string[] plaintexts = [
		x"",
		x"",	// twice the same to test start()
		x"616263",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		
	];
	
	immutable string[] hexHashes = [
		x"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		x"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		x"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		x"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
	];

	testDigest(new SHA384Digest, plaintexts, hexHashes);
}


/// testing SHA512 algorithm
unittest {

	immutable string[] plaintexts = [
		x"",
		x"",	// twice the same to test start()
		x"616263",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
	];
	
	immutable string[] hexHashes = [
		x"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		x"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		x"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		x"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
	];

	
	testDigest(new SHA512Digest, plaintexts, hexHashes);
}
