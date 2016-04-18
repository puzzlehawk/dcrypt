module dcrypt.digests.sha1;

import dcrypt.digest;
import dcrypt.bitmanip;

unittest {
	// test vectors from http://www.di-mgt.com.au/sha_testvectors.html
		
	immutable string[] plaintexts = [
		x"616263",
		x"",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
	];
	
	immutable string[] hashes = [
		x"a9993e364706816aba3e25717850c26c9cd0d89d",
		x"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		x"a49b2446a02c645bf419f995b67091253a04a259"
	];
	
	testDigest(new SHA1Digest(), plaintexts, hashes);
}

alias WrapperDigest!SHA1 SHA1Digest;

static assert(isDigest!SHA1);

/**
 * implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349.
 *
 * It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
 * is the "endianness" of the word processing!
 */
@safe
public struct SHA1
{

public:

	enum name = "SHA1";
	enum digestLength = 20;
	enum blockSize = 64;

	void put(in ubyte[] input...) nothrow @nogc
	{
		uint inOff = 0;
		size_t len = input.length;
		//
		// fill the current word
		//
		while ((xBufOff != 0) && (len > 0))
		{
			putSingleByte(input[inOff]);
			
			inOff++;
			len--;
		}
		
		//
		// process whole words.
		//
		while (len > xBuf.length)
		{
			processWord(input[inOff .. inOff + 4]);
			
			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}
		
		//
		// load in the remainder.
		//
		while (len > 0)
		{
			putSingleByte(input[inOff]);
			
			inOff++;
			len--;
		}
	}

	/// Returns: The final hash value.
	ubyte[digestLength] finish() nothrow @nogc
	{
		ubyte[digestLength] output;
		immutable size_t bitLen = byteCount * 8;
		// add the pad bytes.
		put(128);
		while (xBufOff != 0)
		{
			put(0);
		}
		processLength(bitLen);
		processBlock();

		// pack the integers into a byte array
		//toBigEndian!uint([H1,H2,H3,H4,H5], output);

		toBigEndian!uint(H1, output[0..4]);
		toBigEndian!uint(H2, output[4..8]);
		toBigEndian!uint(H3, output[8..12]);
		toBigEndian!uint(H4, output[12..16]);
		toBigEndian!uint(H5, output[16..20]);

		start();

		return output;
	}

	/// Reset SHA1.
	void start() nothrow @nogc
	{
		H1 = H10;
		H2 = H20;
		H3 = H30;
		H4 = H40;
		H5 = H50;

		xOff = 0;
		X[] = 0;

		byteCount = 0;
		
		xBufOff = 0;
		xBuf[] = 0;
	}

	private void putSingleByte(ubyte input) nothrow @nogc
	{
		xBuf[xBufOff++] = input;
		
		if (xBufOff == xBuf.length)
		{
			processWord(xBuf);
			xBufOff = 0;
		}
		
		byteCount++;
	}

	private void processWord(in ubyte[]  input) nothrow @nogc
	in {
		assert(input.length == 4);
	} body {
		X[xOff] = fromBigEndian!uint(input);

		if (++xOff == 16)
		{
			processBlock();
		}
	}

	private void processLength(ulong bitLength) nothrow @nogc
	{
		if (xOff > 14)
		{
			processBlock();
		}

		X[14] = cast(uint)(bitLength >>> 32);
		X[15] = cast(uint) bitLength;
	}

private:
	//
	// Additive constants
	//
	static {
		enum uint Y1 = 0x5a827999;
		enum uint Y2 = 0x6ed9eba1;
		enum uint Y3 = 0x8f1bbcdc;
		enum uint Y4 = 0xca62c1d6;

		enum uint H10 = 0x67452301;
		enum uint H20 = 0xefcdab89;
		enum uint H30 = 0x98badcfe;
		enum uint H40 = 0x10325476;
		enum uint H50 = 0xc3d2e1f0;
	}

	uint     H1 = H10, H2 = H20, H3 = H30, H4 = H40, H5 = H50;

	uint[80]   X;
	uint     xOff;

	ubyte[4]  xBuf;
	uint     xBufOff;
	size_t    byteCount;
	

	uint f(uint u, uint v, uint w) pure nothrow @nogc
	{
		return ((u & v) | ((~u) & w));
	}

	uint g(uint u, uint v, uint w)  pure nothrow @nogc
	{
		return ((u & v) | (u & w) | (v & w));
	}

	uint h(uint u, uint v, uint w) pure nothrow @nogc
	{
		return (u ^ v ^ w);
	}

	private void processBlock() nothrow @nogc
	{
		//
		// expand 16 word block into 80 word block.
		//
		foreach (uint i; 16 .. 80)
		{
			uint t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
			X[i] = t << 1 | t >>> 31;
		}

		//
		// set up working variables.
		//
		uint     A = H1;
		uint     B = H2;
		uint     C = H3;
		uint     D = H4;
		uint     E = H5;

		//
		// round 1
		//
		uint idx = 0;

		for (uint j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + f(B, C, D) + X[idx++] + Y1;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + f(A, B, C) + X[idx++] + Y1;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + f(E, A, B) + X[idx++] + Y1;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + f(D, E, A) + X[idx++] + Y1;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + f(C, D, E) + X[idx++] + Y1;
			C = C << 30 | C >>> 2;
		}

		//
		// round 2
		//
		for (uint j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y2;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y2;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y2;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y2;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y2;
			C = C << 30 | C >>> 2;
		}

		//
		// round 3
		//
		for (uint j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + g(B, C, D) + X[idx++] + Y3;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + g(A, B, C) + X[idx++] + Y3;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + g(E, A, B) + X[idx++] + Y3;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + g(D, E, A) + X[idx++] + Y3;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + g(C, D, E) + X[idx++] + Y3;
			C = C << 30 | C >>> 2;
		}

		//
		// round 4
		//
		for (uint j = 0; j < 4; j++)
		{
			// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
			// B = rotateLeft(B, 30)
			E += (A << 5 | A >>> 27) + h(B, C, D) + X[idx++] + Y4;
			B = B << 30 | B >>> 2;

			D += (E << 5 | E >>> 27) + h(A, B, C) + X[idx++] + Y4;
			A = A << 30 | A >>> 2;

			C += (D << 5 | D >>> 27) + h(E, A, B) + X[idx++] + Y4;
			E = E << 30 | E >>> 2;

			B += (C << 5 | C >>> 27) + h(D, E, A) + X[idx++] + Y4;
			D = D << 30 | D >>> 2;

			A += (B << 5 | B >>> 27) + h(C, D, E) + X[idx++] + Y4;
			C = C << 30 | C >>> 2;
		}

		
		H1 += A;
		H2 += B;
		H3 += C;
		H4 += D;
		H5 += E;

		//
		// reset start of the buffer.
		//
		xOff = 0;
		X[] = 0;
	}
}



