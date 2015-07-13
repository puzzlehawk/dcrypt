module dcrypt.crypto.digests.sha1;

import dcrypt.crypto.digests.generaldigest;
import dcrypt.util.pack;

/**
 * implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349.
 *
 * It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
 * is the "endianness" of the word processing!
 */
@safe
public class SHA1Digest: GeneralDigest
{

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
	
public:
	/**
	 * Standard constructor
	 */
	this() nothrow
	{
		reset();
	}

	@property
	override string name() pure nothrow @nogc
	{
		return "SHA-1";
	}

	override uint getDigestSize() nothrow @nogc
	{
		return digestLength;
	}

	override uint doFinal(ubyte[] output) nothrow @nogc
	{
		finish();

		// pack the integers into a byte array
		//toBigEndian!uint([H1,H2,H3,H4,H5], output);

		toBigEndian!uint(H1, output[0..4]);
		toBigEndian!uint(H2, output[4..8]);
		toBigEndian!uint(H3, output[8..12]);
		toBigEndian!uint(H4, output[12..16]);
		toBigEndian!uint(H5, output[16..20]);

		reset();

		return 20;
	}

	/**
	 * reset the chaining variables
	 */
	override void reset() nothrow @nogc
	{
		super.reset();

		H1 = 0x67452301;
		H2 = 0xefcdab89;
		H3 = 0x98badcfe;
		H4 = 0x10325476;
		H5 = 0xc3d2e1f0;

		xOff = 0;
		X[] = 0;
	}
	
	protected override SHA1Digest dupImpl() nothrow {
		SHA1Digest clone = new SHA1Digest();
		clone.H1 = H1;
		clone.H2 = H2;
		clone.H3 = H3;
		clone.H4 = H4;
		clone.H5 = H5;
		clone.X = X;
		clone.xOff = xOff;
		return clone;
	}
	
	protected override void processWord(in ubyte[]  input) nothrow @nogc
	{
		// Note: Inlined for performance
		//        X[xOff] = bigEndianToInt(in, inOff);
		uint n = input[0] << 24;
		n |= input[1] << 16;
		n |= input[2] << 8;
		n |= input[3];
		X[xOff] = n;

		if (++xOff == 16)
		{
			processBlock();
		}
	}

	protected override void processLength(ulong bitLength) nothrow @nogc
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
		enum uint    Y1 = 0x5a827999;
		enum uint    Y2 = 0x6ed9eba1;
		enum uint    Y3 = 0x8f1bbcdc;
		enum uint    Y4 = 0xca62c1d6;
	}

	enum digestLength = 20;

	uint     H1, H2, H3, H4, H5;

	uint[80]   X;
	uint     xOff;
	

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

	protected override void processBlock() nothrow @nogc
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
		for (uint j = 0; j <= 3; j++)
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



