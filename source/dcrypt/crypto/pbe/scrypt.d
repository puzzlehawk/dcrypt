module dcrypt.crypto.pbe.scrypt;

import std.range;
import std.parallelism;

import dcrypt.crypto.engines.salsa;
import dcrypt.crypto.digests.sha2;
import dcrypt.crypto.pbe.pbkdf2;
import dcrypt.util.pack;


/// generate a 256 bit key
unittest {
	ubyte[32] key;
	scrypt(key, cast(const(ubyte)[])"password", cast(const(ubyte)[])"salt", 123, 1, 1);
}

/// generate keys and compare them with test vectors from
/// https://www.tarsnap.com/scrypt/scrypt.pdf
unittest {

	ubyte[] key = new ubyte[64];

	key.scrypt(cast(const(ubyte)[])"",cast(const(ubyte)[])"", 16, 1, 1);

	assert(key == x"
77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06");

	scrypt(key, cast(const(ubyte)[])"password",cast(const(ubyte)[])"NaCl", 1024, 8, 16);

	assert(key == x"
fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40");

	scrypt(key, cast(const(ubyte)[])"pleaseletmein",cast(const(ubyte)[])"SodiumChloride",
		16384, 8, 1);
	
	assert(key == x"
70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87");

	//// !! this consumes 1GB of ram
	//	scrypt(key, cast(const(ubyte)[])"pleaseletmein",cast(const(ubyte)[])"SodiumChloride",
	//		1048576, 8, 1);
	//	
	//	assert(key == cast(const(ubyte)[])x"
	//21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
	//ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
	//8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
	//37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4");

}

@safe
{

	// TODO Validate arguments
	///
	/// implementation of https://www.tarsnap.com/scrypt/scrypt.pdf
	/// 		
	/// Params:
	/// output = Output buffer for derived key. Buffer length defines the key length. Lenght < 2^32.
	/// pass = password
	/// salt = cryptographic salt
	/// N = CPU/memory cost parameter
	/// r = block size parameter
	/// p = parallelization parameter. p <= (2^32-1)*hashLen/MFLen
	/// 
	@safe
	public void scrypt(ubyte[] output, in ubyte[] pass, in ubyte[] salt, in uint N, in uint r, in uint p)
	in {
		assert(p <= ((1L<<32)-1)*32/(r * 128), "parallelization parameter p too large");
		assert(output.length < 1L<<32, "dkLen must be smaller than 2^32");
	}
	body {

		MFCrypt(output, pass, salt, N, r, p);
		
	}

private:

	// TODO Validate arguments
	///
	/// implementation of https://www.tarsnap.com/scrypt/scrypt.pdf
	/// 		
	/// Params:
	/// output = output buffer.
	/// pass = password
	/// salt = cryptographic salt
	/// N = CPU/memory cost parameter
	/// r = block size parameter
	/// p = parallelization parameter. p <= (2^32-1)*hashLen/MFLen
	/// dkLen = length in octets of derived key. dkLen < 2^32
	/// 
	/// Returns: Derived key.
	/// 
	@safe
	void MFCrypt(ubyte[] output, in ubyte[] pass, in ubyte[] salt, uint N, uint r, uint p)
	in {
		assert(p <= ((1L<<32)-1)*32/(r * 128), "parallelization parameter p too large");
		assert(output.length < 1L<<32, "dkLen must be smaller than 2^32");
	}
	body {
		uint MFLenBytes = r * 128;
		ubyte[] bytes = new ubyte[p * MFLenBytes];
		SingleIterationPBKDF2(pass, salt, bytes);
		
		size_t BLen = bytes.length >>> 2;
		uint[] B = new uint[BLen];
		
		// wipe data on exit
		scope (exit) {
			bytes[] = 0;
			B[] = 0;
		}
		
		fromLittleEndian(bytes, B);
		
		uint MFLenWords = MFLenBytes >>> 2;
		
		
		if(p > 1) {
			// do parallel computations
			parallSMix(B, MFLenWords, N, r);
		} else {
			// don't use parallelism
			foreach(chunk; chunks(B, MFLenWords)) {
				SMix(chunk, N, r);
			}
		}

		toLittleEndian(B, bytes);
		
		SingleIterationPBKDF2(pass, bytes, output);
	}

	@trusted
	void parallSMix(uint[] B, uint MFLenWords, uint N, uint r) {
		// do parallel computations
		foreach(chunk; parallel(chunks(B, MFLenWords))) {
			SMix(chunk, N, r);
		}
	}

	void SingleIterationPBKDF2(in ubyte[] P, in ubyte[] S, ubyte[] output)
	{
		pbkdf2!SHA256(output, P, S, 1);
	}
	
	void SMix(uint[] B, in uint N, in uint r) pure nothrow
	{
		uint BCount = r * 32;

		uint[16] blockX1;
		uint[16] blockX2;
		uint[] blockY = new uint[BCount];
		
		uint[] X = new uint[BCount];
		uint[][] V = new uint[][N];

		// wipe data on exit
		scope (exit) {
			foreach(ref v;V) {
				v[] = 0;
			}
			X[] = 0;
			blockX1[] = 0;
			blockX2[] = 0;
			blockY[] = 0;
		}

		X[] = B[0..BCount];

		for (uint i = 0; i < N; ++i)
		{
			V[i] = X.dup;
			BlockMix(X, blockX1, blockX2, blockY, r);
		}
		
		uint mask = N - 1;
		for (uint i = 0; i < N; ++i)
		{
			uint j = X[BCount - 16] & mask;
			X[] ^= V[j][];
			BlockMix(X, blockX1, blockX2, blockY, r);
		}

		B[0..BCount] = X[];
		
	}
	
	void BlockMix(uint[] B, uint[] X1, uint[] X2, uint[] Y, int r) pure nothrow @nogc
	body {

		X1[0..16] = B[$-16..$];
		
		size_t BOff = 0, YOff = 0, halfLen = B.length >>> 1;
		
		for (int i = 2 * r; i > 0; --i)
		{
			X2[] = B[BOff..$] ^ X1[];

			salsaCore!8(X2, X1);

			Y[YOff..YOff+16] = X1[0..16];
			
			YOff = halfLen + BOff - YOff;
			BOff += 16;
		}

		B[0..Y.length] = Y[];
	}
}