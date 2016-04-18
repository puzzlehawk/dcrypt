module dcrypt.crypto.macs.poly1305;

import dcrypt.crypto.macs.mac;
import dcrypt.blockcipher.blockcipher;
import dcrypt.bitmanip;

static assert(isMAC!(Poly1305!void), "Poly1305!void is not a valid mac.");

private {
	enum ubyte rMaskLow2 = 0xFC;
	enum ubyte rMaskHigh4 = 0x0F;
}

alias Poly1305!void Poly1305Raw;

@safe nothrow @nogc
public struct Poly1305(Cipher) if ((isBlockCipher!Cipher && Cipher.blockSize == 16) || is(Cipher == void)) {

	static if(useCipher) {
		public enum name = "Poly1305-" ~ Cipher.name;
	} else {
		public enum name = "Poly1305";
	}

	public enum macSize = blockSize;

	private {
		enum useCipher = !is(Cipher == void);
		enum blockSize = 16;

		static if(useCipher) {
			Cipher cipher;
		}
		// Initialised state

		/** Polynomial key */
		int r0, r1, r2, r3, r4;

		/** Precomputed 5 * r[1..4] */
		int s1, s2, s3, s4;

		/** Encrypted nonce */
		int k0, k1, k2, k3;

		// Accumulating state

		/** Current block of buffered input */
		ubyte[blockSize] currentBlock;

		/** Current offset in input buffer */
		uint currentBlockOffset = 0;

		/** Polynomial accumulator */
		int h0, h1, h2, h3, h4;
	}

	/// Wipe sensitive data.
	~this() {
		r0 = r1 = r2 = r3 = r4 = 0;
		s1 = s2 = s3 = s4 = 0;
		k0 = k1 = k2 = k2 = 0;
		
		currentBlock[] = 0;
		h0 = h1 = h2 = h3 = h4 = 0;
	}

	/// Initializes the Poly1305 MAC.
	/// Params:
	/// key = 32 byte key.
	/// nonce = 16 byte nonce. Required if used with block cipher.
	public void start(in ubyte[] key, in ubyte[] nonce = null)
	{
		setKey(key, nonce);
		
		reset();
	}

	private void setKey(in ubyte[] key, in ubyte[] nonce)
	in {
		if(useCipher) {
			assert(nonce !is null && nonce.length == blockSize, "Poly1305 requires an 256 bit IV when used with a block cipher.");
		}

		assert(key !is null && key.length == 32, "Poly1305 requires a 32 byte key.");

	}
	body {

		ubyte[16] r, s;
		r[] = key[0..16];
		clamp(r);
		s[] = key[16..32];
		
		assert(checkKey(r), "Invalid format for r portion of Poly1305 key.");

		// Extract r portion of key

		int t0 = fromLittleEndian!int(r[0..4]);
		int t1 = fromLittleEndian!int(r[4..8]);
		int t2 = fromLittleEndian!int(r[8..12]);
		int t3 = fromLittleEndian!int(r[12..16]);
		
		r0 = t0 & 0x3ffffff; t0 >>>= 26; t0 |= t1 << 6;
		r1 = t0 & 0x3ffff03; t1 >>>= 20; t1 |= t2 << 12;
		r2 = t1 & 0x3ffc0ff; t2 >>>= 14; t2 |= t3 << 18;
		r3 = t2 & 0x3f03fff; t3 >>>= 8;
		r4 = t3 & 0x00fffff;
		
		// Precompute multipliers
		s1 = r1 * 5;
		s2 = r2 * 5;
		s3 = r3 * 5;
		s4 = r4 * 5;

		static if (useCipher)
		{
			cipher.start(true, s);
			cipher.processBlock(nonce, s);
		}
		
		k0 = fromLittleEndian!int(s[0..4]);
		k1 = fromLittleEndian!int(s[4..8]);
		k2 = fromLittleEndian!int(s[8..12]);
		k3 = fromLittleEndian!int(s[12..16]);
	}

	public void put(in ubyte[] inp...) {

		import std.algorithm: min;

		const(ubyte)[] input = inp;

		uint copied = 0;
		while (input.length > 0)
		{
			if (currentBlockOffset == blockSize)
			{
				processBlock();
				currentBlockOffset = 0;
			}

			uint toCopy = min(input.length, blockSize - currentBlockOffset);
			//System.arraycopy(in, copied + inOff, currentBlock, currentBlockOffset, toCopy);
			currentBlock[currentBlockOffset..currentBlockOffset+toCopy] = input[0..toCopy];
			input = input[toCopy..$];
			copied += toCopy;
			currentBlockOffset += toCopy;
		}
		
	}

	private void processBlock()
	{
		if (currentBlockOffset < blockSize)
		{
			currentBlock[currentBlockOffset] = 1;
			for (uint i = currentBlockOffset + 1; i < blockSize; i++)
			{
				currentBlock[i] = 0;
			}
		}

		immutable long t0 = 0xffffffffL & fromLittleEndian!int(currentBlock[0..4]);
		immutable long t1 = 0xffffffffL & fromLittleEndian!int(currentBlock[4..8]);
		immutable long t2 = 0xffffffffL & fromLittleEndian!int(currentBlock[8..12]);
		immutable long t3 = 0xffffffffL & fromLittleEndian!int(currentBlock[12..16]);
		
		h0 += t0 & 0x3ffffff;
		h1 += (((t1 << 32) | t0) >>> 26) & 0x3ffffff;
		h2 += (((t2 << 32) | t1) >>> 20) & 0x3ffffff;
		h3 += (((t3 << 32) | t2) >>> 14) & 0x3ffffff;
		h4 += (t3 >>> 8);
		
		if (currentBlockOffset == blockSize)
		{
			h4 += (1 << 24);
		}
		
		long tp0 = mul32x32_64(h0,r0) + mul32x32_64(h1,s4) + mul32x32_64(h2,s3) + mul32x32_64(h3,s2) + mul32x32_64(h4,s1);
		long tp1 = mul32x32_64(h0,r1) + mul32x32_64(h1,r0) + mul32x32_64(h2,s4) + mul32x32_64(h3,s3) + mul32x32_64(h4,s2);
		long tp2 = mul32x32_64(h0,r2) + mul32x32_64(h1,r1) + mul32x32_64(h2,r0) + mul32x32_64(h3,s4) + mul32x32_64(h4,s3);
		long tp3 = mul32x32_64(h0,r3) + mul32x32_64(h1,r2) + mul32x32_64(h2,r1) + mul32x32_64(h3,r0) + mul32x32_64(h4,s4);
		long tp4 = mul32x32_64(h0,r4) + mul32x32_64(h1,r3) + mul32x32_64(h2,r2) + mul32x32_64(h3,r1) + mul32x32_64(h4,r0);
		
		long b;
		h0 = cast(int)tp0 & 0x3ffffff; b = (tp0 >>> 26);
		tp1 += b; h1 = cast(int)tp1 & 0x3ffffff; b = ((tp1 >>> 26) & 0xffffffff);
		tp2 += b; h2 = cast(int)tp2 & 0x3ffffff; b = ((tp2 >>> 26) & 0xffffffff);
		tp3 += b; h3 = cast(int)tp3 & 0x3ffffff; b = (tp3 >>> 26);
		tp4 += b; h4 = cast(int)tp4 & 0x3ffffff; b = (tp4 >>> 26);
		h0 += b * 5;
	}

	public ubyte[macSize] finish() {
		ubyte[macSize] mac;
		finish(mac);
		return mac;
	}

	public ubyte[] finish(ubyte[] output)
	in {
		assert(output.length >= blockSize, "Output buffer is too short.");
	}
	body {
		if (currentBlockOffset > 0)
		{
			// Process padded final block
			processBlock();
		}
		
		long f0, f1, f2, f3;
		
		int b = h0 >>> 26;
		h0 = h0 & 0x3ffffff;
		h1 += b; b = h1 >>> 26; h1 = h1 & 0x3ffffff;
		h2 += b; b = h2 >>> 26; h2 = h2 & 0x3ffffff;
		h3 += b; b = h3 >>> 26; h3 = h3 & 0x3ffffff;
		h4 += b; b = h4 >>> 26; h4 = h4 & 0x3ffffff;
		h0 += b * 5;
		
		int g0, g1, g2, g3, g4;
		g0 = h0 + 5; b = g0 >>> 26; g0 &= 0x3ffffff;
		g1 = h1 + b; b = g1 >>> 26; g1 &= 0x3ffffff;
		g2 = h2 + b; b = g2 >>> 26; g2 &= 0x3ffffff;
		g3 = h3 + b; b = g3 >>> 26; g3 &= 0x3ffffff;
		g4 = h4 + b - (1 << 26);
		
		b = (g4 >>> 31) - 1;
		int nb = ~b;
		h0 = (h0 & nb) | (g0 & b);
		h1 = (h1 & nb) | (g1 & b);
		h2 = (h2 & nb) | (g2 & b);
		h3 = (h3 & nb) | (g3 & b);
		h4 = (h4 & nb) | (g4 & b);
		
		f0 = (((h0       ) | (h1 << 26)) & 0xffffffffL) + (0xffffffffL & k0);
		f1 = (((h1 >>> 6 ) | (h2 << 20)) & 0xffffffffL) + (0xffffffffL & k1);
		f2 = (((h2 >>> 12) | (h3 << 14)) & 0xffffffffL) + (0xffffffffL & k2);
		f3 = (((h3 >>> 18) | (h4 << 8 )) & 0xffffffffL) + (0xffffffffL & k3);

		toLittleEndian!int(cast(int)f0, output[0..4]);
		f1 += (f0 >>> 32);
		toLittleEndian!int(cast(int)f1, output[4..8]);
		f2 += (f1 >>> 32);
		toLittleEndian!int(cast(int)f2, output[8..12]);
		f3 += (f2 >>> 32);
		toLittleEndian!int(cast(int)f3, output[12..16]);
		
		reset();
		return output[0..blockSize];
	}

	/// Resets the internal state such that a new MAC can be computed.
	public void reset()
	{
		currentBlockOffset = 0;
		
		h0 = h1 = h2 = h3 = h4 = 0;
	}

	/// Returns: i1*i2 as long
	private long mul32x32_64(in int i1, in int i2) pure
	{
		return (cast(long)i1) * i2;
	}

	/// Check if r has right format.
	private bool checkKey(in ubyte[] key) pure {
		assert(key.length == 16, "r must be 128 bits.");

		bool checkMask(in ubyte b, in ubyte mask) pure
		{
			return (b & (~mask)) == 0;
		}

		return 
			checkMask(key[3], rMaskHigh4) &&
				checkMask(key[7], rMaskHigh4) &&
				checkMask(key[11], rMaskHigh4) &&
				checkMask(key[15], rMaskHigh4) &&
				
				checkMask(key[4], rMaskLow2) &&
				checkMask(key[8], rMaskLow2) &&
				checkMask(key[12], rMaskLow2);
	}

	/// Clears bits in key:
	/// Clears top four bits of bytes 3,7,11,15
	/// Clears bottom two bits of bytes 4,8,12
	/// 
	/// Params:
	/// key = Some bits of this key get cleared.
	private void clamp(ref ubyte[16] key)
	{
		// r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
		key[3] &= rMaskHigh4;
		key[7] &= rMaskHigh4;
		key[11] &= rMaskHigh4;
		key[15] &= rMaskHigh4;

		// r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
		key[4] &= rMaskLow2;
		key[8] &= rMaskLow2;
		key[12] &= rMaskLow2;
	}
}



// Raw Poly1305
// onetimeauth.c from nacl-20110221
unittest {

	poly1305Test!(Poly1305!void)(
		x"eea6a7251c1e72916d11c2cb214d3c25 2539121d8e234e652d651fa4c8cff880",
		null,
		x"8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a
                        c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738
                        b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da
                        99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
		x"f3ffc7703f9400e52a7dfb4b3d3305d9"
		);
	
}

unittest {
	import dcrypt.blockcipher.aes;

	poly1305Test!(Poly1305!AES)(
		x"0000000000000000000000000000000000000000000000000000000000000000",
		x"00000000000000000000000000000000",
		x"",
		x"66e94bd4ef8a2c3b884cfa59ca342b2e"
		);
	
}

unittest {
	import dcrypt.blockcipher.aes;
	
	poly1305Test!(Poly1305!AES)(
		x"f795bd0a50e29e0710d3130a20e98d0c f795bd4a52e29ed713d313fa20e98dbc",
		x"917cf69ebd68b2ec9b9fe9a3eadda692",
		x"66f7",
		x"5ca585c75e8f8f025e710cabc9a1508b"
		);
	
}

// Test vectors from RFC7539, A.3. #1
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		x"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #2
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
		null,
		longTestData0,
		x"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
		);
	
}

// Test vectors from RFC7539, A.3. #3
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		longTestData0,
		x"f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0"
		);
	
}

// Test vectors from RFC7539, A.3. #4
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
		null,
		x"
		  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
		  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
		  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
		  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
		  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
		  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
		  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
		  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
		",
		x"45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62"
		);
	
}

// Test vectors from RFC7539, A.3. #5
// If one uses 130-bit partial reduction, does the code handle the case where partially reduced final result is not fully reduced?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
		  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
		",
		x"03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #6
// What happens if addition of s overflows modulo 2^128?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
		null,
		x"
		  02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		",
		x"03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #7
// What happens if data limb is all ones and there is carry from lower limb?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
			FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
			F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
			11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		",
		x"05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #8
// What happens if final result from polynomial part is exactly 2^130-5?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
			FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
			FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
			01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
		",
		x"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #9
// What happens if final result from polynomial part is exactly 2^130-6?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
		  FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
		",
		x"FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
		);
	
}

// Test vectors from RFC7539, A.3. #10
// What happens if 5*H+L-type reduction produces 131-bit intermediate result?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
			E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
			33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
			00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
			01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		",
		x"14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00"
		);
	
}

// Test vectors from RFC7539, A.3. #11
// What happens if 5*H+L-type reduction produces131-bit final result?
unittest {
	
	poly1305Test!(Poly1305!void)(
		x"01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		null,
		x"
			E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
			33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
			00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		",
		x"13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		);
	
}

version(unittest) {
	// Helper function for unittests.
private:

	void poly1305Test(P)(string key, string iv, string data, string expectedMac) {

		alias const(ubyte[]) octets;

		P poly;
		poly.start(cast(octets) key, cast(octets) iv);
		poly.put(cast(octets) data);

		assert(poly.finish() == expectedMac, "Poly1305 failed!");
		
	}

	enum longTestData0 = x"
		  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
		  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
		  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
		  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
		  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
		  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
		  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
		  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
		  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
		  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
		  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
		  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
		  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
		  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
		  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
		  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
		  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
		  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
		  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
		  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
		  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
		  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
		  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
		  73 73 65 64 20 74 6f
		";
}