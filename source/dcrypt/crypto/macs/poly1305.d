module dcrypt.crypto.macs.poly1305;

import dcrypt.crypto.macs.mac;
import dcrypt.crypto.blockcipher;
import dcrypt.util.pack;

static assert(isMAC!(Poly1305!void), "Poly1305!void is not a valid mac.");

private {
	enum ubyte rMaskLow2 = 0xFC;
	enum ubyte rMaskHigh4 = 0x0F;
}

@safe nothrow @nogc
public struct Poly1305(Cipher) if (isBlockCipher!Cipher || is(Cipher == void)) {

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

	/**
	 * Initialises the Poly1305 MAC.
	 * 
	 * @param params if used with a block cipher, then a {@link ParametersWithIV} containing a 128 bit
	 *        nonce and a {@link KeyParameter} with a 256 bit key complying to the
	 *        {@link Poly1305KeyGenerator Poly1305 key format}, otherwise just the
	 *        {@link KeyParameter}.
	 */
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

		ubyte[16] s, r;
		s[] = key[0..16];
		r[] = key[16..32];
		clamp(r[]);
		
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
		doFinal(mac);
		return mac;
	}

	public uint doFinal(ubyte[] output)
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
		return blockSize;
	}

	public void reset()
	{
		currentBlockOffset = 0;
		
		h0 = h1 = h2 = h3 = h4 = 0;
	}

	private static long mul32x32_64(int i1, int i2) pure
	{
		return (cast(long)i1) * i2;
	}
}

/// Check if r has right format.
@safe
private bool checkKey(in ubyte[] key) pure nothrow @nogc {
	assert(key.length == 16, "r must be 128 bits.");

	return 
		checkMask(key[3], rMaskHigh4) &&
			checkMask(key[7], rMaskHigh4) &&
			checkMask(key[11], rMaskHigh4) &&
			checkMask(key[15], rMaskHigh4) &&
			
			checkMask(key[4], rMaskLow2) &&
			checkMask(key[8], rMaskLow2) &&
			checkMask(key[12], rMaskLow2);
}

@safe
private bool checkMask(in ubyte b, in ubyte mask) pure nothrow @nogc
{
	return (b & (~mask)) == 0;
}

/// Clears bits in key.
@safe
private void clamp(ubyte[] key) nothrow @nogc
in {
	assert(key.length == 16);
}
body {
	/*
	 * r[3], r[7], r[11], r[15] have top four bits clear (i.e., are {0, 1, . . . , 15})
	 */
	key[3] &= rMaskHigh4;
	key[7] &= rMaskHigh4;
	key[11] &= rMaskHigh4;
	key[15] &= rMaskHigh4;
	
	/*
	 * r[4], r[8], r[12] have bottom two bits clear (i.e., are in {0, 4, 8, . . . , 252}).
	 */
	key[4] &= rMaskLow2;
	key[8] &= rMaskLow2;
	key[12] &= rMaskLow2;
}

/// Raw Poly1305
/// onetimeauth.c from nacl-20110221
unittest {

	poly1305Test!(Poly1305!void)(
		x"2539121d8e234e652d651fa4c8cff880eea6a7251c1e72916d11c2cb214d3c25",
		null,
		x"8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a
                        c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738
                        b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da
                        99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
		x"f3ffc7703f9400e52a7dfb4b3d3305d9"
		);
	
}

unittest {
	import dcrypt.crypto.engines.aes;

	poly1305Test!(Poly1305!AES)(
		x"0000000000000000000000000000000000000000000000000000000000000000",
		x"00000000000000000000000000000000",
		x"",
		x"66e94bd4ef8a2c3b884cfa59ca342b2e"
		);
	
}

unittest {
	import dcrypt.crypto.engines.aes;
	
	poly1305Test!(Poly1305!AES)(
		x"f795bd4a52e29ed713d313fa20e98dbcf795bd0a50e29e0710d3130a20e98d0c",
		x"917cf69ebd68b2ec9b9fe9a3eadda692",
		x"66f7",
		x"5ca585c75e8f8f025e710cabc9a1508b"
		);
	
}

version(unittest) {
	// Helper function for unittests.

	private void poly1305Test(P)(string key, string iv, string data, string expectedMac) {

		alias const(ubyte[]) octets;

		P poly;
		poly.start(cast(octets) key, cast(octets) iv);
		poly.put(cast(octets) data);

		assert(poly.finish() == expectedMac, "Poly1305 failed!");
		
	}
}