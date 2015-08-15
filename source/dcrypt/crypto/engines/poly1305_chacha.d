module dcrypt.crypto.engines.poly1305_chacha;

import dcrypt.crypto.modes.aead;
import dcrypt.crypto.engines.chacha;
import dcrypt.crypto.macs.poly1305;
import dcrypt.util.pack;

@safe nothrow @nogc
public struct Poly1305ChaCha {

	public enum name = "ChaCha20-Poly1305";

	private {
		Poly1305Raw poly;
		ChaCha20 chaCha;

		ulong aadLength, cipherTextLength;

		bool forEncryption;
		bool aadMode;			/// true: AAD can be processed. false: encrypting or decrypting, can't process AAD anymore.
		bool initialized;

		version (unittest) {
			ubyte[32] polyKey;
		}
	}

	private static ubyte[32] poly1305KeyGen(in ref ubyte[32] key, in ref ubyte[12] nonce) pure {
		uint[16] block;

		ChaCha20.initState(block, key, 0, nonce);
		ChaCha20.chaCha20Block(block, block);

		ubyte[32] poly1305Key;
		toLittleEndian(block[0..8], poly1305Key[]);
		return poly1305Key;
	}

	// Test poly1305KeyGen
	// Test vectors from RFC7539, section 2.6.2
	unittest {
		ubyte[32] key = cast(const ubyte[]) x"808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f";
		ubyte[12] nonce = cast(const ubyte[]) x"000000000001020304050607";

		ubyte[32] expectedPoly1305Key = cast(const ubyte[]) x"8ad5a08b905f81cc815040274ab29471 a833b637e3fd0da508dbb8e2fdd1a646";

		ubyte[32] poly1305Key = poly1305KeyGen(key, nonce);

		assert(poly1305Key == expectedPoly1305Key, "poly1305KeyGen() failed.");
	}

	///
	/// Params:
	/// forEncryption = Not relevant.
	/// key = Secret key. 32 bytes.
	/// constant = Something like an IV (sender ID, ...)
	/// nonce = Unique per secret key. 8 bytes.
	public void start(bool forEncryption, in ubyte[] key, in uint constant, in ubyte[] nonce)
	in {
		assert(key.length == 32, name~" requires a 256 bit key.");
		assert(nonce.length == 8, name~" requires a 64 bit nonce.");
	} body {
		ubyte[12] _nonce;
		toLittleEndian(constant, _nonce[0..4]);
		_nonce[4..12] = nonce;

		start(forEncryption, key, _nonce);
	}

	///
	/// Params:
	/// forEncryption = Not relevant.
	/// key = Secret key. 32 bytes.
	/// nonce = Unique per secret key. 12 bytes.
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] nonce)
	in {
		assert(key.length == 32, "ChaCha20 requires a 256 bit key.");
		assert(nonce.length == 12, "ChaCha20 requires a 96 bit nonce.");
	} body {
		this.forEncryption = forEncryption;

		immutable ubyte[32] _key = key;
		immutable ubyte[12] _nonce = nonce;

		version(unittest) { polyKey = poly1305KeyGen(_key, _nonce); }

		poly.start(poly1305KeyGen(_key, _nonce));
		chaCha.start(forEncryption, key, nonce);

		aadMode = true;
		aadLength = cipherTextLength = 0;

		initialized = true;
	}

	public void processAADBytes(in ubyte[] aad)
	in {
		assert(initialized, name~" not initialized.");
		assert(aadMode, "Must process AAD before cipher data!");
	} body {
		poly.put(aad);
		aadLength += aad.length;
	}

	public ubyte[] processBytes(in ubyte[] input, ubyte[] output)
	in {
		assert(initialized, name~" not initialized.");
		assert(output.length >= input.length, "Output buffer too small.");
	} body {

		if(aadMode) {
			aadMode = false; // Can't process AAD after this.

			// pad AAD
			pad16(aadLength);
		}

		chaCha.processBytes(input, output);
		poly.put(output);

		cipherTextLength += input.length;

		return output[0..input.length];
	}

	/// Returns: The MAC value of the processed AAD and cipher data.
	/// 
	/// Note: Must be reinitialized with `start()` after calling finish
	public ubyte[16] finish(ubyte[] output = null) {

		if(aadMode) {
			pad16(aadLength);
		} else {
			pad16(cipherTextLength);
		}

		ubyte[8] buf;

		// Mac the lengths.
		// Note: Inconsistency in RFC7539: section 2.8.1 says, that lengths get encoded as 4 byte little endian,
		// but in the test vectors they get encoded as 8 byte little endian.
		// 
		toLittleEndian!ulong(aadLength, buf);
		poly.put(buf[]);
		toLittleEndian!ulong(cipherTextLength, buf);
		poly.put(buf[]);

		
		ubyte[16] tag = poly.finish();

		initialized = false;
		return tag;
	}

	/// Pad `poly` by adding as much zero bytes to make `len` a integral multiple of 16.
	private void pad16(size_t len) {
		if(len % 16 != 0) {
			ubyte[16] zeros = 0;
			poly.put(zeros[0..16-len%16]);
		}
	}
}

// Test vectors from RFC7539, section 2.8.2
unittest {

	Poly1305ChaCha pcc;

	enum string plaintext = x"
		4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
		65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
		73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
		6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
		6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
		74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
		63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
		74 2e";

	enum string aad = x"50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7";

	ubyte[32] key = cast(const ubyte[]) x"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f";
	ubyte[8] iv = cast(const ubyte[]) x"40 41 42 43 44 45 46 47";
	uint senderID = 7;

	pcc.start(true, key, senderID, iv);

	ubyte[plaintext.length] ciphertext;

	pcc.processAADBytes(cast(const ubyte[]) aad[]);
	pcc.processBytes(cast(const ubyte[]) plaintext[], ciphertext[]);

	ubyte[16] tag = pcc.finish();

	assert(tag == x"1ae10b594f09e26a7e902ecbd0600691", Poly1305ChaCha.name~" produced wrong tag.");

}