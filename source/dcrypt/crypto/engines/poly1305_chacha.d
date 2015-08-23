module dcrypt.crypto.engines.poly1305_chacha;

/// Implementation of the Poly1305-ChaCha20 AEAD cipher.
/// 
/// Standard: RFC 7539

import dcrypt.crypto.modes.aead;
import dcrypt.crypto.engines.chacha;
import dcrypt.crypto.macs.poly1305;
import dcrypt.util.pack;

// TODO: adapt to AEAD API
static assert(isAEADCipher!Poly1305ChaCha, Poly1305ChaCha.name~" is not a valid AEAD cipher.");

@safe nothrow @nogc
public struct Poly1305ChaCha {

	public enum name = "ChaCha20-Poly1305";
	public enum macSize = 16;

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

	public size_t processBytes(in ubyte[] input, ubyte[] output)
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

		return input.length;
	}

	/// Returns: The MAC value of the processed AAD and cipher data.
	/// 
	/// Note: Must be reinitialized with `start()` after calling finish
	public size_t finish(ubyte[] mac, ubyte[] output = null)
	in {
		assert(mac.length == 16, "MAC buffer must be 16 bytes.");
	} body {

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

		
		mac[0..16] = poly.finish();

		initialized = false;
		return 0;
	}

	/// Get the minimal size of the output buffer for an input of length `len`.
	/// Since this is a stream cipher, input and output are equal in length.
	public size_t getUpdateOutputSize(in size_t len) pure {
		return len;
	}

	/// Get the minimal buffer size needed for a call to `finish()`.
	/// Since this is a stream cipher all data gets processed instantaneously.
	/// Returns: 0
	public size_t getOutputSize(in size_t len) pure {
		return 0;
	}

private:

	/// Pad `poly` by adding as much zero bytes to make `len` a integral multiple of 16.
	void pad16(size_t len) {
		if(len % 16 != 0) {
			ubyte[16] zeros = 0;
			poly.put(zeros[0..16-len%16]);
		}
	}

	static ubyte[32] poly1305KeyGen(in ref ubyte[32] key, in ref ubyte[12] nonce) pure {
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

	enum string expectedCipherText = x"
		d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
		a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
		3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
		1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 
		92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 
		fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
		3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 
		61 16";

	enum string aad = x"50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7";

	ubyte[32] key = cast(const ubyte[]) x"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f";
	ubyte[8] iv = cast(const ubyte[]) x"40 41 42 43 44 45 46 47";
	uint senderID = 7;

	pcc.start(true, key, senderID, iv);

	ubyte[plaintext.length] ciphertext;

	pcc.processAADBytes(cast(const ubyte[]) aad[]);
	pcc.processBytes(cast(const ubyte[]) plaintext[], ciphertext[]);

	ubyte[16] tag;
	pcc.finish(tag);

	assert(ciphertext == expectedCipherText, Poly1305ChaCha.name~" produced wrong ciphertext.");
	assert(tag == x"1ae10b594f09e26a7e902ecbd0600691", Poly1305ChaCha.name~" produced wrong tag.");

}