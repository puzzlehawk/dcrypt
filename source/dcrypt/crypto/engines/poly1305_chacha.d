module dcrypt.crypto.engines.poly1305_chacha;

import dcrypt.crypto.modes.aead;
import dcrypt.crypto.engines.chacha;
import dcrypt.crypto.macs.poly1305;
import dcrypt.util.pack;

@safe nothrow @nogc
public struct Poly1305ChaCha {

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
		ubyte[12] nonce = cast(const ubyte[]) x"00 00 00 00 00 01 02 03 04 05 06 07";

		ubyte[32] expectedPoly1305Key = cast(const ubyte[]) x"8ad5a08b905f81cc815040274ab29471 a833b637e3fd0da508dbb8e2fdd1a646";

		ubyte[32] poly1305Key = poly1305KeyGen(key, nonce);

		assert(poly1305Key == expectedPoly1305Key, "poly1305KeyGen() failed.");
	}



}