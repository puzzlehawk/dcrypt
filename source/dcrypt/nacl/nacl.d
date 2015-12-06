module dcrypt.nacl.nacl;

import dcrypt.crypto.ecc.curve25519;
import dcrypt.crypto.ecc.ed25519;
import dcrypt.crypto.engines.poly1305_chacha;
import dcrypt.exceptions: InvalidCipherTextException;
import dcrypt.util: wipe;

import std.exception: enforce;

@safe

void crypto_box(ubyte[] output, in ubyte[] message, in ref ubyte[12] nonce, in ref ubyte[32] sk, in ref ubyte[32] pk) nothrow @nogc
in {
	assert(output.length == message.length + Poly1305ChaCha.macSize, "Output buffer too short. Should be message.lenght + Poly1305ChaCha.macSize.");
}
body {

	ubyte[32] s = curve25519_scalarmult(sk, pk); /// shared secret

	Poly1305ChaCha cipher;
	cipher.start(true, s, 0, nonce);
	cipher.processBytes(message, output);
	ubyte[Poly1305ChaCha.macSize] mac;
	cipher.finish(mac);
	output[$-Poly1305ChaCha.macSize..$] = mac;

	wipe(s);
}

/// Throws: Throws a InvalidCipherTextException if signature is invalid.
void crypto_box_open(ubyte[] output, in ubyte[] ciphertext, in ref ubyte[12] nonce, in ref ubyte[32] sk, in ref ubyte[32] pk)
in {
	assert(output.length == ciphertext.length - Poly1305ChaCha.macSize, "Output buffer too short. Should be message.lenght - Poly1305ChaCha.macSize.");
}
body {
	
	ubyte[32] s = curve25519_scalarmult(sk, pk); /// shared secret
	
	Poly1305ChaCha cipher;
	cipher.start(false, s, 0, nonce);
	cipher.processBytes(ciphertext, output);

	ubyte[Poly1305ChaCha.macSize] mac;
	cipher.finish(mac);

	const ubyte[] actualMac = ciphertext[$-Poly1305ChaCha.macSize..$];

	enforce(mac == actualMac, new InvalidCipherTextException("Invalid signature."));
	
	wipe(s);
}

/// Test crypto_box.
unittest {
	ubyte[12] nonce;
	ubyte[32] skA = 1;
	ubyte[32] skB = 2;
	ubyte[32] pkA = secret_to_public(skA);
	ubyte[32] pkB = secret_to_public(skB);

	ubyte[] msg = cast(ubyte[]) "Hello World!".dup;
	ubyte[] ciphertext = new ubyte[msg.length + Poly1305ChaCha.macSize];

	// wrap into box
	crypto_box(ciphertext, msg, n, skA, pkB);

	ubyte[] msg2 = new ubyte[ciphertext.length - Poly1305ChaCha.macSize];

	try {
		// unwrap
		crypto_box_open(msg2, ciphertext, n, skB, pkA);

		assert(msg2 == msg);
	} catch(InvalidCipherTextException e) {
		assert(false);
	}
}

/// Test crypto_box with altered ciphertext
unittest {
	ubyte[12] nonce;
	ubyte[32] skA = 1;
	ubyte[32] skB = 2;
	ubyte[32] pkA = secret_to_public(skA);
	ubyte[32] pkB = secret_to_public(skB);
	
	ubyte[] msg = cast(ubyte[]) "Hello World!".dup;
	ubyte[] ciphertext = new ubyte[msg.length + Poly1305ChaCha.macSize];
	
	// wrap into box
	crypto_box(ciphertext, msg, n, skA, pkB);
	
	ubyte[] msg2 = new ubyte[ciphertext.length - Poly1305ChaCha.macSize];

	// tampering the ciphertext
	ciphertext[0] ^= 1;

	bool exceptionThrown = false;
	try {
		// unwrap
		crypto_box_open(msg2, ciphertext, n, skB, pkA);
		
		assert(false);
	} catch(InvalidCipherTextException e) {
		exceptionThrown = true;
	}
	assert(exceptionThrown, "crypto_box_open did not detect modified ciphertext.");
}