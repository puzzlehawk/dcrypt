module dcrypt.nacl.secretbox;

/// High level API for symmetric authenticated encryption.
/// Compatible to http://nacl.cr.yp.to/secretbox.html.

import dcrypt.crypto.macs.poly1305;
import dcrypt.streamcipher.salsa;
import dcrypt.util;
import dcrypt.exceptions;

private {
	enum tag_bytes = 16;
	enum key_bytes = 32;
	enum nonce_bytes = 24;

	alias XSalsa20 StreamCipher;
	alias Poly1305Raw Auth;
}

/// High-level symmetric authenticated encryption.
/// 
/// Params:
/// msg = Plaintext message.
/// nonce = 24 bytes used once per key.
/// key = Secret shared key. 32 bytes.
///
/// Returns:
/// Authentication tag and encrypted message. The output is 16 bytes longer than the input.
public ubyte[] secretbox(in ubyte[] msg, in ubyte[] nonce, in ubyte[] key) @safe nothrow
in {
	assert(key.length == key_bytes, "Invalid key length.");
	assert(nonce.length == nonce_bytes, "Invalid nonce length.");
} body {

	StreamCipher streamcipher;
	streamcipher.start(true, key, nonce);

	ubyte[32] auth_key = 0;
	scope(exit) {
		wipe(auth_key);
	}

	// Derive authentication key by encrypting 32 zeros.
	streamcipher.processBytes(auth_key, auth_key);

	Poly1305Raw auth;
	auth.start(auth_key);

	ubyte[] output = new ubyte[tag_bytes + msg.length];

	ubyte[] ciphertext = streamcipher.processBytes(msg, output[tag_bytes .. $]);
	auth.put(ciphertext);
	output[0..tag_bytes] = auth.finish();

	return output;
}

/// High-level symmetric authenticated decryption.
/// 
/// Params:
/// boxed = Ciphertext and authentication tag as created by `secretbox()`.
/// nonce = 24 bytes used once per key.
/// key = Secret shared key. 32 bytes.
///
/// Returns: Returns the plaintext if the authentication tag is correct.
/// 
/// Throws: Throws an exception if the authentication tag is invalid.
public ubyte[] secretbox_open(in ubyte[] boxed, in ubyte[] nonce,  in ubyte[] key) @safe
in {
	assert(key.length == key_bytes, "Invalid key length.");
	assert(nonce.length == nonce_bytes, "Invalid nonce length.");
	assert(boxed.length >= tag_bytes, "Message too short. Can't even contain a 16 byte tag.");
} body {
	
	StreamCipher streamcipher;
	streamcipher.start(false, key, nonce);
	
	ubyte[32] auth_key = 0;
	
	// Derive authentication key by encrypting 32 zeros.
	streamcipher.processBytes(auth_key, auth_key);
	
	Poly1305Raw auth;
	auth.start(auth_key);

	const ubyte[] ciphertext = boxed[tag_bytes..$];

	auth.put(ciphertext);
	ubyte[tag_bytes] recv_tag = auth.finish();
	const ubyte[] expected_tag = boxed[0..tag_bytes];

	if(crypto_equals(recv_tag, expected_tag)) {
		// Tag is correct.

		ubyte[] plaintext = new ubyte[ciphertext.length];
		
		streamcipher.processBytes(ciphertext, plaintext);
		
		return plaintext;
	} else {
		throw new InvalidCipherTextException("Invalid tag!");
	}
}


unittest {
	alias immutable ubyte[] octets;

	octets key = cast(octets) x"
		1b27556473e985d462cd51197a9a46c7
		6009549eac6474f206c4ee0844f68389";

	octets nonce = cast(octets) x"
		69696ee955b62b73cd62bda875fc73d6
		8219e0036b7a0b37";

	octets msg = cast(octets) x"
		be075fc53c81f2d5cf141316ebeb0c7b
		5228c52a4c62cbd44b66849b64244ffc
		e5ecbaaf33bd751a1ac728d45e6c6129
		6cdc3c01233561f41db66cce314adb31
		0e3be8250c46f06dceea3a7fa1348057
		e2f6556ad6b1318a024a838f21af1fde
		048977eb48f59ffd4924ca1c60902e52
		f0a089bc76897040e082f93776384864
		5e0705";

	octets boxed_ref = cast(octets) x"
		f3ffc7703f9400e52a7dfb4b3d3305d9
		8e993b9f48681273c29650ba32fc76ce
		48332ea7164d96a4476fb8c531a1186a
		c0dfc17c98dce87b4da7f011ec48c972
		71d2c20f9b928fe2270d6fb863d51738
		b48eeee314a7cc8ab932164548e526ae
		90224368517acfeabd6bb3732bc0e9da
		99832b61ca01b6de56244a9e88d5f9b3
		7973f622a43d14a6599b1f654cb45a74
		e355a5";

	
	test_secret_box(msg, boxed_ref, key, nonce);
}

// Test with pseudo random input.
unittest {
	import dcrypt.random.drng;
	HashDRNG_SHA256 drng;
	drng.setSeed(0);

	ubyte[32] key;
	ubyte[24] nonce;

	drng.nextBytes(key);
	drng.nextBytes(nonce);

	ubyte[1001] message;
	drng.nextBytes(message);

	test_secret_box(message, null, key, nonce);
}

version(unittest) {
	/// Helper function for testing.
	/// Params:
	/// msg = Plaintext.
	/// boxed_ref = Expected ciphertext with authentication tag.
	/// key = Symmetric encryption key.
	void test_secret_box(in ubyte[] msg, in ubyte[] boxed_ref, in ubyte[] key, in ubyte[] nonce) {
		// test encryption
		ubyte[] boxed = secretbox(msg, nonce, key);
		if(boxed_ref !is null) {
			assert(boxed == boxed_ref, "secretbox failed");
		}

		// test decryption
		if(boxed_ref !is null) {
			ubyte[] unboxed = secretbox_open(boxed_ref, nonce, key);
			assert(unboxed == msg, "secretbox_open failed");
		} else {
			ubyte[] unboxed = secretbox_open(boxed, nonce, key);
			assert(unboxed == msg, "secretbox_open failed");
		}
		
		// test invalid authentication
		ubyte[] tampered_box = boxed.dup;
		tampered_box[$-1] ^= 1;
		
		bool exception = false;
		try {
			ubyte[] unboxed = secretbox_open(tampered_box, nonce, key);
			assert(false, "Invalid ciphertext passed as valid.");
		} catch(InvalidCipherTextException e) {
			exception = true;
		} finally {
			assert(exception, "Expected exception has not been thrown.");
		}
	}
}
