﻿module dcrypt.nacl.box;

/// High level API for asymmetric authenticated encryption.
/// Compatible to http://nacl.cr.yp.to/box.html.

public import dcrypt.nacl.secretbox;
import dcrypt.crypto.ecc.curve25519;
import dcrypt.crypto.engines.salsa;
import dcrypt.util;
import dcrypt.exceptions: InvalidCipherTextException;

/// Encrypt a message using asymmetric cryptography.
/// 
/// Params:
/// msg = The secret message.
/// nonce = A number unique per (secret_key, public_key) pair.
/// secret_key = Your secret key.
/// public_key = Recipients public key.
/// 
/// Returns: Encrypted and authenticated packet.
ubyte[] box(in ubyte[] msg, in ubyte[] nonce, in ubyte[] secret_key, in ubyte[] public_key) @safe nothrow {

	ubyte[32] shared_key = derive_shared_key(secret_key, public_key);
	scope(exit) {
		wipe(shared_key);
	}

	return secretbox(msg, nonce, shared_key);
}

/// Generate a public key from a secret key.
/// 
/// Params:
/// secret_key = A 32 byte secret key, choosen randomly.
/// 
/// Returns: Returns the public key matching to the given secret key.
ubyte[32] box_keypair(in ubyte[] secret_key) nothrow @safe @nogc 
in {
	assert(secret_key.length == 32, "Secret key must be 32 bytes.");
} body {
	return curve25519_scalarmult(secret_key);
}

/// Decrypts a packet generated by `box()`.
/// 
/// Params:
/// box = The received packet.
/// nonce = A number unique per (secret_key, public_key) pair.
/// secret_key = Your secret key.
/// public_key = Senders public key.
/// 
/// Returns: Plaintext if authentication tag is valid.
/// 
/// Throws: IllegalCipherTextException if authentication tag is not valid.
ubyte[] box_open(in ubyte[] box, in ubyte[] nonce, in ubyte[] secret_key, in ubyte[] public_key) @safe {

	ubyte[32] shared_key = derive_shared_key(secret_key, public_key);
	scope(exit) {
		wipe(shared_key);
	}

	return secretbox_open(box, nonce, shared_key);
}

/// Derive a shared key from a secret and a public key. Used for box() and box_open().
///
///	Returns: The shared key.
private ubyte[32] derive_shared_key(in ubyte[] secret_key, in ubyte[] public_key) @safe nothrow @nogc {
	ubyte[32] shared_key;
	
	immutable ubyte[16] zero_nonce = 0;
	
	shared_key = curve25519_scalarmult(secret_key, public_key);
	shared_key = HSalsa(shared_key, zero_nonce);

	return shared_key;
}

/// Test vectors from naclcrypto-20090310.pdf
unittest {
	alias immutable ubyte[] octets;

	octets alice_sk = cast(octets) x"
		77076d0a7318a57d3c16c17251b26645
		df4c2f87ebc0992ab177fba51db92c2a";

	octets bob_pk = cast(octets) x"
		de9edb7d7b7dc1b4d35b61c2ece43537
		3f8343c85b78674dadfc7e146f882b4f";

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

	test_box(msg, boxed_ref, nonce, alice_sk, bob_pk);
}

version(unittest) {
	/// Helper function for testing.
	/// Params:
	/// msg = Plaintext.
	/// boxed_ref = Expected ciphertext with authentication tag.
	/// nonce = A number unique per (sk, pk) pair.
	/// sk = Own secret key.
	/// pk = Public key.
	void test_box(in ubyte[] msg, in ubyte[] boxed_ref, in ubyte[] nonce, in ubyte[] sk, in ubyte[] pk) {
		// test encryption
		ubyte[] boxed = box(msg, nonce, sk, pk);
		if(boxed_ref !is null) {
			assert(boxed == boxed_ref, "box() failed");
		}
		
		// test decryption
		if(boxed_ref !is null) {
			ubyte[] unboxed = box_open(boxed_ref, nonce, sk, pk);
			assert(unboxed == msg, "box_open failed");
		} else {
			ubyte[] unboxed = box_open(boxed, nonce, sk, pk);
			assert(unboxed == msg, "box_open failed");
		}
		
		// test invalid authentication
		ubyte[] tampered_box = boxed.dup;
		tampered_box[$-1] ^= 1;
		
		bool exception = false;
		try {
			ubyte[] unboxed = box_open(tampered_box, nonce, sk, pk);
			assert(false, "Invalid ciphertext passed as valid.");
		} catch(InvalidCipherTextException e) {
			exception = true;
		} finally {
			assert(exception, "Expected exception has not been thrown.");
		}
	}
}