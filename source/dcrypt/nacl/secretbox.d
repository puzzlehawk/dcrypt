module dcrypt.nacl.secretbox;

import dcrypt.crypto.macs.poly1305;
import dcrypt.crypto.engines.salsa;

enum overhead_bytes = 16;
enum key_bytes = 32;
enum nonce_bytes = 24;

public ubyte[] secretbox(in ubyte[] msg, in ubyte[] key, in ubyte[] nonce) @safe nothrow
in {
	assert(key.length == key_bytes, "Invalid key length.");
	assert(nonce.length == nonce_bytes, "Invalid nonce length.");
} body {

	XSalsa20 streamcipher;
	streamcipher.start(true, key, nonce);

	ubyte[32] auth_key = 0;

	// Derive authentication key by encrypting 32 zeros.
	streamcipher.processBytes(auth_key, auth_key);

	Poly1305Raw auth;
	auth.start(auth_key);

	ubyte[] output = new ubyte[overhead_bytes + msg.length];

	ubyte[] ciphertext = streamcipher.processBytes(msg, output[overhead_bytes .. $]);
	auth.put(ciphertext);
	output[0..overhead_bytes] = auth.finish();

	return output;
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

	ubyte[] boxed = secretbox(msg, key, nonce);

	assert(boxed == boxed_ref, "secretbox failed");
}