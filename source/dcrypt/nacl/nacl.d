module nacl;

public import dcrypt.nacl.secretbox;
public import dcrypt.nacl.box;

import dcrypt.random;

public alias secretbox crypto_secretbox;
public alias secretbox_open crypto_secretbox_open;
public alias box crypto_box;
public alias box_open crypto_box_open;
public alias box_keypair crypto_box_keypair;

/// Generate a keypair.
public void box_keypair(out ubyte[32] sk, out ubyte[32] pk) nothrow @safe @nogc {
	nextBytes(sk);
	pk = dcrypt.nacl.box.box_keypair(sk[]);
}

unittest {
	ubyte[32] sk, pk;

	/// Generate a random keypair.
	box_keypair(sk, pk);

//	import std.stdio;
//
//	writefln("%(%.2x%)", sk);
//	writefln("%(%.2x%)", pk);
}