module dcrypt.random;

/// Handling global source of randomness.


import dcrypt.crypto.random.fortuna.fortuna;

import dcrypt.crypto.random.rdrand;

import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.sources.rdrand;
import dcrypt.crypto.random.fortuna.sources.systemtick;
import dcrypt.crypto.random.fortuna.sources.filesource;

private Fortuna globalRNG;

private enum urandom = "/dev/urandom";

public void nextBytes(ubyte[] buf) @safe nothrow @nogc {
	globalRNG.nextBytes(buf);
}

unittest {
	ubyte[50] buf1, buf2;

	nextBytes(buf1);
	nextBytes(buf2);

	assert(buf1 != buf2);
}

private shared static this(){
	/// Initialize entropy sources.

	debug import std.stdio;

	if(RDRand.isSupported) {
		// start rdrand entropy source

		debug writeln("starting RDRAND entropy source");
		EntropySource rdrand_src = new RDRandEntropySource;
		rdrand_src.start();

	} else {
		debug writeln("RDRAND entropy source not available");
	}

	try {
		debug writeln("starting /dev/urandom entropy source");
		EntropySource urandom_src = new FileEntropySource(urandom);
		urandom_src.start();
	} catch(Exception e) {
		debug writeln("/dev/urandom entropy source not available", e);
	}

	debug writeln("starting system-tick entropy source");
	EntropySource systick_src = new SystemTickEntropySource;
	systick_src.start();
}