module dcrypt.random;

/// Handling global source of randomness.


import dcrypt.crypto.random.fortuna.fortuna;

import dcrypt.crypto.random.rdrand;

import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.sources.rdrand;
import dcrypt.crypto.random.fortuna.sources.systemtick;
import dcrypt.crypto.random.fortuna.sources.filesource;

private FortunaRNG globalRNG;

private enum urandom = "/dev/urandom";


shared static this(){
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
}