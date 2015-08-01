module dcrypt.crypto.random.fortuna.fortuna;

public import dcrypt.crypto.random.prng;
public import dcrypt.crypto.blockcipher;
public import dcrypt.crypto.digest;

import dcrypt.crypto.random.fortuna.generator;
import dcrypt.crypto.random.fortuna.accumulator;

import dcrypt.crypto.engines.aes;
import dcrypt.crypto.digests.sha2;

import std.datetime;


/// OOP wrapper
public alias WrapperPRNG!(FortunaCore!(AES, SHA256)) FortunaRNG;
public alias FortunaCore!(AES, SHA256) Fortuna;

/// Get some random bytes from Fortuna.
unittest {
	FortunaCore!(AES, SHA256) fortuna;

	ubyte[61] buf1;
	ubyte[buf1.length] buf2;
	fortuna.addSeed([0,1,2,3]);
	foreach(i;0..10) {
		buf2 = buf1;
		fortuna.nextBytes(buf1);

		if(i > 0) {
			assert(buf2 != buf1, "data is not random");
		}
	}
}


/// Add real entropy to the global accumulator.
/// 
/// Params:
/// sourceID =	The ID of the entropy source. Can actually be any number.
/// pool = The ID of the pool to add the entropy.
/// seed	=	Random data.
@safe
public void addEntropy(in ubyte sourceID, in size_t pool, in ubyte[] seed...) nothrow @nogc 
in {
	assert(pool < Accumulator.pools, "Pool ID out of range.");
}
body {
	assert(globalAcc !is null, "Accumulator not initialized!");
	globalAcc.addEntropy(sourceID, pool, seed);
	
}

/// Get 32 bytes of unpredictable* seed from the global accumulator.
/// 
/// Note:
/// * The seed can only be unpredictable if the accumulator gets enough entropy from entropy sources.
/// 
/// Params:
/// buf	=	A buffer for exactly 32 bytes.
/// 
/// Throws:
/// Error = if buffer has wrong size.
@safe
private void getSeed(ubyte[] buf) nothrow @nogc
in {
	assert(buf.length == 32, "buf must be 32 bytes long.");
}
body {
	assert(globalAcc !is null, "Accumulator not initialized!");
	globalAcc.extractEntropy(buf);
}

private shared Accumulator globalAcc;	/// The entropy accumulator is used globally.

/// initialize and seed the global accumulator
private shared static this() {
	globalAcc = new shared Accumulator;

	// seed the accumulator
	ubyte[32] buf;
	foreach(i;0..4096/buf.length) {
		import dcrypt.crypto.random.fortuna.sources.systemtick;

		getTimingEntropy(buf);
		addEntropy(0, i%Accumulator.pools, buf);

	}
}


static assert(isRNG!(FortunaCore!(AES, SHA256)), "Fortuna does not meet requirements for PRNGs.");

/// FortunaCore is meant to be the mothership of the PRNGs. It should run as a singleton -
/// one instance per application that handles the accumulator and entropy sources.
/// 
/// Params:
/// Cipher = A block cipher.
/// Digest = A hash algorithm.
@safe
private struct FortunaCore(Cipher, Digest) if(isBlockCipher!Cipher && isDigest!Digest)  {
nothrow:
	
	public {

		enum name = "FortunaCore";

		/// Add entropy to generators state but not to the accumulator.
		@safe
		void addSeed(in ubyte[] seed) nothrow @nogc {
			// pass this call directly to the generator
			prng.addSeed(seed);
		}

		/// Fill the buffer with random bytes.
		void nextBytes(ubyte[] buffer) nothrow @nogc {
			randomData(buffer);
		}
	}

	
	private {
		enum minReseedInterval = 100; /// minimal time in ms between reseeds

		FortunaGenerator!(Cipher, Digest) prng;

		size_t reseedCount = 0; /// increment each time reseed() is called
		ulong lastReseed = 0; /// time of the last reseed in ms

		@safe
		void randomData(ubyte[] buffer) nothrow @nogc
		{

			if(
				//a.getLength() >= MINPOOLSIZE &&
				TickDuration.currSystemTick.msecs - lastReseed > minReseedInterval) {
				
				reseed();

			}

			if(lastReseed == 0 && reseedCount == 0) {
				assert(false, "PRNG not seeded yet");
			}

			// ready to generate the random data
			prng.nextBytes(buffer);
		}

		/// get entropy from accumulator
		@trusted
		private void reseed() nothrow @nogc {
			ubyte[32] buf;

			getSeed(buf);

			assert(std.algorithm.any!"a != 0"(buf[]), "Got only zeros from accumulator instead of noise!");

			prng.addSeed(buf);
			
			lastReseed = TickDuration.currSystemTick.msecs;
			++reseedCount;

		}
		
	}
}