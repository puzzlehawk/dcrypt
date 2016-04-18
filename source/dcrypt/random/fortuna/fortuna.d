module dcrypt.random.fortuna.fortuna;

public import dcrypt.random.drng;
public import dcrypt.blockcipher.blockcipher;
public import dcrypt.digest;

import dcrypt.random.fortuna.generator;
import dcrypt.random.fortuna.accumulator;

import dcrypt.blockcipher.aes;
import dcrypt.digests.sha3;

import std.datetime;


/// OOP wrapper
public alias WrapperPRNG!Fortuna FortunaRNG;

alias FortunaGenerator!(AES, SHA3_256) PRNGWithInput;
public alias FortunaCore!PRNGWithInput Fortuna;

/// Get some random bytes from Fortuna.
unittest {
	Fortuna fortuna;

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

/// Extract seed from global accumulator.
private unittest {
	ubyte[32] buf1, buf2;
	getSeed(buf1);
	getSeed(buf2);
	assert(buf1 != buf2, "Accumulator failed!");
}


/// Add real entropy to the global accumulator.
/// 
/// Params:
/// sourceID =	The ID of the entropy source. Can actually be any number.
/// pool = The ID of the pool to add the entropy.
/// seed	=	Random data.
@safe
public void addEntropy(in ubyte sourceID, in size_t pool, in ubyte[] seed...) nothrow @nogc 
{
	assert(globalAcc !is null, "Accumulator not initialized!");
	globalAcc.addEntropy(sourceID, pool%FortunaAccumulator.pools, seed);
	
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

package alias Accumulator!HashDRNG_SHA3_256 FortunaAccumulator;
private shared FortunaAccumulator globalAcc;	/// The entropy accumulator is used globally.

/// Initialize and seed the global accumulator.
private shared static this() {
	globalAcc = new shared FortunaAccumulator;

	
	version(linux) {
		// Read entropy from /dev/urandom and seed the global accumulator.

		import dcrypt.random.urandom;
		if(URandomRNG.isAvailable) {
			URandomRNG rng = new URandomRNG;
			ubyte[64] buf;
			foreach(i; 0..32) {
				rng.nextBytes(buf);
				addEntropy(0, i, buf);
			}
		}

	} else {

		// Seed the accumulator with (weak?) timing entropy.
		ubyte[32] buf;
		foreach(i;0..4096/buf.length) {
			import dcrypt.random.fortuna.sources.systemtick;

			getTimingEntropy(buf);
			addEntropy(0, i, buf);
		}

	}
}



static assert(isRNGWithInput!(FortunaCore!(FortunaGenerator!(AES, SHA3_256))), "Fortuna does not meet requirements for PRNGs.");

/// FortunaCore is meant to be the mothership of the PRNGs. It should run as a singleton -
/// one instance per application that handles the accumulator and entropy sources.
/// 
/// Params:
/// Cipher = A block cipher.
/// Digest = A hash algorithm.
@safe
private struct FortunaCore(RNGWithInput) if(isRNGWithInput!RNGWithInput)  {
nothrow:
	
	public {

		enum name = "FortunaCore";
		enum isDeterministic = true;

		/// Add entropy to generators state but not to the accumulator.
		@safe
		void addSeed(in ubyte[] seed...) nothrow @nogc {
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

		RNGWithInput prng;

		size_t reseedCount = 0; /// increment each time reseed() is called
		ulong lastReseed = 0; /// time of the last reseed in ms

		@safe
		void randomData(ubyte[] buffer) nothrow @nogc
		{

			if(
				//a.getLength() >= MINPOOLSIZE &&
				TickDuration.currSystemTick.msecs - lastReseed > minReseedInterval)
			{
				reseed();
			}

			if(lastReseed == 0 && reseedCount == 0) {
				assert(false, "PRNG not seeded yet");
			}

			// ready to generate the random data
			prng.nextBytes(buffer);
		}

		/// get entropy from accumulator
		@safe
		private void reseed() nothrow @nogc {
			ubyte[32] buf;

			getSeed(buf);

			prng.addSeed(buf);
			
			lastReseed = TickDuration.currSystemTick.msecs;
			++reseedCount;
		}
		
	}
}