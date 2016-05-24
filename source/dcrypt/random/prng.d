module dcrypt.random.prng;

import std.range;
import dcrypt.random.fortuna.fortuna;
import dcrypt.random.fortuna.generator;

import dcrypt.blockcipher.aes;
import dcrypt.digests.sha2;

alias FortunaGenerator!(AES, SHA256) DRNG; /// Deterministic PRNG

// TODO implement PRNGs as input ranges

///
/// Test if T is a random number generator.
/// Returns: Returns $(D true) if T can be used as a PRNG.
/// 
@safe
template isRNG(T)
{
	enum bool isRNG = 
		is(T == struct) && // isInputRange!T &&
			is(typeof(
					{
						ubyte[] buf;
						T rng = T.init;
						string name = rng.name;
						rng.nextBytes(buf);
					}));
}

@safe
template isRNGWithInput(T)
{
	enum bool isRNGWithInput = isRNG!T &&
			is(typeof(
					{
						ubyte[] buf;
						T rng = T.init;
						rng.addSeed(cast(const ubyte[]) buf);
						rng.addSeed(cast(ubyte) 0);
						rng.addSeed(cast(ubyte) 0, cast(ubyte) 0);
					}));
}

/// Helper function for prng.
/// 
/// Params:
/// rng = The RNG to put the data into.
/// seed = The seed to update the RNG with.
/// 
/// Example:
/// 	ubyte[4] buf;
/// 	RNG rng;
/// 	rng.addSeed(cast(ubyte) 0x01, buf, buf[0..2]);
@safe
public void addSeed(R, T...)(ref R rng, in T seed) nothrow @nogc
if(isRNGWithInput!D) {
	foreach(s; seed) {
		digest.addSeed(s);
	}
}

@safe
public abstract class PRNG {

// TODO: default RNG
//	/**
//	 * Creates a default PRNG. Type depends on your system.
//	 */
//	public static PRNG getInstance() nothrow
//	out (result) {
//		assert(result !is null, "failed to initialize PRNG instance");
//	}
//	body {
//		return new Fortuna();
//	}
	
	/// Fill the buffer with random bytes.
	/// 
	/// Params:
	/// buf = Output buffer to be filled with PRNG data.
	public abstract void nextBytes(ubyte[] buf) nothrow;
	
	/// Returns: The name of the RNG algorithm.
	@property
	public abstract string name() pure nothrow;

	///
	/// Add a seed value to the PRNG.
	/// 
	/// Params:
	/// seed = The seed value to add to the PRNG.
	public abstract void addSeed(in ubyte[] seed) nothrow;
	
}

///
///	Wrapper class for PRNGs.
///
@safe
public class WrapperPRNG(R) if(isRNGWithInput!R): PRNG {

	private R rng;

override:
	/// Fill the buffer with random bytes.
	/// 
	/// Params:
	/// buf = Output buffer to be filled with PRNG data.
	public void nextBytes(ubyte[] buf) nothrow {
		rng.nextBytes(buf);
	}
	
	/// Returns: the name of the RNG algorithm
	@property
	public string name() pure nothrow @nogc {
		return rng.name;
	}
	
	///
	/// Add a seed value to the PRNG.
	/// 
	/// Params:
	/// seed = the seed value to add to the PRNG
	public void addSeed(in ubyte[] seed) nothrow @nogc {
		rng.addSeed(seed);
	}
}