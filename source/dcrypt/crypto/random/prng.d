module dcrypt.crypto.random.prng;

import std.range;
//import dcrypt.crypto.random.urandom;
import dcrypt.crypto.random.fortuna.fortuna;

// TODO implement PRNGs as input ranges

///
/// Test if T is a random number generator.
/// Returns: Returns $(D true) if T can be used as a PRNG.
/// 
@safe
template isPRNG(T)
{
	enum bool isPRNG = 
		is(T == struct) &&
			is(typeof(
					{
						ubyte[] buf;
						T rng = void;
						string name = rng.name;
						rng.nextBytes(buf);
						rng.addSeed(cast(const ubyte[]) buf);
					}));
}

@safe
public abstract class PRNG {

	/**
	 * Creates a default PRNG. Type depends on your system.
	 */
	public static PRNG getInstance() nothrow
	out (result) {
		assert(result !is null, "failed to initialize PRNG instance");
	}
	body {
		return new Fortuna();
	}
	
	/// Fill the buffer with random bytes.
	/// Params:
	/// buf = output buffer to be filled with PRNG data
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
public class WrapperPRNG(R) if(isPRNG!R): PRNG {

	private R rng;

override:
	/// fill the buffer with random bytes
	/// Params:
	/// buf = output buffer to be filled with PRNG data
	public void nextBytes(ubyte[] buf) nothrow @nogc {
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