module dcrypt.crypto.random.urandom;

import std.stdio;
import std.file;
import std.exception;
import std.conv: text;

import dcrypt.crypto.random.prng;

/// This module wraps the /dev/urandom special file into a dcrypt PRNG.
/// Available for Linux only.

version(linux) {

	/// Test /dev/urandom based PRNG.
	unittest {
		URandomPRNG rng = new URandomPRNG;
		
		ubyte[16] buf;
		
		assert(rng.isAvailable);
		
		rng.nextBytes(buf);
		
		assert(buf != x"000000000000000000000000000000", "failed to get entropy from /dev/urandom");
	}

}  

unittest {
	if(URandomPRNG.isAvailable) {
		PRNG rand = new URandomPRNG();
		
		auto buf1 = new ubyte[64];
		auto buf2 = new ubyte[64];
		
		rand.nextBytes(buf1);
		rand.nextBytes(buf2);
		
		assert(buf1 != buf2, "data is not random");
	}
}



///
///	URandomRNG provides an interface to the /dev/urandom RNG of
///	most Unix like systems.
///
@safe
public class URandomPRNG: PRNG {

	/**
	 Throws: exception if /dev/urandom is not available
	 */
	public this() {
		if (isAvailable()) {
			urandFile = File(urand , "r");
		} else {
			throw new Exception(urand~" not available");
		}
	}
	
	~this() {
		urandFile.close();
	}

	@property
	public static bool isAvailable() nothrow {
		// HACK: problem with different standard library version
		version(LDC) {
			try {
				return exists(urand);
			}catch(Exception e) {}	

			return false;
		} else {
			return exists(urand);
		}
	}

	override {

		/// Returns: Get the name of this PRNG.
		@property
		public pure nothrow string name() {
			return "/dev/urandom";
		}
		
		@trusted
		public void nextBytes(ubyte[] buf) {
			try {
				urandFile.rawRead(buf);
			}catch(Exception e) {
				assert(false, text("URandomPRNG failed to get entropy from ",urand));
			}
		}
		
		public void addSeed(in ubyte[] seed) {
			// dont do anything
		}
	}

	private {
		enum urand = "/dev/urandom";
		File urandFile;
	}
	
}
