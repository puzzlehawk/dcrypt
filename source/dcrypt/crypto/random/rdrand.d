module dcrypt.crypto.random.rdrand;


/// The RDRand PRNG generates random data with intels rdrand instruction.
/// Use `RDRand.isSupported` to check at runntime if rdrand is supported.
/// 
/// TODO: This module is not yet tested.

import dcrypt.crypto.random.prng;
import dcrypt.bitmanip;
import core.cpuid;
import std.range: chunks;

unittest {
	if(RDRand.isSupported) {
		ubyte[71] buf1;
		ubyte[71] buf2;

		RDRand rand;

		rand.nextBytes(buf1);
		rand.nextBytes(buf2);
		
		assert(buf1 != buf2, "rdrand produced twice the same output!");
	}
}

static assert(isRNG!RDRand);

@safe
public struct RDRand {

	public {

		enum name = "RDRand";

	}

	/// Returns: `true` if your platform supports the rdrand instruction. Evaluated at runtime.
	@property
	public static bool isSupported() nothrow @nogc {
		return hasRdrand();
	}
	
	/// Generate random data with rdrand instruction.
	/// Params:
	/// buf = Buffer for random data.
	/// 
	/// Throws: Throws an Error if your platform does not support the RDRAND instruction.
	@trusted
	public static void nextBytes(ubyte[] buf) nothrow @nogc
	{
		
		if(!isSupported) {
			assert(false, "RDRAND is not supported by your platform!");
		}
		
		size_t len = buf.length / 8;
		
		asm nothrow @nogc {
			
			mov RDI, buf+8;	// load pointer to destination buffer
			mov RCX, len;	// set counter to len
			
			// fill buf with random data
		fillLoop:
			rdrand	R8;
			mov	R8, RAX;
			mov		[RDI], R8;
			add		RDI, 8;
			
			loop fillLoop;
		}
		
		
		if(buf.length % 8 > 0) {
			
			assert(buf.length-len*8 < 8);
			
			// fill remainder with random bytes
			ulong r = nextLong();
			
			foreach(ref b; buf[len*8 .. $]) {
				b = cast(ubyte) r;
				r >>= 8;
			}
		}
	}

//	public void nextBytes(ubyte[] buf) nothrow @nogc 
//	{
//
//		if(!isSupported) {
//			assert(false, "RDRAND is not supported by your platform!");
//		}
//
//		while(buf.length > 0) {
//			long r = nextLong();
//			for(uint i = 0; i < 8 && buf.length > 0; ++i) {
//				buf[0] = cast(ubyte) r & 0xFF;
//				r >>= 8;
//			}
//		}
//	}

	/// Returns: A uniformly random ulong.
	/// 
	// TODO: optimize to fill an array
	@trusted
	private static ulong nextLong() nothrow @nogc {
		ulong r;

		asm nothrow @nogc {
			rdrand	R8;
			mov		r, R8;
		}

		return r;
	}


	unittest {
		if(isSupported) {
			long r1 = nextLong();
			long r2 = nextLong();

			assert(r1 != r2, "rdrand produced twice the same output!");
		}
	}

}