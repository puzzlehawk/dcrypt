module dcrypt.random.rdrand;


/// The RDRand PRNG generates random data with intels rdrand instruction.
/// Use `RDRand.isSupported` to check at runntime if rdrand is supported.
/// 
/// TODO: This module is not yet tested.

import dcrypt.random.prng;
import dcrypt.bitmanip;
import core.cpuid;

unittest {
	if(RDRand.isSupported) {
		ubyte[71] buf1;
		ubyte[71] buf2;

		RDRand rand;

		rand.nextBytes(buf1);
		rand.nextBytes(buf2);
		
		assert(buf1 != buf2, "rdrand produced twice the same output!");

		ubyte[32] buf3; // Test multiple of 8.
		rand.nextBytes(buf3);
	}
}

// OOP wrapper
alias WrapperPRNG!RDRand RDRandRNG;

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

		while(buf.length >= 8) {
			ulong r = nextLong();
			toLittleEndian!long(r, buf);
			buf = buf[8..$];
		}
		
		if(buf.length > 0) {
			
			assert(buf.length < 8);
			
			// fill remainder with random bytes
			ulong r = nextLong();
			
			foreach(ref b; buf) {
				b = cast(ubyte) r;
				r >>= 8;
			}
		}
	}

	/// RDRAND is not seedable.
	public void addSeed(in ubyte[] seed...) nothrow @nogc {
		// Don't do anything.
	}

	/// Returns: A uniformly random ulong.
	/// 
	// TODO: optimize to fill an array
	@trusted
	private static ulong nextLong() nothrow @nogc {

		version(X86_64) {

			ulong r;

			version(LDC) {
				asm nothrow @nogc {
					db 0x49, 0x0f, 0xc7, 0xf0; // rdrand R8;
					mov		r, R8;
				}
			} else {
				asm nothrow @nogc {
					rdrand	R8;
					mov		r, R8;
				}
			}

			return r;

		} else {
			assert(false, "RDRAND is supported on x86_64 only.");
		}
	}

	
	unittest {
		if(isSupported) {
			long r1 = nextLong();
			long r2 = nextLong();

			assert(r1 != r2, "rdrand produced twice the same output!");
		}
	}

}