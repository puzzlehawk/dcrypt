module dcrypt.crypto.random.fortuna.sources.systemtick;

import core.time;


import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.fortuna: addEntropy;

/// Generate entropy data with the system clock.
/// 

unittest {
	auto stick = new SystemTickEntropySource;
}

@safe
public class SystemTickEntropySource: EntropySource
{

	override ubyte[] getEntropy(ubyte[] buf) {
		getTimingData(buf);

		
		return buf;
	}

	@nogc @property nothrow
	override public string name() {
		return "SystemTickSource";
	}

	/// Fill the buffer with timing measurements.
	/// Params:
	/// buf = The buffer to fill.
	@safe @nogc nothrow
	private static void getTimingData(ubyte[] buf) {
		foreach(ref b; buf) {
			ulong ticks = MonoTime.currTime.ticks;
			b = cast(ubyte) (ticks^(ticks>>8)^(ticks>>16)); // Combine three bytes of ticks for the case if the system clock has low resolution.
		}
	}

	unittest {
		ubyte[32] buf1, buf2;
		
		getTimingData(buf1);
		getTimingData(buf2);
		
		assert(buf1 != buf2, "Measurements are not at all random!");
	}

}