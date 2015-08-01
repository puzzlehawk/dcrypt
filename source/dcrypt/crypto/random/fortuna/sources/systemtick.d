module dcrypt.crypto.random.fortuna.sources.systemtick;

import core.time;


import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.fortuna: addEntropy;

/// Generate entropy data with the system clock.
/// 


unittest {
	auto sTick = new SystemTickEntropySource;
	ubyte[32] buf1;
	ubyte[32] buf2;
	sTick.getEntropy(buf1);
	sTick.getEntropy(buf2);

	assert(buf1 != buf2, "Measurements are not at all random!");

}

@safe
public class SystemTickEntropySource: EntropySource
{

	override ubyte[] getEntropy(ubyte[] buf) {
		getTimingEntropy(buf);

		
		return buf;
	}

	@nogc @property nothrow
	override public string name() {
		return "SystemTickSource";
	}

	@safe @nogc nothrow
	override uint scheduleNext() {
		return 250;
	}

}

/// Fill the buffer with timing measurements.
/// Params:
/// buf = The buffer to fill.
@safe @nogc nothrow
static void getTimingEntropy(ubyte[] buf) {
	foreach(ref b; buf) {
		ulong ticks = MonoTime.currTime.ticks;
		b = cast(ubyte) (ticks^(ticks>>8)^(ticks>>16)); // Combine three bytes for the case if the system clock has low resolution.
	}
}

unittest {
	ubyte[32] buf1, buf2;
	
	getTimingEntropy(buf1);
	getTimingEntropy(buf2);
	
	assert(buf1 != buf2, "Measurements are not at all random!");
}