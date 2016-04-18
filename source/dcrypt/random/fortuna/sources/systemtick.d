module dcrypt.random.fortuna.sources.systemtick;

import core.time;


import dcrypt.random.fortuna.entropysource;
import dcrypt.random.fortuna.fortuna: addEntropy;

/// Generate entropy data with the system clock.
/// 

unittest {
	auto st = new SystemTickEntropySource;
	st.start();
}

@safe
public class SystemTickEntropySource: EntropySource
{

	override void collectEntropy() nothrow {
		ubyte[64] buf;

		getTimingEntropy(buf);

		sendEntropyEvent(buf);
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