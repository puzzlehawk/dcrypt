module dcrypt.crypto.random.fortuna.sources.rdrand;

import dcrypt.crypto.random.rdrand;
import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.fortuna: addEntropy;

/// Generate entropy data with intel rdrand instruction.

@safe
public class RDRandEntropySource: EntropySource
{

	private {
		uint delay = 250;
		RDRand rdrand;
	}

	override ubyte[] getEntropy(ubyte[] buf) {

		if(rdrand.isSupported) {
			rdrand.nextBytes(buf);
			return buf;
		} else {
			// not supported
			delay = 0;
			return buf[0..0];
		}

	}

	@nogc @property nothrow
	override public string name() {
		return "RDRand";
	}

	@safe @nogc nothrow
	override uint scheduleNext() {
		return delay;
	}

}