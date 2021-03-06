﻿module dcrypt.random.fortuna.sources.rdrand;

import dcrypt.random.rdrand;
import dcrypt.random.fortuna.entropysource;
import dcrypt.random.fortuna.fortuna: addEntropy;

/// Generate entropy data with intel rdrand instruction.

@safe
public class RDRandEntropySource: EntropySource
{

	private {
		uint delay = 250;
		RDRand rdrand;
	}

	override void collectEntropy() nothrow {

		ubyte[32] buf;

		if(rdrand.isSupported) {
			rdrand.nextBytes(buf);
		} else {
			// not supported
			delay = 0;
		}

		sendEntropyEvent(buf);
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