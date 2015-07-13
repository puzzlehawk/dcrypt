module dcrypt.crypto.random.fortuna.entropysource;

import dcrypt.crypto.random.fortuna.accumulator;

///
/// This class provides a simple method to pass an entropy event
/// to the accumulator of the PRNG algorithm. Namely: sendEntropyEvent()
/// 
/// 
@safe
public abstract class EntropySource
{
	private static ubyte idCounter = 0;
	private ubyte sourceID;

	@safe
	final this() nothrow {
		this.sourceID = idCounter++; // give each source another ID (as long as there are less than 256 sources)
	}

	/// start entropy collection
	public abstract void start();

	/// stop entropy collection
	public abstract void stop();

	/// use this method to send entropy to the accumulator
	@safe
	final void sendEntropyEvent(in ubyte[] buf) {
		import dcrypt.crypto.random.fortuna.fortuna;

		addEntropy(sourceID, buf);
	}

}

