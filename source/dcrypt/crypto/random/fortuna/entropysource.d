module dcrypt.crypto.random.fortuna.entropysource;


import core.thread;

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
	private Thread worker;

	@trusted
	final this() nothrow {
		this.sourceID = idCounter++; // give each source another ID (as long as there are less than 256 sources)
		try {
			worker = new Thread(&run);
			worker.isDaemon = true;
			worker.start();
		} catch(Exception e) {
			assert(false, e.toString());
		}
	}

	private void run() {
		bool running = true;

		while(running) {
			ubyte[32] buf;

			getEntropy(buf);

			sendEntropyEvent(buf);

			uint delay = scheduleNext();

			if(delay > 0) {
				trustedSleep!"msecs"(delay);
			} else {
				running = false;
			}

		}

	}

	@trusted
	private static void trustedSleep(string s)(uint i) nothrow {
		try {
			Thread.sleep(dur!s(i));
		} catch (ThreadError te) {
			// swallow
		}
	}

	/// Collect entropy.
	/// 
	/// Returns: Slice pointing to the new data in the buffer.
	public abstract ubyte[] getEntropy(ubyte[] buf);

	@safe @nogc nothrow
	public abstract uint scheduleNext();

	@property @nogc nothrow
	public abstract string name();

	/// use this method to send entropy to the accumulator
	@safe
	private void sendEntropyEvent(in ubyte[] buf) {
		import dcrypt.crypto.random.fortuna.fortuna;

		addEntropy(sourceID, buf);

		import std.stdio;
		debug writeln(sourceID, " ",  name, ":\t", dcrypt.util.encoders.hex.toHexStr(buf));
	}

}

