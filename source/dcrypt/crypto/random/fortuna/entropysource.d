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


	final this() nothrow {
		this.sourceID = idCounter++; // give each source another ID (as long as there are less than 256 sources)
	}

	@trusted
	public final void start() nothrow {
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

			ubyte[] recvEntropy = getEntropy(buf);	// Get the entropy.

			sendEntropyEvent(recvEntropy);	// Send the entropy to the global accumulator.

			uint delay = scheduleNext();	// Ask the source when it wants to be invoked.

			if(delay > 0) {
				trustedSleep!"msecs"(delay);
			} else {
				// delay == 0 means the source wants to be closed
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

//		import std.stdio;
//		debug writeln(sourceID, " ",  name, ":\t", dcrypt.util.encoders.hex.toHexStr(buf));
	}

}

