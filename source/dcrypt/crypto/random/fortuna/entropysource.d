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
	private size_t pool = 0; // ID of the pool where the entropy gets sent to.
	private bool calledSendEntropyEvent; /// Used to control wether the source calls sendEntropyEvent or not.
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

			calledSendEntropyEvent = false;
			collectEntropy();

			assert(calledSendEntropyEvent, name~" did not call sendEntropyEvent().");

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
	/// Note: Implementation must call `sendEntropyEvent(in ubyte[] buf)` to send data to the accumulator.
	public abstract void collectEntropy();

	@safe @nogc nothrow
	public abstract uint scheduleNext();

	@property @nogc nothrow
	public abstract string name();

	/// use this method to send entropy to the accumulator
	@safe
	protected final void sendEntropyEvent(in ubyte[] buf) nothrow {
		import dcrypt.crypto.random.fortuna.fortuna: addEntropy;

		calledSendEntropyEvent = true;

		addEntropy(sourceID, pool, buf);

		++pool;

//		debug {
//			try {
//				import std.stdio;
//				writeln(sourceID, " ", pool, " ",  name, ":\t", dcrypt.encoders.hex.toHexStr(buf[0..$/4]));
//			} catch(Exception e) {}
//		}
	}

}

