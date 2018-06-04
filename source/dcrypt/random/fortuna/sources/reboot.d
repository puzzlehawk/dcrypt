module dcrypt.random.fortuna.sources.reboot;

/// The reboot entropy source loads entropy from a specified file
/// and updates the seed in this file with new random data.
/// The goal of this entropy source is to provide good entropy at start of
/// the program. This is however not the case when the program is run the first time.

import dcrypt.random.fortuna.entropysource;
import dcrypt.random.fortuna.fortuna;

import std.stdio;
import std.file;

private enum blockSize = 32*32;
private enum blocksPerFile = 16;

@safe
public class RebootEntropySource: EntropySource
{

	private string seedFile;
	private Fortuna rng;
	private uint blockCounter = 0;
	private uint delay = 1;

	/// Params:
	/// seedFile = The file to load the seed from and to store new seed.
	this(string seedFile) nothrow
	{
		this.seedFile = seedFile;
	}

	/// Read entropy from file.
	@trusted
	override public void collectEntropy() nothrow {

		delay = 0; // one shot

		if(exists(seedFile)) {
			try {
				// read whole file and send it to the accumulator
				File inputFile = File(seedFile, "rb");

				scope(exit) {
					inputFile.close();
				}

				foreach(ubyte[] c; inputFile.chunks(32)) {
					sendEntropyEvent(c);
				}


			} catch (Exception e) {
				
				// TODO
				assert(false, "error opening entropy file");
			}
		}
	}

	@nogc @property nothrow
	override public string name() {
		return "RebootSource";
	}

	@safe @nogc nothrow
	override uint scheduleNext() {
		return delay;
	}

	/// Get random data from Fortuna and store it to a file for use at next program start.
	@trusted
	private void storeEntropy() nothrow {
		try {
			ubyte[32] buf;

			File f = File(seedFile, "wb");

			//f.seek(blockSize*blockCounter, SEEK_SET); // FIXME seek does not work as intended

			foreach(i; 0..32) {
				rng.nextBytes(buf);
				f.rawWrite(buf);
			}

			blockCounter++;
			blockCounter %= blocksPerFile;

		}catch (Exception e) {
			version(assert) {
				assert(false, "'reboot' entropy source: could not store entropy to file!");
			}
			// TODO use a logger
		}
	}

	~this() {
		storeEntropy();
	}
}

