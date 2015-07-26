module dcrypt.crypto.random.fortuna.sources.reboot;

/// The reboot entropy source loads entropy from a specified file
/// and updates the seed in this file with new random data.
/// The goal of this entropy source is to provide good entropy at start of
/// the program. This is however not the case when the program is run the first time.

import dcrypt.crypto.random.fortuna.entropysource;
import dcrypt.crypto.random.fortuna.fortuna;

import std.stdio;
import std.file;

enum blockSize = 32*32;
enum blocksPerFile = 16;

version (linux) {
	unittest {
		RebootEntropySource rbs = new RebootEntropySource("/tmp/reboot.seed");
		ubyte[32] buf;

		ubyte[] slice = rbs.getEntropy(buf);

	}
}

@safe
public class RebootEntropySource: EntropySource
{

	private string seedFile;
	private Fortuna rng;
	private uint blockCounter = 0;
	private File inputFile;

	/// Params:
	/// seedFile = The file to load the seed from and to store new seed.
	this(string seedFile) nothrow
	{
		this.seedFile = seedFile;
		if(exists(seedFile)) {
			try {
				inputFile = File(seedFile, "rb");
			} catch (Exception e) {
				
				// TODO
				assert(false, "error opening entropy file");
			}
		}
	}

	/// Read entropy from file.
	@trusted
	override public ubyte[] getEntropy(ubyte[] buf) nothrow {
		if(exists(seedFile)) {
			// get entropy
			try {

				return inputFile.rawRead(buf);

			} catch (Exception e) {
				// TODO
				assert(false, "error reading entropy file");
			}
		}

		return buf[0..0];
	}

	@nogc @property nothrow
	override public string name() {
		return "RebootSource";
	}

	/// Get random data from Fortuna and store it to a file for use at next program start.
	@trusted
	private void storeEntropy() nothrow {
		try {
			ubyte[32] buf;

			File f = File(seedFile, "a+b");

			f.seek(blockSize*blockCounter, SEEK_SET); // FIXME seek does not work as intended

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
		inputFile.close();
		storeEntropy();
	}
}

