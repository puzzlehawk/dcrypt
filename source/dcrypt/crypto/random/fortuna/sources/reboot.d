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
		rbs.start();
		//rbs.stop();
	}
}

@safe
public class RebootEntropySource: EntropySource
{

	private string seedFile;
	private Fortuna rng = new Fortuna;
	private uint blockCounter = 0;

	/// Params:
	/// seedFile = The file to load the seed from and to store new seed.
	this(string seedFile)
	{
		this.seedFile = seedFile;
	}

	public override void start() nothrow {
		getEntropy();
		storeEntropy();
	}

	public override void stop() nothrow {
		storeEntropy();
	}

	@trusted
	private void getEntropy() nothrow {
		if(exists(seedFile)) {
			// get entropy
			try {
				File f = File(seedFile, "rb");

				foreach(c; f.byChunk(4096)) {
					sendEntropyEvent(c);
				}
				
				f.close();

			} catch (Exception e) {
				// TODO
				assert(false, "error reading entropy file");
			}
		}
	}

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
		storeEntropy();
	}
}

