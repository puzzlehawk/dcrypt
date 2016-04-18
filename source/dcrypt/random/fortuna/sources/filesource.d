module dcrypt.random.fortuna.sources.filesource;

/// Read entropy from a file or special file (/dev/urandom).

import dcrypt.random.fortuna.entropysource;
import dcrypt.random.fortuna.fortuna;

import std.stdio;
import std.file;

//version (linux) {
//	/// Get entropy from /dev/urandom
//	unittest {
//		import std.algorithm: any;
//		FileEntropySource fs = new FileEntropySource("/dev/urandom");
//
//		ubyte[32] buf;
//		ubyte[] slice = fs.getEntropy(buf);
//
//		assert(slice.length == buf.length, "No data read from /dev/urandom");
//		assert(any!"a != 0"(slice), "Got only zeros from /dev/urandom");
//	}
//}

@safe
public class FileEntropySource: EntropySource
{

	private string seedFile;
	private File inputFile;
	private uint delay = 250;

	/// Params:
	/// seedFile = The file to load the seed from and to store new seed.
	/// Throws: `ErrnoException` if the seed file can not be opened for reading.
	this(string seedFile)
	{
		this.seedFile = seedFile;
		inputFile = File(seedFile, "rb");
	}

	/// Read entropy from file.
	@trusted
	override public void collectEntropy() nothrow {

		ubyte[32] buf;
		ubyte[] slice = buf[0..0];

		if(inputFile.isOpen) {
			// get entropy
			try {

				slice = inputFile.rawRead(buf);

				if(slice.length < buf.length) {
					// No remaining data in file
					// disable scheduling

					delay = 0;
				}

			} catch (Exception e) {
				// TODO
				assert(false, "error reading entropy file");
			}
		} else {
			delay = 0; // disable scheduling
		}

		sendEntropyEvent(slice);
	}

	@nogc @property nothrow
	override public string name() {
		return "FileSource";
	}

	@safe @nogc nothrow
	override uint scheduleNext() {
		return delay;
	}

	
	~this() {
		if(inputFile.isOpen) {
			inputFile.close();
		}
	}
}

