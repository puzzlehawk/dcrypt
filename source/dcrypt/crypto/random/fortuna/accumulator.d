module dcrypt.crypto.random.fortuna.accumulator;


import dcrypt.crypto.digests.sha2;
import dcrypt.crypto.digest;
import dcrypt.util.pack;

private enum minPoolSize = 64;	/// return empty entropy if pool0's size is < MINPOOLSIZE
private enum bufferSize = 32;	/// size of the output buffer and internal state

// Test shared and non-shared Accumulator
unittest {
	auto acc = new Accumulator;
	auto accShared = new shared Accumulator;

	ubyte[32] buf1;
	ubyte[32] buf2;

	foreach(i; 0..32) {

		acc.extractEntropy(buf1);
		accShared.extractEntropy(buf2);

		assert(buf1 == buf2, "Accumulator does not behave deterministically!");

		acc.addEntropy(0, i%Accumulator.pools, buf1);
		accShared.addEntropy(0, i%Accumulator.pools, buf2);
	}

	// change only one accumulator
	acc.addEntropy(0, 0, buf1);

	acc.extractEntropy(buf1);
	accShared.extractEntropy(buf2);
	
	assert(buf1 != buf2, "Outputs should be different!");
}



/**
 * This class is a core component of the Fortuna algorithm and is responsible for collecting
 * and accumulating entropy from various sources.
 */
@safe
package class Accumulator
{

	public enum pools = 32; // TODO 32 might be overkill

	alias SHA256 Digest; /// use SHA256 as digest
	
	nothrow @nogc:

	/// Returns: Amount of new seed bytes in pool0.
	@property
	uint freshEntropyLength() {
		return entropyPools[0].freshEntropy;
	}

	
	/// Multithreading aware version of `extractEntropy()`
	@safe
	synchronized void extractEntropy(ubyte[] buf)
	in {
		assert(buf.length == Digest.digestLength, "buffer size does not match digest size");
	}
	body {
		transaction(0, 0, null, buf);
	}
	
	/// Multithreading aware version of `addEntropy()`
	@safe
	synchronized void addEntropy(in ubyte sourceID, in size_t pool, in ubyte[] data) {
		transaction(sourceID, pool, data, null);
	}

	/**
	 * Params:
	 * reseedCount = Used to determine from which pools entropy should be fetched.
	 * buf = Write the seed in this buffer. Length must be `bufferSize`.
	 */
	void extractEntropy(ubyte[] buf)
	in {
		assert(buf.length == Digest.digestLength, "buffer size does not match digest size");
	}
	body {

		scope(exit) {
			counter++;
		}

		ubyte[Digest.digestLength] iBuf;

		foreach(i, pool; entropyPools) {
			if(counter % (1<<i) == 0) { // reseedCount divisible by 2^i ?
				pool.extractEntropy(iBuf);
				masterPool.addEntropy(iBuf);
			}else {
				// won't be divisible by 2^(i+1) either
				break;
			}
		}

		masterPool.extractEntropy(buf);
		
	}

	/// Accumulate an entropy event.
	/// 
	/// Params:
	/// sourceID = A number assigned to the source.
	/// pool = The pool to add the entropy. 0 <= pool < Accumulator.pools
	/// data = Entropy data.
	@safe
	void addEntropy(in ubyte sourceID, in size_t pool, in ubyte[] data...)
	in {
		assert(pool < pools, "Pool ID out of range.");
	}
	body {
		ubyte[5] iBuf; // contains sourceID and length of event data

		// pack sourceID and data.length in buffer
		iBuf[0] = sourceID;
		toLittleEndian(cast(uint)data.length, iBuf[1..5]);

		entropyPools[pool].addEntropy(iBuf);
		entropyPools[pool].addEntropy(data);
	}

	/// Provides synchronized access to the accumulator.
	/// Used to add entropy or to extract entropy or both at the same time.
	/// 
	/// Params:
	/// sourceID = the ID of the entropy source.
	/// pool = The pool to add the entropy.
	/// data = Entropy data. Can be `null`.
	/// buf = 32 bytes buffer for random data. Can also be `null`.
	@trusted
	private synchronized void transaction(in ubyte sourceID, in size_t pool, in ubyte[] data, ubyte[] buf = null) {
		if(data !is null) {
			(cast(Accumulator) this).addEntropy(sourceID, pool, data);
		}
		if(buf !is null) {
			(cast(Accumulator) this).extractEntropy(buf);
		}
	}

	private {
		EntropyPool!Digest[pools] entropyPools;
		EntropyPool!Digest masterPool;
		uint counter = 0; // count how many times extractEntropy() has been called
	}

	
}

@safe
private struct EntropyPool(Digest) 
if(isDigest!Digest && Digest.digestLength == bufferSize) {

	private  Digest accumulator;
	private  uint freshEntropyBytes = 0;
	
	nothrow @nogc:

	/// extract a block of entropy bits out of this pool.
	/// the internal state is not leaked.
	/// 
	/// Returns: The length of the extracted data.
	/// 
	/// TODO calls doFinal twice: could be a performance issue
	uint extractEntropy(ubyte[] oBuf)
	in {
		assert(oBuf.length >= accumulator.digestLength, "output buffer too small");
	}
	body {
		ubyte[bufferSize] iBuf;

		Digest temp = accumulator;

		accumulator.put(0x01, 0x02, 0x03, 0x04);

		// TODO return ubyte[]
		uint len = cast(ubyte)accumulator.finish(oBuf).length; // write to output buffer

		freshEntropyBytes = 0; // out of fresh entropy

		accumulator = temp;	// reset to previous state

		return len;
	}
	
	/// accumulate some bytes in the entropy pool
	/// Params:
	/// b = the entropy to add
	void addEntropy(in ubyte[] b...) {
		accumulator.put(b);
		freshEntropyBytes += b.length;
	}

	/// Returns: the number of bytes that have flown in this pool since the last call of extractEntropy().
	@property
	uint freshEntropy() {
		return freshEntropyBytes;
	}
}


// Test cloning of a digest.
private unittest {

	SHA256 d1;
	SHA256 d2;

	ubyte[d1.digestLength] buf1;
	ubyte[d2.digestLength] buf2;

	d1.put(0x01);
	d2.put(0x02);
	d2 = d1;
	d1.finish(buf1);

	d1 = d2;

	d1.finish(buf1);
	d2.finish(buf2);

	assert(buf1 == buf2, "Cloning digests does not work properly.");

}