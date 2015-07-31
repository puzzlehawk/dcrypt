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

		acc.addEntropy(0,buf1);
		accShared.addEntropy(0,buf2);
	}

	// change only one accumulator
	acc.addEntropy(0, buf1);

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
		transaction(0, null, buf);
	}
	
	/// Multithreading aware version of `addEntropy()`
	@safe
	synchronized void addEntropy(in ubyte sourceID, in ubyte[] data) {
		transaction(sourceID, data, null);
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
				//digest.put(iBuf);
			}else {
				// won't be divisible by 2^(i+1) either
				break;
			}
		}

		/// check if `iBuf` is changed. `iBuf` beeing filled with 0s means that very likely something went wrong.
		assert(std.algorithm.any!"a != 0"(iBuf[]), "No fresh entropy from pools!");

//		// TODO simplify
//		digest.doFinal(iBuf);	// extracted entropy from pools
//
//		// Hash twice to avoid leaking accumulator state.
//		// This is important if more than one Fortuna instance get their entropy from this accumulator.
//		// `iBuf` does not get leaked.
//		digest.put(0x01);
//		digest.put(iBuf);
//		digest.put(0x01);
//		digest.doFinal(buf);	// this is the new seed / output
//
//		digest.put(iBuf);		// feed back to conserve entropy

		masterPool.extractEntropy(buf);
		
	}

	/// Accumulate an entropy event.
	/// 
	/// Params:
	/// sourceID = A number assigned to the source.
	/// data = Entropy data.
	void addEntropy(in ubyte sourceID, in ubyte[] data...)
	{
		ubyte[5] iBuf; // contains sourceID and length of event data

		// pack sourceID and data.length in buffer
		iBuf[0] = sourceID;
		toLittleEndian(cast(uint)data.length, iBuf[1..5]);

		import std.range: chain, chunks;

		entropyPools[pool].addEntropy(iBuf);

		// Distribute the event onto multiple pools.
		foreach(c; data.chunks(8)) {
			entropyPools[pool].addEntropy(c); // write a chunk into a pool
			pool = (pool+1) % POOLS; // FIXME fill pool in random order not round robin
		}
	}

	/// Provides synchronized access to the accumulator.
	/// Used to add entropy or to extract entropy or both at the same time.
	/// 
	/// Params:
	/// sourceID = the ID of the entropy source.
	/// data = Entropy data. Can be `null`.
	/// buf = 32 bytes buffer for random data. Can also be `null`.
	@trusted
	private synchronized void transaction(in ubyte sourceID, in ubyte[] data, ubyte[] buf = null) {
		if(data !is null) {
			(cast(Accumulator) this).addEntropy(sourceID, data);
		}
		if(buf !is null) {
			(cast(Accumulator) this).extractEntropy(buf);
		}
	}

	private {
		enum POOLS = 32; // TODO 32 might be overkill
		EntropyPool!Digest[POOLS] entropyPools;
		EntropyPool!Digest masterPool;
		uint pool = 0;
		uint counter = 0; // count how many times extractEntropy() has been called
	}

	invariant {
		assert(pool < POOLS);
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

		accumulator.doFinal(iBuf);
		accumulator.put(iBuf);
		uint len = accumulator.doFinal(oBuf); // write to output buffer

		accumulator.put(iBuf); // seed with old state (which is newer leaked outside of EntropyPool)
		accumulator.put(0x01);

		freshEntropyBytes = 0; // out of fresh entropy

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