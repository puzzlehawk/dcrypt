module dcrypt.crypto.random.fortuna.generator;

import std.range: chunks;

import dcrypt.crypto.random.prng;
import dcrypt.crypto.blockcipher;
import dcrypt.crypto.digest;
import dcrypt.crypto.params.keyparameter;

///	generate a deterministic PRNG sequence
@safe unittest {
	import dcrypt.crypto.engines.aes;
	import dcrypt.crypto.digests.sha2;

	FortunaGenerator!(AES, SHA256) prng;
	prng.addSeed([0]);

	ubyte[71] random;
	prng.nextBytes(random);

	assert(random == x"2fd720d5d7f93dc8371586ae8c09547095613e2cf8967206f8d16d5717cf15a53beae29b2cf9fc0443ae6c37fd1f11aefb13061415c4d5f27d876cb67a63ba592af029f0447815",
		"Unexpected output of deterministic PRNG.");

	ubyte[random.length] random2;

	prng.nextBytes(random2);

	assert(random != random2, "PRNG produced twice the same data!");
}

// Test if FortunaGenerator fullfills requirements to be a PRNG.
import dcrypt.crypto.engines.aes;
import dcrypt.crypto.digests.sha2;
static assert(isRNG!(FortunaGenerator!(AES, SHA256)), "FortunaGenerator violates requirements of isPRNG!");



/// This PRNG forms a base component of the Fortuna PRNG as proposed by Bruce Schneier & Niels Ferguson (PRNG with input).
/// The Generator can be used stand alone as deterministic PRNG (DRNG). It won't gather entropy on its own and
/// provided with the same seed it will always generate the same sequence of bytes for the same underlying 
/// block cipher and hash algorithm.
/// 
/// Note: Generator MUST be seeded before generating pseudo random data either with `addSeed()` or by passing the seed to the constructor.
/// 
/// Params:
/// Cipher = defines the underlying block cipher algorithm.
/// Digest = Underlying hash algorithm. Hash length has to be 256 bits (corresponds to used key size).
@safe
public struct FortunaGenerator(Cipher, Digest) if(isBlockCipher!Cipher && isDigest!Digest && Digest.digestLength == 32)
{
	// PRNG interface implementation
	public nothrow {

		this(ubyte[] seed...) @nogc {
			addSeed(seed);
		}

		enum isDeterministic = true;
		enum name = "FortunaGenerator/"~Cipher.name~"-"~Digest.name; /// Name of the PRNG algorithm.

		/// Fill an arbitrary-size buffer with random data.
		void nextBytes(ubyte[] buf) @nogc {
			// pseudoRandomData won't generate more data than reseedLimit at once, so call it multiple times if necessary.
			foreach(chunk; chunks(buf, reseedLimit)) {
				pseudoRandomData(chunk);
			}
		}
		
		/// add entropy to the generator
		void addSeed(in ubyte[] seed...) @nogc {
			reseed(seed);
		}

	}

	private {
		enum reseedLimit = 1<<20;			/// Force a reseed after generating this amount of bytes.
		enum blockSize = Cipher.blockSize;
		
		ubyte[blockSize] counter;			/// Counter for CTR mode.
		ubyte[blockSize] internalBuffer;	
		ubyte[32] key;						/// Secret encryption key.
		
		Cipher cipher;
		Digest digest;

		bool initialized = false;
	}

	private nothrow {

		/// compute a new key: newKey = Hash(oldKey | seed)
		void reseed(in ubyte[] seed...) @nogc {
			digest.put(key);
			digest.put(seed);
			digest.finish(key);

			updateKey();

			incrementCounter();

			initialized = true;
		}

		/// inits cipher with the current key
		void updateKey () @nogc {
			cipher.start(true, key);
		}

		/// increment the counter by 1
		void incrementCounter() @nogc {
			for (uint i = 0; i < counter.length; i++) {
				counter[i]++;
				if (counter[i] != 0) {
					break;
				}
			}
		}

		/**
		 * Fill buffer with pseudo random blocks.
		 * 
		 * Params:
		 * buffer =	Fill this buffer with pseudo random blocks. Length must be multiple of blockSize (probably 16 or 32).
		 */
		void generateBlocks(ubyte[] buffer) @nogc
		in {
			assert(buffer.length % blockSize == 0, 
				"invalid input buffer size, multiple of blockSize required");
			assert(initialized, "PRNG not yet initalized. Call `addSeed()` first.");
		}
		body {
			foreach(chunk; chunks(buffer, blockSize)) {
				cipher.processBlock(counter, chunk);
				incrementCounter();
			}
		}

		/**
		 * Fill the buffer with pseudo random data. Buffer size is limitet to 2^20 bytes.
		 * 
		 * Params:
		 * buffer = buffer for PRNG data
		 */
		void pseudoRandomData(ubyte[] buffer) @nogc
		in {
			assert(buffer.length <= reseedLimit, "won't generate more than reseedLimit bytes in one request");
		}
		body {
			scope(exit) {	// ensure that the key is changed after each request
				generateBlocks(key);
				updateKey();
			}

			immutable size_t remaining = buffer.length % blockSize;
			generateBlocks(buffer[0..$-remaining]);

			if(remaining) {
				generateBlocks(internalBuffer);
				scope(exit) {
					internalBuffer[] = 0; // wipe the buffer on exit
				}

				buffer[$-remaining..$] = internalBuffer[0..remaining];
			}
		}
	}

	~this() {
		import dcrypt.util.util: wipe;

		wipe(key);
		wipe(counter);
		wipe(internalBuffer);
	}
}