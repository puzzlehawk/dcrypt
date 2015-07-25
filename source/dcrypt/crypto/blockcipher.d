module dcrypt.crypto.blockcipher;

/// Use this to check if type is a block cipher.
@safe
template isBlockCipher(T)
{
	enum bool isBlockCipher =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[0] block;
						T bc = T.init; // Can define
						string name = T.name;
						uint blockSize = T.blockSize;
						bc.start(true, cast(const ubyte[]) block, cast(const ubyte[]) block);	// init with secret key and iv
						uint len = bc.processBlock(cast (const ubyte[]) block, block);
						bc.reset();
					}));
}

@safe
public interface BlockCipher {

	
	@safe public:

	/**
	 * Initialize the cipher.
	 *
	 * Params:
	 * forEncryption	=	if true the cipher is initialised for
	 *  encryption, if false for decryption.
	 * userKey	=	A secret key.
	 * iv = A nonce.
	 */
	void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc;

	/**
	 * Return the name of the algorithm the cipher implements.
	 *
	 * Returns: the name of the algorithm the cipher implements.
	 */
	@property
	string name() pure nothrow;

	/**
	 * Return the block size for this cipher (in bytes).
	 *
	 * Returns: the block size for this cipher in bytes.
	 */
	@property
	uint blockSize() pure nothrow @nogc;

	/**
	 * Process one block of input from the array in and write it to
	 * the out array.
	 *
	 * Params:
	 *	input = the slice containing the input data.
	 *  output = the slice the output data will be copied into.
	 * Throws: IllegalStateException if the cipher isn't initialised.
	 * Returns: the number of bytes processed and produced.
	 */
	@nogc
	uint processBlock(in ubyte[] input, ubyte[] output) nothrow;

	/**
	 * Reset the cipher. After resetting the cipher is in the same state
	 * as it was after the last init (if there was one).
	 */
	@nogc
	void reset() nothrow;
}

@safe
public class BlockCipherWrapper(T) if(isBlockCipher!T): BlockCipher {

	private T cipher;

	@safe public:
	
	/**
	 * Initialize the cipher.
	 *
	 * Params:
	 *	forEncryption	=	if true the cipher is initialised for
	 *  encryption, if false for decryption.
	 *  params	=	the key and other data required by the cipher.
	 *
	 * Throws: IllegalArgumentException if the params argument is
	 * inappropriate.
	 */
	void start(bool forEncryption, in ubyte[] key, in ubyte[] iv = null) nothrow {
		cipher.start(forEncryption, key, iv);
	}
	
	/**
	 * Return the name of the algorithm the cipher implements.
	 *
	 * Returns: the name of the algorithm the cipher implements.
	 */
	@property
	string name() pure nothrow {
		return cipher.name;
	}
	
	/**
	 * Return the block size for this cipher (in bytes).
	 *
	 * Returns: the block size for this cipher in bytes.
	 */
	@property
	uint blockSize() pure nothrow @nogc {
		return T.blockSize;
	}
	
	/**
	 * Process one block of input from the array in and write it to
	 * the out array.
	 *
	 * Params:
	 *	input = the slice containing the input data.
	 *  output = the slice the output data will be copied into.
	 * Throws: IllegalStateException if the cipher isn't initialised.
	 * Returns: the number of bytes processed and produced.
	 */
	uint processBlock(in ubyte[] input, ubyte[] output) nothrow @nogc {
		return cipher.processBlock(input, output);
	}
	
	/**
	 * Reset the cipher. After resetting the cipher is in the same state
	 * as it was after the last init (if there was one).
	 */
	void reset() nothrow @nogc {
		cipher.reset();
	}
}

version(unittest) {
	
	// unittest helper functions

	
	/// Runs decryption and encryption using BlockCipher bc with given keys, plaintexts, and ciphertexts
	///
	/// Params:
	/// hexKeys	=	the keys encoded in hex
	/// hexPlaintexts	=	the plaintexts encoded in hex
	/// hexCiphertexts	=	the corresponding ciphertexts in hex
	///
	/// Throws:
	/// AssertionError	if encryption or decryption failed
	///
	@safe
	public void blockCipherTest(BlockCipher bc, string[] keys, string[] plaintexts, string[] cipherTexts, string[] ivs = null) {
		import dcrypt.util.encoders.hex;
		import std.conv: text;
		
		foreach (uint i, string test_key; keys)
		{
			ubyte[] buffer = new ubyte[bc.blockSize];


			const ubyte[] key = cast(const ubyte[]) test_key;
			const (ubyte)[] iv = null;
			if(ivs !is null) { 
				iv = cast(const (ubyte)[]) ivs[i]; 
			}

			// Encryption
			bc.start(true, key, iv);
			bc.processBlock(cast(const ubyte[]) plaintexts[i], buffer);
			
			assert(buffer == cipherTexts[i],
				text(bc.name, " encrypt: (", hexEncode(buffer), ") != (", hexEncode(cipherTexts[i]), ")"));
			
			// Decryption
			bc.start(false, key, iv);
			bc.processBlock(cast(const ubyte[]) cipherTexts[i], buffer);
			assert(buffer == plaintexts[i],
				text(bc.name, " decrypt: (", hexEncode(buffer),") != (", hexEncode(plaintexts[i]), ")"));
		}
	}
}