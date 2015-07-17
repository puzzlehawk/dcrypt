module dcrypt.crypto.modes.cbc;

import std.algorithm: fill;
import dcrypt.crypto.blockcipher;
import dcrypt.crypto.params.keyparameter;
import dcrypt.errors, dcrypt.exceptions;


/// test AES/CBC encryption
/// test vectors: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
@safe
unittest {
	import dcrypt.crypto.engines.aes;
	import std.range;
	import std.conv: text;
	
	CBC!AES cbc;
	
	const ubyte[] key = cast(const ubyte[])x"2b7e151628aed2a6abf7158809cf4f3c";
	const ubyte[] iv = cast(const ubyte[])x"000102030405060708090a0b0c0d0e0f";
	
	const ubyte[] plain = cast(const ubyte[])x"
		6bc1bee22e409f96e93d7e117393172a
		ae2d8a571e03ac9c9eb76fac45af8e51
		30c81c46a35ce411e5fbc1191a0a52ef
		f69f2445df4f9b17ad2b417be66c3710
	";
	
	const ubyte[] expected_ciphertext = cast(const ubyte[])x"
		7649abac8119b246cee98e9b12e9197d
		5086cb9b507219ee95db113a917678b2
		73bed6b8e3c1743b7116e69e22229516
		3ff1caa1681fac09120eca307586e1a7
	";
	
	
	// encryption mode
	cbc.start(true, key, iv);
	
	ubyte[plain.length] buf;
	buf = plain;
	
	foreach(block; chunks(buf[],16)) {
		cbc.processBlock(block,block);
	}
	
	assert(buf == expected_ciphertext, text(cbc.name,": encryption failed"));
	
	// decryption mode
	cbc.start(false, key, iv);
	
	foreach(block; chunks(buf[],16)) {
		cbc.processBlock(block,block);
	}
	
	assert(buf == plain, text(cbc.name,": decryption failed"));
	
}

// OOP API wrapper
alias CBCBlockCipher(T) = BlockCipherWrapper!(CBC!T);

/**
 * implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
 */
@safe
public struct CBC(Cipher) if(isBlockCipher!Cipher)
{
	public enum blockSize = Cipher.blockSize;
	public enum name = Cipher.name ~ "/CBC";

	private{
		ubyte[blockSize]	cbcV;
		ubyte[blockSize]	cbcNextV;
		ubyte[blockSize]	IV;			// IV as provided by user.

		Cipher		cipher;
		bool		forEncryption;
		bool		initialized = false;
	}

	
	/**
	 * return the underlying block cipher that we are wrapping.
	 *
	 * Returns the underlying block cipher that we are wrapping.
	 */
	ref Cipher getUnderlyingCipher() pure nothrow
	{
		return cipher;
	}

	
	/// Initialize the cipher and, possibly, the initialization vector (IV).
	///
	/// Params: 
	/// forEncryption = if true the cipher is initialized for encryption, if false for decryption.
	/// params = the key and other data required by the cipher.
	public void start(bool forEncryption, KeyParameter keyParam) nothrow
	in {
		assert(keyParam !is null, "Nullpointer!");
	}
	body {

		if (ParametersWithIV ivParam = cast(ParametersWithIV) keyParam)
		{
			start(forEncryption, ivParam.getKey(), ivParam.getIV());
		}
		else
		{
			start(forEncryption, keyParam.getKey());
		}
	}

	
	/// Initialize the cipher and, possibly, the initialization vector (IV).
	/// If the cipher is already initialized a new IV can be set without the overhead
	/// of a new key setup: init(forEncryption, null, newIV)
	/// 
	/// Params: 
	/// forEncryption = if true the cipher is initialized for encryption, if false for decryption.
	/// params = the key and other data required by the cipher.
	public void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc 
	in {
		//assert(iv !is null, "CBC without IV not supported!");
		assert(iv is null || iv.length == blockSize, "Length ov IV does not match block size!");
	}
	body {

		bool oldMode = this.forEncryption;
		this.forEncryption = forEncryption;

		if(userKey is null) {
			// possible to change iv overhead of new key setup
			assert(initialized, "cipher not initialized");
			assert(forEncryption == oldMode, "Cant switch between encryption and decryption without providing a new key.");

			IV[] = iv[];
		} else {
			
			cipher.start(forEncryption, userKey);
			
			if(iv !is null) {
				IV[] = iv[];
			} else {
				IV[] = 0;
			}
		}
		initialized = true;
		reset();
	}

	/**
	 * Process one block of input from the array in and write it to
	 * the out array.
	 *
	 * Params
	 * input = the array containing the input data.
	 * output = the array the output data will be copied into.
	 * Returns: the number of bytes processed and produced.
	 */
	public uint processBlock(in ubyte[] input, ubyte[] output)
	in {
		assert(input.length == blockSize, "input.length != blockSize");
		assert(output.length >= blockSize, "output buffer too small");
		assert(initialized, "cipher not initialized");
	}
	body {
		return (forEncryption) ? encryptBlock(input, output) : decryptBlock(input, output);
	}

	/**
	 * reset the chaining vector back to the IV and reset the underlying
	 * cipher.
	 */
	public void reset() nothrow
	in {
		assert(initialized, "cipher not initialized");
	}
	body {
		cbcV[] = IV[];
		cbcNextV[] = 0; // fill with zeros
		cipher.reset();
	}

	private nothrow @nogc @safe:

	/**
	 * Do the appropriate chaining step for CBC mode encryption.
	 *
	 * Params
	 * input = the array containing the input data.
	 * output = the array the output data will be copied into.
	 * Returns: the number of bytes processed and produced.
	 */
	uint encryptBlock(in ubyte[] input, ubyte[] output)
	in {
		assert(input.length >= blockSize, "input buffer too short");
		assert(output.length >= blockSize, "output buffer too short");
		assert(initialized, "cipher not initialized");
	}
	body {
		/*
		 * XOR the cbcV and the input,
		 * then encrypt the cbcV
		 */
		cbcV[0..blockSize] ^= input[0..blockSize];

		uint length = cipher.processBlock(cbcV,output);

		/*
		 * copy ciphertext to cbcV
		 */

		cbcV[] = output[0..cbcV.length];

		return length;
	}

	/**
	 * Do the appropriate chaining step for CBC mode decryption.
	 *
	 * Params
	 * input = the array containing the input data.
	 * output = the array the output data will be copied into.
	 * Returns: the number of bytes processed and produced.
	 */
	uint decryptBlock(in ubyte[] input, ubyte[] output)
	in {
		assert(input.length >= blockSize, "input buffer too short");
		assert(output.length >= blockSize, "output buffer too short");
		assert(initialized, "cipher not initialized");
	}
	body  {

		cbcNextV[0..blockSize] =  input[0..blockSize];

		uint length = cipher.processBlock(input, output);

		/*
		 * XOR the cbcV and the output
		 */
		output[] ^= cbcV[];

		/*
		 * swap the back up buffer into next position
		 */
		ubyte[]  tmp;

		tmp = cbcV;
		cbcV = cbcNextV;
		cbcNextV = tmp;

		return length;
	}
}
