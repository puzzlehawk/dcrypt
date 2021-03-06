module dcrypt.blockcipher.modes.ctr;

import dcrypt.blockcipher.blockcipher;



/// test AES/CTR encryption
/// test vectors: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
@safe
unittest {
	import dcrypt.blockcipher.aes;
	import std.range;
	import std.conv: text;

	CTR!AES ctr;

	const ubyte[] key = cast(const ubyte[])x"2b7e151628aed2a6abf7158809cf4f3c";
	const ubyte[] iv = cast(const ubyte[])x"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

	const ubyte[] plain = cast(const ubyte[])x"
		6bc1bee22e409f96e93d7e117393172a
		ae2d8a571e03ac9c9eb76fac45af8e51
		30c81c46a35ce411e5fbc1191a0a52ef
		f69f2445df4f9b17ad2b417be66c3710
	";

	const ubyte[] expected_ciphertext = cast(const ubyte[])x"
		874d6191b620e3261bef6864990db6ce
		9806f66b7970fdff8617187bb9fffdff
		5ae4df3edbd5d35e5b4f09020db03eab
		1e031dda2fbe03d1792170a0f3009cee
	";


	// encryption mode
	ctr.start(true, key, iv);

	ubyte[plain.length] buf;
	buf = plain;

	foreach(block; chunks(buf[],16)) {
		ctr.processBlock(block,block);
	}

	assert(buf == expected_ciphertext, text(ctr.name,": encryption failed"));

	// decryption mode
	ctr.start(false, key, iv);

	foreach(block; chunks(buf[],16)) {
		ctr.processBlock(block,block);
	}
	
	assert(buf == plain, text(ctr.name,": decryption failed"));

}

// OOP API wrapper
alias CTRBlockCipher(T) = BlockCipherWrapper!(CTR!T);

@safe
public struct CTR(Cipher) if(isBlockCipher!Cipher) {

	public enum blockSize = Cipher.blockSize;
	public enum name = Cipher.name ~ "/CTR";

	private {
		ubyte[blockSize] counter;
		ubyte[blockSize] nonce;
		ubyte[blockSize] buf;

		Cipher cipher;
	}

	/// Params:
	/// forEncryption = Does not matter for CTR because encryption and decryption is the same in this mode.
	/// userKey = secret key
	/// iv = initialisation vector
	public void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv)
	in {
		assert(iv !is null, "CTR without IV is not supported.");
		// does the IV match the block size?
		assert(iv.length == blockSize, "length of IV has to be the same as the block size");
	}
	body {
		cipher.start(true, userKey);
		nonce[] = iv[];
		reset();
	}

	public void reset() nothrow @nogc {
		cipher.reset();
		counter[0..blockSize] = nonce[0..blockSize];
	}

	public uint processBlock(in ubyte[] input, ubyte[] output) nothrow @nogc
	in {
		assert(input.length == blockSize, "CTR: input.length != blockSize");
		assert(output.length >= blockSize, "CTR: output buffer too small");
	}
	body {

		// encrypt counter
		cipher.processBlock(counter, buf);

		// xor input and key stream
		output[0..blockSize] = input[]^buf[]; // byte wise xor

		// increment counter

		for(uint i = blockSize -1; i >= 0; --i) {
			if(++counter[i] != 0) {
				break;
			}
			// increment next element on overflow of the previous
		}

		return blockSize;
	}

}