module dcrypt.crypto.bufferedblockcipher;

import dcrypt.crypto.blockcipher;
import dcrypt.crypto.modes.ctr;
import std.algorithm: min;

unittest {
	import dcrypt.crypto.engines.aes;
	import dcrypt.util.encoders.hex;
	import std.stdio;
	
	BufferedBlockCipher!AES bbc;
	bbc.init(true, new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")));
	
	ubyte[] plain = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
	plain ~= plain;
	ubyte[] cipher = Hex.decode("3ad77bb40d7a3660a89ecaf32466ef97");
	cipher ~= cipher;
	
	ubyte[] output = new ubyte[32];
	
	uint len = 0;
	len += bbc.processBytes(plain[0..0], output[len..$]);
	len += bbc.processBytes(plain[0..1], output[len..$]);
	len += bbc.processBytes(plain[1..7], output[len..$]);
	len += bbc.processBytes(plain[7..14], output[len..$]);
	assert(len == 0);
	len += bbc.processBytes(plain[14..20], output[len..$]);
	assert(len == 16);
	
	assert(output[0..16] == cipher[0..16], "BufferedBlockCipher failed");
	
	// feed it with single bytes
	foreach(b; plain[20..$]) {
		len += bbc.processByte(b, output[len..$]);
	}
	assert(output == cipher, "BufferedBlockCipher.processByte(...) failed");
}

/// test buffered AES/CTR encryption
/// test vectors: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
@safe
unittest {
	import dcrypt.crypto.engines.aes;
	import dcrypt.crypto.modes.ctr;
	import dcrypt.crypto.modes.cbc;
	import dcrypt.crypto.params.keyparameter;
	import std.range;
	import std.conv: text;

	BufferedBlockCipher!(CTR!AES) cipher;
	
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
	cipher.init(true, new ParametersWithIV(key, iv));

	ubyte[plain.length] buf;

	size_t len;
	len = cipher.processBytes(plain, buf);
	len += cipher.doFinal(buf[len..$]);
	assert(len == plain.length);
	
	assert(buf == expected_ciphertext, text(cipher.getAlgorithmName,": encryption failed"));
	
	// decryption mode
	cipher.init(false, new ParametersWithIV(key, iv));
	
	len = cipher.processBytes(buf, buf);
	len += cipher.doFinal(buf[len..$]);
	assert(len == plain.length);
	
	assert(buf == plain, text(cipher.getAlgorithmName,": decryption failed"));
	
}

/// test buffered AES/CTR encryption with incomplete last block
/// test vectors: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
@safe
unittest {
	import dcrypt.crypto.engines.aes;
	import dcrypt.crypto.modes.ctr;
	import dcrypt.crypto.modes.cbc;
	import dcrypt.crypto.params.keyparameter;
	import std.range;
	import std.conv: text;
	
	BufferedBlockCipher!(CTR!AES, true) cipher; // true: allow partial block
	
	const ubyte[] key = cast(const ubyte[])x"2b7e151628aed2a6abf7158809cf4f3c";
	const ubyte[] iv = cast(const ubyte[])x"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	
	const ubyte[] plain = cast(const ubyte[])x"
		6bc1bee22e409f96e93d7e117393172a
		ae2d8a571e03ac9c9eb76fac45af8e51
		30c81c46a35ce411e5fbc1191a0a52ef
		f69f2445df4f9b17
	";
	
	const ubyte[] expected_ciphertext = cast(const ubyte[])x"
		874d6191b620e3261bef6864990db6ce
		9806f66b7970fdff8617187bb9fffdff
		5ae4df3edbd5d35e5b4f09020db03eab
		1e031dda2fbe03d1
	";
	
	
	// encryption mode
	cipher.init(true, new ParametersWithIV(key, iv));
	
	ubyte[plain.length] buf;
	
	size_t len;
	len = cipher.processBytes(plain, buf);
	len += cipher.doFinal(buf[len..$]);
	assert(len == plain.length);
	
	assert(buf == expected_ciphertext, text(cipher.getAlgorithmName,": encryption failed"));
	
	// decryption mode
	cipher.init(false, new ParametersWithIV(key, iv));
	
	len = cipher.processBytes(buf, buf);
	len += cipher.doFinal(buf[len..$]);
	assert(len == plain.length);
	
	assert(buf == plain, text(cipher.getAlgorithmName,": decryption failed"));
	
}

///
/// test if T is a block cipher
///
@safe
template isBufferedBlockCipher(T)
{
	enum bool isBufferedBlockCipher =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[0] block;
						T bc = void;
						string name = bc.getAlgorithmName();
						uint blockSize = T.blockSize;
						bc.init(true, new KeyParameter([]));
						uint len = bc.processByte(cast(ubyte)0,block);
						uint len = bc.processBytes(block, block);
						uint len = bc.doFinal(block);
						bc.reset();
					}));
}

///
///	Params:
///	T = a block cipher or a block cipher combined with a mode (CTR, CBC, ...)
///	permitPartialBlock = tells wether the underlying cipher supports a partial last block (CTR does). default: false
///
///	Examples:
///	BufferedBlockCipher!AES) ecbEncryption;
/// BufferedBlockCipher!(CTR!AES, true) ctrEncryption;
/// 
@safe
public struct BufferedBlockCipher(Cipher, bool permitPartialBlock = false) if(isBlockCipher!Cipher)
{
	public {

		enum blockSize = Cipher.blockSize;

		void init(bool forEncryption, KeyParameter params) nothrow {
			cipher.init(forEncryption, params);
		}

		@property
		string getAlgorithmName() pure nothrow {
			return cipher.name;
		}

		void reset() nothrow {
			cipher.reset();
			buf[] = 0;
			bufOff = 0;
		}

		/**
		 * takes one byte and stores it in a buffer. Only if the buffer is full it gets encrypted
		 * and the cipher text gets written to output.
		 * 
		 * Params:
		 * b	=	the byte to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		@nogc
		uint processByte(in ubyte b, ubyte[] output) nothrow
		in {
			assert(bufOff < buf.length, "bufOff can't be larger than buf.length");
			assert(output.length >= buf.length, "output buffer too small");
		}
		body {
			buf[bufOff] = b;
			++bufOff;

			if(bufOff == buf.length) {
				bufOff = 0;
				return cipher.processBlock(buf, output);
			}
			return 0;
		}

		/**
		 * encrypt or decrypt byte array
		 * 
		 * Params:
		 * i	=	the bytes to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		@nogc
		uint processBytes(in ubyte[] i, ubyte[] output) nothrow
		in {
			assert(output.length >= bufOff + i.length, "output buffer too small");
		}
		body {
			uint outLen = 0;

			const(ubyte)[] input = i;

			if(bufOff > 0) {
				// fill the buffer and process it if full
				uint remainingBuf = cast(uint)(buf.length)-bufOff;
				uint len = min(remainingBuf, input.length);

				buf[bufOff..bufOff + len] = input[0..len];
				bufOff += len;

				// drop used input bytes
				input = input[len..$];

				if(bufOff == buf.length) {
					// block is full, process it
					bufOff = 0;

					len = cipher.processBlock(buf, output);
					output = output[len..$];
					outLen += len;
				}
			}

			while (input.length >= buf.length) {
				assert(bufOff == 0, "blocks not aligned");

				uint len = cipher.processBlock(input[0..buf.length], output); 
				
				assert(len == buf.length); // this can be assumed. TODO: replace len with blockSize

				input = input[len..$];
				output = output[len..$];
				outLen += len;
			}

			// still some remaining bytes?
			if(input.length > 0){
				assert(input.length < buf.length);

				buf[0..input.length] = input[]; // copy remaining data into buffer
				bufOff += cast(uint)input.length; // cast is safe, because length has to be smaller than blocksize
			}

			return outLen;
		}

		///
		/// encrypt the remaining bytes in the buffer
		///
		///	Params: output = output buffer
		/// Returns: number of written bytes
		uint doFinal(ubyte[] output)
		in {
			if(permitPartialBlock) {
				assert(output.length >= bufOff, "output buffer too small");
			}else if (bufOff > 0) {
				assert(output.length >= buf.length, "output buffer too small");
			}
		}

		body {
			scope(success) {reset();} // ensure reset() is called after successful encryption/decryption

			uint outLen = 0;
			if(bufOff != 0) {
				buf[bufOff..$] = 0; // don't encrypt old bytes
				cipher.processBlock(buf, buf);

				static if(permitPartialBlock) {
					output[0..bufOff] = buf[0..bufOff]; // copy partial block
				} else {
					output[0..buf.length] = buf[]; // copy full block
				}

				outLen = bufOff;
			}
			return outLen;
		}

		
		/// Returns: the BlockCipher passed once to the constructor.
		ref Cipher getUnderlyingCipher() nothrow @nogc {
			return cipher;
		}
	}

	protected {
		Cipher cipher; /// the underlying block cipher
		ubyte[blockSize] buf; /// buffer for incomplete blocks
		uint bufOff = 0; /// where the next byte get added to the buffer (i.e. buf[bufOff++] = newByte)
	}

	private {
		invariant {
			// there's no reason for the offset to be larger than the buffer length
			assert(bufOff <= buf.length, "bufOff can't be larger than buf.length");
		}
	}
}

@safe
public interface IBufferedBlockCipher
{
	
	public {
		
		void init(bool forEncryption, KeyParameter params) nothrow;
		
		@property
		string name() pure nothrow;
		
		@property
		uint blockSize() pure nothrow;
		
		void reset() nothrow;
		
		/**
		 * takes one byte and stores it in a buffer. Only if the buffer is full it gets encrypted
		 * and the cipher text gets written to output.
		 * 
		 * Params:
		 * b	=	the byte to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		uint processByte(in ubyte b, ubyte[] output) nothrow @nogc;
		
		/**
		 * Params:
		 * i	=	the bytes to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		uint processBytes(in ubyte[] i, ubyte[] output) nothrow @nogc;
		
		/**
		 * encrypt the remaining bytes in the buffer
		 */
		uint doFinal(ubyte[] output) nothrow @nogc;
		
	}
	
}

/// wrapper class for BufferedBlockCipher
@safe
public class BufferedBlockCipherWrapper(T) if(isBlockCipher!T): IBufferedBlockCipher
{

	private BufferedBlockCipher!T cipher;

	public {
		
		void init(bool forEncryption, KeyParameter params) nothrow {
			cipher.init(forEncryption, params);
		}
		
		@property
		string getAlgorithmName() pure nothrow {
			return cipher.getAlgorithmName();
		}
		
		@property
		uint blockSize() pure nothrow {
			return cipher.blockSize();
		}
		
		void reset() nothrow {
			cipher.reset();
		}
		
		/**
		 * takes one byte and stores it in a buffer. Only if the buffer is full it gets encrypted
		 * and the cipher text gets written to output.
		 * 
		 * Params:
		 * b	=	the byte to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		@nogc
		uint processByte(in ubyte b, ubyte[] output) nothrow
		{
			return cipher.processByte(b,output);
		}
		
		/**
		 * Params:
		 * i	=	the bytes to encrypt
		 * output	=	the output buffer
		 * 
		 * Returns: the number of bytes written to output. Will be 0 or BLOCKSIZE of underlying cipher.
		 */
		@nogc
		uint processBytes(in ubyte[] i, ubyte[] output) nothrow
		{
			return processBytes(i, output);
		}
		
		/**
		 * encrypt the remaining bytes in the buffer
		 */
		uint doFinal(ubyte[] output)
		{
			cipher.doFinal(output);
		}
		
		/**
		 * Returns: the BlockCipher passed once to the constructor.
		 */
		ref T getUnderlyingCipher() nothrow @nogc {
			return cipher.getUnderlyingCipher();
		}
	}

}