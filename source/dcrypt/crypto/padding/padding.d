module dcrypt.crypto.padding.padding;

public import dcrypt.exceptions: InvalidCipherTextException;
public import dcrypt.crypto.blockcipher;

///
/// test if T is a block cipher padding
///
@safe
template isBlockCipherPadding(T)
{
	enum bool isBlockCipherPadding =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[] block;
						T padding = void; //Can define
						string name = T.name;
						padding.addPadding(block, cast(uint) 0);
						uint padcount = padding.padCount(block);
					}));
}

// TODO test vectors, doFinal() require minimal output buffer length
/// Test PaddedBufferedBlockCipher with AES and PKCS7 padding.
@safe
unittest {
	import dcrypt.crypto.padding.pkcs7;
	import dcrypt.crypto.engines.aes;
	
	PaddedBufferedBlockCipher!(AES, PKCS7Pad) c;
	
	immutable ubyte[] key = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	ubyte[] plain = new ubyte[65];
	ubyte[] output = new ubyte[96];
	
	foreach(plainTextLength; [0,1,15,16,17,24,31,32,33,63,64,65]) { // some odd number, smaller than one block, larger than two blocks
		
		plain.length = plainTextLength;
		
		foreach(i,ref b; plain) {
			b = cast(ubyte)i;
		}
		
		output.length = ((plainTextLength/c.blockSize)+2)*c.blockSize; // next even block size
		
		c.start(true, key);
		
		size_t len = c.processBytes(plain, output);
		len += c.doFinal(output[len..$]);
		output = output[0..len]; // crop slice to its size
		
		ubyte[] cipher = output.dup;
		output[] = 0;
		c.start(false, key);
		len = c.processBytes(cipher, output);
		len += c.doFinal(output[len..$]);
		
		assert(len == plain.length, "length does not match");
		assert(output[0..len] == plain, "decrypted ciphertext is not equal to original plaintext");
	}
}

///
/// PaddedBufferedBlockCipher extends a block cipher or mode (CTR, CBC, ...) by
/// the ability to process data that is not a multiple of the block size.
/// The last block will be padded according to the chosen padding scheme. If the
/// last block is full, then a additional padding block will be appended.
/// 
@safe
public struct PaddedBufferedBlockCipher(C, Padding, bool permitPartialBlock = false)
	if(isBlockCipher!C && isBlockCipherPadding!Padding)
{

	public enum blockSize = C.blockSize;
	public enum name = C.name ~ "/" ~ Padding.name;

	public {
		
		void start(bool forEncryption, in ubyte[] key, in ubyte[] iv = null) nothrow @nogc {
			this.forEncryption = forEncryption;
			cipher.start(forEncryption, key, iv);
			reset();
		}
		
		/**
		 * takes one byte and stores it in a buffer. If the buffer is already full it gets
		 * encrypted and written to output
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
			assert(bufOff < blockSize, "bufOff can't be larger than buf.length");
			assert(output.length >= blockSize, "output buffer too small");
		}
		body {
			uint outLen = 0;
			
			if(bufOff == blockSize) {
				bufOff = 0;
				outLen = cipher.processBlock(buf, output);
			}
			buf[bufOff] = b;
			++bufOff;
			
			return outLen;
		}
		
		/**
		 * input length not limited to multiples of block size.
		 * ensure that length of output buffer is sufficiently large (see below).
		 * 
		 * Params:
		 * i	=	the input data
		 * output	=	the output buffer. this buffer must be able to hold the
		 * same amount of data as given by the input + padding bytes.
		 * output.length >= i.length rounded up to the next multiple of block size
		 * 
		 */
		@nogc
		uint processBytes(in ubyte[] i, ubyte[] output) nothrow
		in {
			assert(bufOff < blockSize, "bufOff can't be larger than buf.length");
			assert(output.length >= bufOff + i.length, "output buffer too small");
		}
		body {
			uint outLen = 0;
			
			const(ubyte)[] input = i;
			
			uint remainingBuf = blockSize-bufOff;
			
			if(input.length > remainingBuf) {
				// fill the buffer and process it if full
				
				buf[bufOff..bufOff + remainingBuf] = input[0..remainingBuf];
				bufOff += remainingBuf;
				// drop used input bytes
				input = input[remainingBuf..$];
				
				// process the now full buffer
				assert(bufOff == blockSize);
				uint len = cipher.processBlock(buf, output); 
				output = output[len..$];
				outLen += len;
				bufOff = 0;
				
				// got some more complete blocks?
				while (input.length > blockSize) {
					len = cipher.processBlock(input[0..blockSize], output);
					
					assert(len == blockSize); // this can be assumed.
					
					input = input[blockSize..$];
					output = output[blockSize..$];
					outLen += blockSize;
				}
			}
			assert(input.length <= blockSize-bufOff); // it should not be possible to have now more bytes than the buffer can take
			
			// still some remaining bytes?
			if(input.length > 0){
				buf[bufOff..bufOff+input.length] = input[];
				bufOff += cast(uint)input.length; // cast is safe, because length has to be smaller than blocksize
			}
			
			return outLen;
		}
		
		/**
		 * encrypt the remaining bytes in the buffer, add the padding
		 * 
		 * Params: output = output buffer. length should be 2*blockSize
		 */
		uint doFinal(ubyte[] output)
		in {
			
			assert(output.length >= buf.length, "output buffer too small");
			
			if(forEncryption){
				assert(output.length >= 2*blockSize, "output buffer too small. 2*blockSize required, because possibly appending one full padding block");
			}else{
				assert(bufOff == blockSize, "last block incomplete for decryption");
			}
		}
		body {
			scope(success) {reset();}
			
			static if(!is(Padding == void)) {
				return doFinalWithPad(output);
			} else {
				return doFinalNoPad(output);
			}
		}
		
		
		private uint doFinalWithPad(ubyte[] output) {
			size_t len; /// the number of bytes written to output[]
			if(forEncryption) {
				
				// for padded schemes only
				if(bufOff == blockSize) {
					// this block is full and therefore can't be padded
					// so an aditional (empty) block has to be appended
					
					assert(output.length >= 2*blockSize, "output buffer too small");
					
					len = cipher.processBlock(buf, output);
					output = output[blockSize..$];
					bufOff = 0; // the appended block does not contain data, only padding
					buf[] = 0; // clear buffer
				}
				
				// add padding to the last block
				padding.addPadding(buf, bufOff);
				len += cipher.processBlock(buf, output);
			} else{
				// remove padding
				cipher.processBlock(buf, buf);
				
				uint padBytes = padding.padCount(buf);
				len = buf.length - padBytes;
				output[0..len] = buf[0..len];
				
			}
			
			return cast(uint)len;
		}
		
		private uint doFinalNoPad(ubyte[] output) nothrow @nogc {
			// no padding scheme
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
		
		public void reset() nothrow @nogc {
			cipher.reset();
			bufOff = 0;
			buf[] = 0;
		}
	}
	
	public ref Padding getUnderlyingPadding() nothrow {
		return padding;
	}
	
	
	private {
		C cipher;
		uint bufOff = 0;
		ubyte[blockSize] buf;
		bool forEncryption;
		
		Padding padding;
	}
}