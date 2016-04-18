module dcrypt.blockcipher.modes.aead;

public import dcrypt.blockcipher.blockcipher;

///
/// test if T is a AEAD cipher
///
@safe
template isAEADCipher(T)
{
	enum bool isAEADCipher =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[0] block;
						T bc = void; //Can define

						bc.start(true, block, block); //  start with key, iv

						string name = T.name;
						uint macSize = T.macSize;

						//BlockCipher c = bc.getUnderlyingCipher();
						bc.processAADBytes(cast (const ubyte[])block);
						size_t outLen = bc.processBytes(cast(const ubyte[]) [0], cast(ubyte[]) [0]);
						// TODO: ubyte[] slice = bc.processBytes(cast(const ubyte[]) [0], cast(ubyte[]) [0]);
						//bc.doFinal(cast(const ubyte[]) [0]);
						// TODO: ubyte[] mac = finish(block);
						size_t len = bc.finish(cast(ubyte[]) [0], cast(ubyte[]) [0]);
						size_t s1 = bc.getUpdateOutputSize(cast(size_t) 0);
						size_t s2 = bc.getOutputSize(cast(size_t) 0);
						//bc.reset();
					}));
}

@safe
public interface AEADCipher
{

	public {
		/**
		 * initialize the underlying cipher. Parameter can either be an AEADParameters or a ParametersWithIV object.
		 * Params:
		 * forEncryption = true if we are setting up for encryption, false otherwise.
		 * params = the necessary parameters for the underlying cipher to be initialised.
		 * macSize = Size of mac tag in bits.
		 */
		void start(bool forEncryption, in ubyte[] key, in ubyte[] iv) nothrow @nogc;

		/**
		 * Return the name of the algorithm.
		 * 
		 * Returns: the algorithm name.
		 */
		@property
		string name() pure nothrow;
		

		/**
		 * Add a sequence of bytes to the associated data check.
		 * <br>If the implementation supports it, this will be an online operation and will not retain the associated data.
		 *
		 * Params: in = the input byte array.
		 */
		void processAADBytes(in ubyte[] aad) nothrow;

		/**
		 * process a block of bytes from in putting the result into out.
		 * Params:
		 * in = the input byte array.
		 * out = the output buffer the processed bytes go into.
		 * Returns: the number of bytes written to out.
		 * Throws: Error if the output buffer is too small.
		 */
		size_t processBytes(in ubyte[] input, ubyte[] output) nothrow;

		/**
		 * Finish the operation either appending or verifying the MAC at the end of the data.
		 *
		 * Params: 
		 * out = space for any resulting output data.
		 * macBuf = Buffer for MAC tag.
		 * Returns: number of bytes written into out.
		 * Throws: IllegalStateError = if the cipher is in an inappropriate state.
		 * dcrypt.exceptions.InvalidCipherTextException =  if the MAC fails to match.
		 */
		size_t doFinal(ubyte[] macBuf, ubyte[] output);

		
		/**
		 * return the size of the output buffer required for a processBytes
		 * an input of len bytes.
		 *
		 * Params: len = the length of the input.
		 * Returns: the space required to accommodate a call to processBytes
		 * with len bytes of input.
		 */
		size_t getUpdateOutputSize(size_t len) nothrow;
		
		/**
		 * return the size of the output buffer required for a processBytes plus a
		 * doFinal with an input of len bytes.
		 *
		 * Params:
		 * len = the length of the input.
		 * Returns: the space required to accommodate a call to processBytes and doFinal
		 * with len bytes of input.
		 */
		size_t getOutputSize(size_t len) nothrow;

	}
}

// TODO AEAD cipher wrapper
/// Wrapper class for AEAD ciphers
@safe
public class AEADCipherWrapper(T) if(isAEADCipher!T): AEADCipher
{

	private T cipher;

	public {

		//		/// Params: c = underlying block cipher
		//		this(BlockCipher c) {
		//			cipher = T(c);
		//		}

		/**
		 * initialize the underlying cipher. Parameter can either be an AEADParameters or a ParametersWithIV object.
		 * Params:
		 * forEncryption = true if we are setting up for encryption, false otherwise.
		 * params = the necessary parameters for the underlying cipher to be initialised.
		 */
		void start(bool forEncryption, in ubyte[] key, in ubyte[] iv) {
			cipher.start(forEncryption, key, iv);
		}
		
		/**
		 * Return the name of the algorithm.
		 * 
		 * Returns: the algorithm name.
		 */
		@property
		string name() pure nothrow {
			return cipher.name;
		}

		
		/**
		 * Add a sequence of bytes to the associated data check.
		 * If the implementation supports it, this will be an online operation and will not retain the associated data.
		 *
		 * Params: in = the input byte array.
		 */
		void processAADBytes(in ubyte[] aad) nothrow {
			cipher.processAADBytes(aad);
		}
		
		/**
		 * process a block of bytes from in putting the result into out.
		 * Params:
		 * in = the input byte array.
		 * out = the output buffer the processed bytes go into.
		 * Returns: the number of bytes written to out.
		 * Throws: Error if the output buffer is too small.
		 */
		size_t processBytes(in ubyte[] input, ubyte[] output) nothrow {
			return cipher.processBytes(input, output);
		}
		
		/**
		 * Finish the operation. Does not verify the mac.
		 *
		 * Params:
		 * out = space for any resulting output data.
		 * macBuf = Buffer for MAC tag.
		 * Returns: number of bytes written into out.
		 * Throws: IllegalStateError = if the cipher is in an inappropriate state.
		 */
		size_t doFinal(ubyte[] macBuf, ubyte[] output){
			return cipher.finish(macBuf, output);
		}
		
		/**
		 * return the size of the output buffer required for a processBytes
		 * an input of len bytes.
		 *
		 * Params: len = the length of the input.
		 * Returns: the space required to accommodate a call to processBytes
		 * with len bytes of input.
		 */
		size_t getUpdateOutputSize(size_t len) nothrow {
			return cipher.getUpdateOutputSize(len);
		}
		
		/**
		 * return the size of the output buffer required for a processBytes plus a
		 * doFinal with an input of len bytes.
		 *
		 * Params:
		 * len = the length of the input.
		 * Returns: the space required to accommodate a call to processBytes and doFinal
		 * with len bytes of input.
		 */
		size_t getOutputSize(size_t len) nothrow {
			return cipher.getOutputSize(len);
		}
	}
}



version(unittest) {
	
	// unittest helper functions

	
	/// Runs decryption and encryption using AEADCipher cipher with given keys, plaintexts, and ciphertexts.
	///
	/// Params:
	/// hexKeys =	the keys encoded in hex
	/// hexIVs =	hex encoded nonces
	/// hexPlaintexts =	the plaintexts encoded in hex
	/// hexAAD = 	additional authenticated data
	/// hexCiphertexts =	the corresponding ciphertexts in hex
	/// macSize = MAC sizes in bits
	///
	/// Throws:
	/// AssertionError	if encryption or decryption failed
	@safe
	public void AEADCipherTest(
		AEADCipher cipher, 
		in string[] hexKeys, 
		in string[] hexIVs,
		in string[] hexPlaintexts,
		in string[] hexAAD, 
		in string[] hexCipherTexts,
		in uint[]	macSize
		) {
		
		import dcrypt.blockcipher.modes.aead;
		import dcrypt.encoders.hex;
		import std.conv: text;
		
		foreach (uint i, string test_key; hexKeys)
		{
			ubyte[] plain = hexDecode(hexPlaintexts[i]);
			ubyte[] aad = hexDecode(hexAAD[i]);
			ubyte[] ciphertext = hexDecode(hexCipherTexts[i]);
			
			ubyte[] output = new ubyte[plain.length];
						
			// set to encryption mode
			cipher.start(true, hexDecode(test_key), hexDecode(hexIVs[i]));

			output.length = cipher.getOutputSize(plain.length);

			immutable size_t taglen = macSize[i]/8;
			ubyte[] expectedMac = ciphertext[$-taglen..$];
			ciphertext = ciphertext[0..$-taglen];

//			assert(cipher.getUpdateOutputSize(plain.length) == plain.length);
			assert(output.length >= cipher.getUpdateOutputSize(plain.length));


			assert(output.length >= cipher.getUpdateOutputSize(plain.length));

			// test encryption
			cipher.processAADBytes(aad);
			size_t offset = cipher.processBytes(plain, output);

			ubyte[16] mac;
			size_t len = offset+cipher.doFinal(mac, output[offset..$]);

			assert(output == ciphertext,
				text(cipher.name~" encrypt: (",hexEncode(output),") != ("~hexCipherTexts[i]~")"));
				
			assert(mac[0..taglen] == expectedMac);
			
		}
	}
}