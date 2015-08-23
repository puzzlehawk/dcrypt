module dcrypt.crypto.modes.aead;

public import dcrypt.crypto.blockcipher;
import dcrypt.crypto.params.keyparameter;

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
						//BlockCipher c = bc.getUnderlyingCipher();
						bc.processAADBytes(cast (const ubyte[])block);
						bc.processBytes(cast(const ubyte[]) [0], cast(ubyte[]) [0]);
						// TODO: ubyte[] slice = bc.processBytes(cast(const ubyte[]) [0], cast(ubyte[]) [0]);
						bc.doFinal(cast(const ubyte[]) [0]);
						// TODO: ubyte[] mac = finish(block);
						bc.getMac(cast(const ubyte[]) [0]);
						size_t s1 = bc.getUpdateOutputSize(cast(size_t) 0);
						size_t s2 = bc.getOutputSize(cast(size_t) 0);
						bc.reset();
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
		void start(bool forEncryption, in ubyte[] key, in ubyte[] iv, in uint macSize = 0) nothrow @nogc;

		/**
		 * Return the name of the algorithm.
		 * 
		 * Returns: the algorithm name.
		 */
		@property
		string name() pure nothrow;
		
		/**
		 * return the cipher this object wraps.
		 *
		 * Returns: the cipher this object wraps.
		 */
		BlockCipher getUnderlyingCipher() nothrow;

		
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
		 * Params: out = space for any resulting output data.
		 * Returns: number of bytes written into out.
		 * Throws: IllegalStateError = if the cipher is in an inappropriate state.
		 * dcrypt.exceptions.InvalidCipherTextException =  if the MAC fails to match.
		 */
		size_t doFinal(ubyte[] output);

		/**
		 * Write the MAC of the processed data to buf
		 * 
		 * Params: buf  = output buffer
		 */
		void getMac(ubyte[] buf) nothrow;
		
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

		/**
		 * Reset the cipher. After resetting the cipher is in the same state
		 * as it was after the last init (if there was one).
		 */
		void reset() nothrow;
	}
}

//// TODO AEAD cipher wrapper
///// Wrapper class for AEAD ciphers
//@safe
//public class AEADCipherWrapper(T) if(isAEADCipher!T): AEADCipher
//{
//
//	private T cipher = void;
//
//	public {
//
//		//		/// Params: c = underlying block cipher
//		//		this(BlockCipher c) {
//		//			cipher = T(c);
//		//		}
//
//		/**
//		 * initialize the underlying cipher. Parameter can either be an AEADParameters or a ParametersWithIV object.
//		 * Params:
//		 * forEncryption = true if we are setting up for encryption, false otherwise.
//		 * params = the necessary parameters for the underlying cipher to be initialised.
//		 * Throws: IllegalArgumentException if the params argument is inappropriate.
//		 */
//		void init(bool forEncryption, ParametersWithIV params) {
//			cipher.init(forEncryption, params);
//		}
//		
//		/**
//		 * Return the name of the algorithm.
//		 * 
//		 * Returns: the algorithm name.
//		 */
//		string getAlgorithmName() pure nothrow {
//			return cipher.getAlgorithmName();
//		}
//
//		/**
//		 * return the cipher this object wraps.
//		 *
//		 * Returns: the cipher this object wraps.
//		 */
//		BlockCipher getUnderlyingCipher() pure nothrow {
//			return cipher.getUnderlyingCipher();
//		}
//
//		
//		/**
//		 * Add a sequence of bytes to the associated data check.
//		 * If the implementation supports it, this will be an online operation and will not retain the associated data.
//		 *
//		 * Params: in = the input byte array.
//		 */
//		void processAADBytes(in ubyte[] aad) nothrow {
//			cipher.processAADBytes(aad);
//		}
//		
//		/**
//		 * process a block of bytes from in putting the result into out.
//		 * Params:
//		 * in = the input byte array.
//		 * out = the output buffer the processed bytes go into.
//		 * Returns: the number of bytes written to out.
//		 * Throws: Error if the output buffer is too small.
//		 */
//		size_t processBytes(in ubyte[] input, ubyte[] output) nothrow {
//			return cipher.processBytes(input, output);
//		}
//		
//		/**
//		 * Finish the operation either appending or verifying the MAC at the end of the data.
//		 *
//		 * Params: out = space for any resulting output data.
//		 * Returns: number of bytes written into out.
//		 * Throws: IllegalStateError = if the cipher is in an inappropriate state.
//		 * dcrypt.exceptions.InvalidCipherTextException =  if the MAC fails to match.
//		 */
//		size_t doFinal(ubyte[] output){
//			return cipher.doFinal(output);
//		}
//		
//		/**
//		 * Write the MAC of the processed data to buf
//		 * 
//		 * Params: buf  = output buffer
//		 */
//		void getMac(ubyte[] buf) nothrow {
//			cipher.getMac(buf);
//		}
//		
//		/**
//		 * return the size of the output buffer required for a processBytes
//		 * an input of len bytes.
//		 *
//		 * Params: len = the length of the input.
//		 * Returns: the space required to accommodate a call to processBytes
//		 * with len bytes of input.
//		 */
//		size_t getUpdateOutputSize(size_t len) nothrow {
//			return cipher.getUpdateOutputSize(len);
//		}
//		
//		/**
//		 * return the size of the output buffer required for a processBytes plus a
//		 * doFinal with an input of len bytes.
//		 *
//		 * Params:
//		 * len = the length of the input.
//		 * Returns: the space required to accommodate a call to processBytes and doFinal
//		 * with len bytes of input.
//		 */
//		size_t getOutputSize(size_t len) nothrow {
//			return cipher.getOutputSize(len);
//		}
//		
//		/**
//		 * Reset the cipher. After resetting the cipher is in the same state
//		 * as it was after the last init (if there was one).
//		 */
//		void reset() nothrow {
//			cipher.reset();
//		}
//	}
//}



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
		
		import dcrypt.crypto.modes.aead;
		import dcrypt.util.encoders.hex;
		import std.conv: text;
		
		foreach (uint i, string test_key; hexKeys)
		{
			ubyte[] plain = hexDecode(hexPlaintexts[i]);
			ubyte[] aad = hexDecode(hexAAD[i]);
			ubyte[] ciphertext = hexDecode(hexCipherTexts[i]);
			
			ubyte[] output = new ubyte[0];
						
			// set to encryption mode
			cipher.start(true, hexDecode(test_key), hexDecode(hexIVs[i]), macSize[i]);
			
			// test reset()
			cipher.processAADBytes([0,1,2,3]);
			output.length = cipher.getOutputSize(plain.length);
			cipher.processBytes(plain, output);
			cipher.reset();
			
			output.length = cipher.getOutputSize(plain.length);
			
			// test encryption
			cipher.processAADBytes(aad);
			size_t offset = cipher.processBytes(plain, output);
			
			size_t len = offset+cipher.doFinal(output[offset..$]);
			//output = output[0..len];
			
			assert(output == ciphertext,
				text(cipher.name~" encrypt: (",hexEncode(output),") != ("~hexCipherTexts[i]~")"));
			
		}
	}
}