module dcrypt.aead.aead;

public import dcrypt.blockcipher.blockcipher;

///
/// Test if T is a AEAD cipher.
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

						ubyte[] slice = bc.processBytes(cast(const ubyte[]) [0], cast(ubyte[]) [0]);
						//ubyte[] mac = bc.finish(block);

						size_t len = bc.finish(cast(ubyte[]) [0], cast(ubyte[]) [0]);
						size_t s1 = bc.getUpdateOutputSize(cast(size_t) 0);
						size_t s2 = bc.getOutputSize(cast(size_t) 0);
					}));
}

@safe
public interface IAEADEngine
{

	public {

		 /// Initialize the underlying cipher.
		 /// Params:
		 /// forEncryption = true if we are setting up for encryption, false otherwise.
		 /// key	= Secret key.
		 /// nonce	= Number used only once.
		void start(bool forEncryption, in ubyte[] key, in ubyte[] nonce) nothrow @nogc;

		/// Returns: Returns the name of the algorithm.
		@property
		string name() pure nothrow;
		

		/// Process additional authenticated data.
		void processAADBytes(in ubyte[] aad) nothrow;

		/// Encrypt or decrypt a block of bytes.
		/// 
		/// Params:
		/// input	= Input buffer.
		/// output	= Output buffer.
		/// 
		/// Returns: A slice pointing to the output data.
		ubyte[] processBytes(in ubyte[] input, ubyte[] output) nothrow;

		///	Close the AEAD cipher by producing the remaining output and a authentication tag.
		/// 
		/// Params:
		/// macBuf	= Buffer for the MAC tag.
		/// output	= Buffer for remaining output data.
		/// 
		/// Note: In decryption mode this does not verify the integrity of the data. Verification has to be done by the programmer!
		///
		size_t finish(ubyte[] macBuf, ubyte[] output);

		/// Returns: Return the size of the output buffer required for a processBytes an input of len bytes.
		size_t getUpdateOutputSize(size_t len) nothrow const;
	
		/// Returns: Return the size of the output buffer required for a processBytes plus a finish with an input of len bytes.
		size_t getOutputSize(size_t len) nothrow const;

	}
}

// TODO AEAD cipher wrapper
/// Wrapper class for AEAD ciphers
@safe
public class AEADCipherWrapper(T) if(isAEADCipher!T): IAEADEngine
{

	private T cipher;

	public {

		void start(bool forEncryption, in ubyte[] key, in ubyte[] iv) {
			cipher.start(forEncryption, key, iv);
		}
	
		@property
		string name() pure nothrow {
			return cipher.name;
		}

		void processAADBytes(in ubyte[] aad) nothrow {
			cipher.processAADBytes(aad);
		}
		
	
		ubyte[] processBytes(in ubyte[] input, ubyte[] output) nothrow {
			return cipher.processBytes(input, output);
		}

		size_t finish(ubyte[] macBuf, ubyte[] output){
			return cipher.finish(macBuf, output);
		}

		size_t getUpdateOutputSize(size_t len) nothrow const {
			return cipher.getUpdateOutputSize(len);
		}

		size_t getOutputSize(size_t len) nothrow const {
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
		IAEADEngine cipher, 
		in string[] hexKeys, 
		in string[] hexIVs,
		in string[] hexPlaintexts,
		in string[] hexAAD, 
		in string[] hexCipherTexts,
		in uint[]	macSize
		) {
		
		import dcrypt.aead.aead;
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
			ubyte[] out_slice = cipher.processBytes(plain, output);

			ubyte[16] mac;
			size_t len = out_slice.length+cipher.finish(mac, output[out_slice.length..$]);

			assert(output == ciphertext,
				text(cipher.name~" encrypt: (",hexEncode(output),") != ("~hexCipherTexts[i]~")"));
				
			assert(mac[0..taglen] == expectedMac);
			
		}
	}
}