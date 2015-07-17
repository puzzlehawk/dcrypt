module dcrypt.crypto.modes.gcm.gcm;

public import dcrypt.crypto.modes.aead;
public import dcrypt.crypto.params.keyparameter;
import dcrypt.crypto.modes.gcm.ghash;
import dcrypt.crypto.modes.gcm.multiplier;

public import dcrypt.exceptions: InvalidCipherTextException, IllegalArgumentException;


/// Implementation of the Galois/Counter mode (GCM)
/// as described in NIST Special Publication 800-38D
/// 
/// Standards: NIST Special Publication 800-38D


// TODO Shoup tables
// TODO support for uneven macSize

//alias GCMBlockCipher(T) = AEADBlockCipherWrapper!(GCM!T); // would be nice but does not yet work

///
///	usage of OOP API:
///	auto aes_gcm = new AEADBlockCipherWrapper!(GCM!AES)();
///
@safe
public struct GCM(T) if(is(T == void) || isBlockCipher!T)
{
	// if T == void: use OOP API for underlying block cipher
	static if(is(T == void)) {
		/**
		 * Params:
		 * c = underlying BlockCipher
		 */
		public this(BlockCipher c)
		in {
			assert(c.blockSize() == BLOCKSIZE, "GCM: block size of underlying cipher must be 128 bits!");	
		}
		body {
			blockCipher = c;
		}
	} else {
		static assert(T.blockSize == BLOCKSIZE, "GCM: block size of underlying cipher must be 128 bits!");
	}

	private {

		enum BLOCKSIZE = 16;

		static if(is(T == void)) {
			BlockCipher blockCipher;
		} else {
			T blockCipher;	/// underlying BlockCipher
		}
		GHash gHash;					/// provides the multiplication in GF(2^128) by H
		CircularBlockBuffer!BLOCKSIZE buf;	/// stores input data before processing

		ubyte[BLOCKSIZE] Y;				/// counter
		ubyte[BLOCKSIZE] E0;			/// E(key, Y0), needed to derive AuthTag from GHASH
		ubyte[BLOCKSIZE] mac;			/// used to store the encrypted ghash TODO: use other buffer, e.g. E0 itself
		
		ubyte[BLOCKSIZE] initialY;		/// used to reset Y

		uint macBitLen = 128;			/// length of token
		
		bool forEncryption;				/// Tells wether we are in ecryption or decryption mode.
		bool initialized = false;		/// True if and only if GCM has been initialized
	}


	public void init(bool forEncryption, in ubyte[] key, in ubyte[] nonce = null, uint macSize = 128) nothrow {
			start(forEncryption, key, nonce, 128);
	}

	public {
	
		/**
		 * Returns: the algorithm name.
		 */
		string getAlgorithmName() pure nothrow {
			return blockCipher.name ~ "/GCM";
		}

		static uint blockSize() pure nothrow @nogc {
			return BLOCKSIZE;
		}

		static if(is(T == void)) {
			/**
			 * Returns: the cipher this object wraps.
			 */
			BlockCipher getUnderlyingCipher() pure nothrow @nogc {
				return blockCipher;
			}
		} else {
			/**
			 * Returns: the cipher this object wraps.
			 */
			ref T getUnderlyingCipher() pure nothrow @nogc {
				return blockCipher;
			}
		}
		
		/**
		 * Add a sequence of bytes to the associated data check.
		 * 
		 * Params: in = the input byte array.
		 */
		void processAADBytes(in ubyte[] aad) nothrow @nogc 
		in {
			assert(initialized, "not initialized");
		}
		body {
			gHash.updateAAD(aad);
		}

		/**
		 * process a block of bytes from in putting the result into out.
		 * Params:
		 * in = the input byte array.
		 * out = the output buffer the processed bytes go into.
		 * Returns: the number of bytes written to out.
		 * Throws: Error if the output buffer is too small.
		 */
		size_t processBytes(in ubyte[] input, ubyte[] output) nothrow 
		in {
			assert(initialized, "not initialized");
			assert(output.length >= getUpdateOutputSize(input.length), "output buffer too short");
		}
		body {

			import std.algorithm: min;
			size_t processedBytes = 0;

			const(ubyte)[] iBuf = input;

			while(iBuf.length > 0) {
				if(buf.isFull()) {
					// encrypt one block
					outputBlock(output);
					output = output[BLOCKSIZE..$];
					processedBytes += BLOCKSIZE;
				}

				// copy max one block to the buffer
				size_t procLen = buf.put(iBuf);
				iBuf = iBuf[procLen..$];
			}

			return processedBytes;
		}
		
		/**
		 * Finish the operation by either appending or verifying the MAC at the end of the data.
		 *
		 * Params: out = space for any resulting output data.
		 * Returns: number of bytes written into out.
		 * Throws: InvalidCipherTextException if the MAC does not match.
		 */
		size_t doFinal(ubyte[] output) 
		in {
			assert(initialized, "not initialized");

			assert(output.length >= getOutputSize(0), "output buffer too small");
		}
		body{

			size_t outputBytes = 0;

			size_t macLen = (macBitLen + 7) / 8;

			if(!forEncryption) {
				if(buf.length < macLen) {
					throw new InvalidCipherTextException("ciphertext so short that it can't even contain the MAC");
				}
			}

			size_t partialBlockLen = forEncryption ? buf.length : buf.length - macLen;

			ubyte[2*BLOCKSIZE] lastBlocks; // last two blocks. probably not full. last few bytes are the token.

			
			// copy partial cipher data block
			buf.drainAll(lastBlocks);

			assert(output.length >= partialBlockLen, "output buffer too short");
			// encrypt last partial block
			ubyte[2*BLOCKSIZE] keyStream;

			// generate two blocks of key stream
			genNextKeyStreamBlock(keyStream[0..BLOCKSIZE]);
			genNextKeyStreamBlock(keyStream[BLOCKSIZE..2*BLOCKSIZE]);

			output[0..partialBlockLen] = lastBlocks[0..partialBlockLen] ^ keyStream[0..partialBlockLen];

			// update ghash
			gHash.updateCipherData(forEncryption ? output[0..partialBlockLen] : lastBlocks[0..partialBlockLen]);

			output = output[partialBlockLen..$];
			outputBytes += partialBlockLen;
			
			// calculate the hash
			gHash.doFinal(mac);

			mac[] ^= E0[]; // calculate the token
			

			if(forEncryption) {
				// append token
				assert(output.length >= macLen, "output buffer too short for MAC");

				assert(macLen <= BLOCKSIZE);

				output[0..macLen] = mac[0..macLen];
				output = output[macLen..$];
				outputBytes += macLen;
			}
			else {
				// verify token in decryption mode

				// get received mac
				ubyte[] receivedMAC = lastBlocks[partialBlockLen..partialBlockLen+macLen];

				// compare received token and calculated token within constant time
				bool correctMac = true;
				foreach(i;0..macLen) {
					correctMac &= receivedMAC[i] == mac[i];
				}
				if(!correctMac) {
					throw new InvalidCipherTextException("wrong MAC");
				}

			}

			return outputBytes;
		}
		
		/**
		 * Write the MAC of the processed data to buf
		 * 
		 * Params: buf  = output buffer
		 * 
		 * TODO variable tag size ( macSize of AEADParameters)
		 */
		void getMac(ubyte[] buf) nothrow @nogc 
		in {
			assert(initialized, "not initialized");
			assert(buf.length >= BLOCKSIZE, "output buffer too short for MAC");
		}
		body {
			buf[0..BLOCKSIZE] = mac[];
		}
		
		/**
		 * return the size of the output buffer required for a processBytes
		 * an input of len bytes.
		 *
		 * Params: len = the length of the input.
		 * Returns: the space required to accommodate a call to processBytes
		 * with len bytes of input.
		 */
		size_t getUpdateOutputSize(size_t len) nothrow @nogc {
			size_t total = len + buf.length;
			return (total + BLOCKSIZE - 1) && (~BLOCKSIZE+1);
		}
		
		/**
		 * return the size of the output buffer required for a processBytes plus a
		 * doFinal with an input of len bytes.
		 *
		 * Params: len = the total length of the input.
		 * Returns: the space required to accommodate a call to processBytes and doFinal
		 * with len bytes of input.
		 */
		size_t getOutputSize(size_t len) nothrow @nogc {
			size_t macSize = (macBitLen+7)/8;
			size_t totalData = len + buf.length;
			if(forEncryption) {
				return totalData+macSize;
			}else {
				return totalData < macSize  ? 0 : totalData - macSize;
			}
		}
		
		/**
		 * Reset the cipher. After resetting the cipher is in the same state
		 * as it was after the last init (if there was one).
		 */
		void reset() nothrow 
		{
			gHash.reset();
			buf.reset();

			Y = initialY;
			blockCipher.reset();
		}
	}

	/**
	 * init cipher, H, Y0, E0
	 * 
	 * Params:
	 * forEncryption = encrypt (true) or decrypt (false)
	 * iv = initialization vector
	 * key = encryption key
	 * macSize = length of authentication tag in bits. 32 <= macSize <= 128
	 * 
	 * Throws: IllegalArgumentException
	 */
	private void start(bool forEncryption, in ubyte[] key, in ubyte[] iv, uint macSize) nothrow @nogc
	in {
		assert(macSize >= 32, "macSize can't be lower than 32 bits.");
		assert(macSize <= 128, "macSize can't be longer than 128 bits.");
		assert(macSize % 8 == 0, "macSize must be a multiple of 8. uneven length not yet supported");
	}
	body {

		this.forEncryption = forEncryption;
		this.macBitLen = macSize;

		// init underyling cipher
		blockCipher.start(true, key);
		
		// init gHash
		ubyte[BLOCKSIZE] H;
		H[] = 0;
		blockCipher.processBlock(H,H); // calculate H=E(K,0^128);
		
		gHash.init(H);
		
		// init IV
		if(iv.length == 12) { // 96 bit IV is optimal
			Y[0..iv.length] = iv[];
			Y[$-1] = 1;
		}else {
			gHash.updateCipherData(iv);
			gHash.doFinal(Y);
		}

		// generate key stream used later to encrypt ghash
		genNextKeyStreamBlock(E0);

		initialY = Y; // remember this to reset the cipher

		initialized = true;
	}
	
	private nothrow @safe @nogc {

		/**
		 * generates the next key stream block by incrementing the counter
		 * and encrypting it.
		 * 
		 * bufOff is set to 0
		 */
		void genNextKeyStreamBlock(ubyte[] buf)
		in {
			assert(buf.length == BLOCKSIZE);
			//assert(keyStreamBufOff == BLOCKSIZE, "not yet ready to generate next block");
		}
		body {
			blockCipher.processBlock(Y,buf);
			incrCounter();
		}

		/**
		 * encrypt or decrypt a block and write it to output
		 * update GHash
		 */
		void outputBlock(ubyte[] output)
		in {
			assert(output.length >= BLOCKSIZE, "output buffer too short");
			assert(buf.length >= BLOCKSIZE, "not enough data in buffer");
		}
		body {
			ubyte[BLOCKSIZE] keyStream;
			ubyte[BLOCKSIZE] inputBuf;
			genNextKeyStreamBlock(keyStream);

			buf.drainBlock(inputBuf);

			// encrypt the buffer
			output[0..BLOCKSIZE] = keyStream[0..BLOCKSIZE] ^ inputBuf[0..BLOCKSIZE];

			// update gHash
			gHash.updateCipherData(forEncryption ? output[0..BLOCKSIZE] : inputBuf[0..BLOCKSIZE]);
		}

		/** 
		 * increment Y by 1
		 * treats rightmost 32 bits as uint, lsb on the right
		 */
		void incrCounter() {
			for(uint i = BLOCKSIZE -1; i >= BLOCKSIZE-4; --i) {
				if(++Y[i] != 0) {
					break;
				}
				// increment next element on overflow of the previous
			}
		}

	}
}

/// test vectors from
/// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
/// section 2.2.1
unittest {
	import dcrypt.crypto.engines.aes;

	alias const(ubyte)[] octets;

	octets key = cast(octets)x"AD7A2BD03EAC835A6F620FDCB506B345";
	octets iv = cast(octets)x"12153524C0895E81B2C28465"; // 96 bits

	auto gcm = new GCMBlockCipher(new AESEngine);
	gcm.init(true, new ParametersWithIV(key, iv));

	ubyte[] output = new ubyte[64];
	ubyte[] oBuf = output;
	size_t outLen;

	gcm.processAADBytes(cast(octets)x"D609B1F056637A0D46DF998D88E52E00");

	outLen = gcm.processBytes(cast(octets)x"08000F101112131415161718191A1B1C", oBuf);
	oBuf = oBuf[outLen..$];
	outLen = gcm.processBytes(cast(octets)x"1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A", oBuf);
	oBuf = oBuf[outLen..$];

	outLen = gcm.processBytes(cast(octets)x"0002", oBuf);
	oBuf = oBuf[outLen..$];

	gcm.processAADBytes(cast(octets)x"B2C2846512153524C0895E81");

	outLen = gcm.doFinal(oBuf);

	
	assert(output == cast(octets)x"701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D4F8D55E7D3F06FD5A13C0C29B9D5B880");
}

/// test decryption
/// test vectors from
/// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
/// section 2.2.1
unittest {
	import dcrypt.crypto.engines.aes;
	
	alias const(ubyte)[] octets;
	
	octets key = cast(octets)x"AD7A2BD03EAC835A6F620FDCB506B345";
	octets iv = cast(octets)x"12153524C0895E81B2C28465"; // 96 bits
	
	GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
	gcm.init(false, new ParametersWithIV(key, iv));
	
	ubyte[] output = new ubyte[48];
	ubyte[] oBuf = output;
	size_t outLen;
	
	gcm.processAADBytes(cast(octets)x"D609B1F056637A0D46DF998D88E52E00");

	// add ciphertext
	outLen = gcm.processBytes(cast(octets)
		x"701AFA1CC039C0D765128A665DAB6924
	      3899BF7318CCDC81C9931DA17FBE8EDD
	      7D17CB8B4C26FC81E3284F2B7FBA713D
	      4F8D55E7D3F06FD5A13C0C29B9D5B880", oBuf);
	oBuf = oBuf[outLen..$];
	
	gcm.processAADBytes(cast(octets)x"B2C2846512153524C0895E81");
	
	outLen = gcm.doFinal(oBuf);
	
	
	assert(output == cast(octets)
		x"08000F101112131415161718191A1B1
	      C1D1E1F202122232425262728292A2B
	      2C2D2E2F303132333435363738393A0002");
}

/// Test decryption with modified cipher data. An exception should be thrown beacause of wrong token.
/// 
/// test vectors from
/// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
/// section 2.2.1
unittest {
	import dcrypt.crypto.engines.aes;
	
	alias const(ubyte)[] octets;
	
	octets key = cast(octets)x"AD7A2BD03EAC835A6F620FDCB506B345";
	octets iv = cast(octets)x"12153524C0895E81B2C28465"; // 96 bits
	
	GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
	gcm.init(false, new ParametersWithIV(key, iv));
	
	ubyte[] output = new ubyte[48];
	ubyte[] oBuf = output;
	size_t outLen;
	
	gcm.processAADBytes(cast(octets)x"D609B1F056637A0D46DF998D88E52E00");
	
	// add ciphertext
	outLen = gcm.processBytes(cast(octets)
		x"701AFA1CC039C0D765128A665DAB6924
	      3899BF7318CCDC81C9931DA17FBE8EDD
	      7D17CB8B4C26FC81E3284F2B7FBA713D
	      4F8D55E7D3F06FD5A13C0C29B9D5BEEF", oBuf); // 880 has been changed do EEF
	oBuf = oBuf[outLen..$];
	
	gcm.processAADBytes(cast(octets)x"B2C2846512153524C0895E81");

	// verify that an InvalidCipherTextException is thrown
	bool exception = false;
	try {
		outLen = gcm.doFinal(oBuf);
	} catch (InvalidCipherTextException e) {
		exception = true;
	}
	assert(exception, "Ciphertext has been altered but no exception has been thrown!");
}

/// Test decryption with altered AAD. An exception should be thrown beacause of wrong token.
/// 
/// test vectors from
/// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
/// section 2.2.1
unittest {
	import dcrypt.crypto.engines.aes;
	
	alias const(ubyte)[] octets;
	
	octets key = cast(octets)x"AD7A2BD03EAC835A6F620FDCB506B345";
	octets iv = cast(octets)x"12153524C0895E81B2C28465"; // 96 bits
	
	GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
	gcm.init(false, new ParametersWithIV(key, iv));
	
	ubyte[] output = new ubyte[48];
	ubyte[] oBuf = output;
	size_t outLen;
	
	gcm.processAADBytes(cast(octets)x"D609B1F056637A0D46DF998D88E52E00");
	
	// add ciphertext
	outLen = gcm.processBytes(cast(octets)
		x"701AFA1CC039C0D765128A665DAB6924
	      3899BF7318CCDC81C9931DA17FBE8EDD
	      7D17CB8B4C26FC81E3284F2B7FBA713D
	      4F8D55E7D3F06FD5A13C0C29B9D5B880", oBuf);
	oBuf = oBuf[outLen..$];
	
	gcm.processAADBytes(cast(octets)x"B2C2846512153524C089beef"); // changed 5E81 to beef
	
	// verify that an InvalidCipherTextException is thrown
	bool exception = false;
	try {
		outLen = gcm.doFinal(oBuf);
	} catch (InvalidCipherTextException e) {
		exception = true;
	}
	assert(exception, "AAD has been altered but no exception has been thrown!");
}

// test vectors from
// gcm-spec: Test Case 6
unittest {

	import dcrypt.crypto.engines.aes;
	
	alias const(ubyte)[] octets;
	
	octets key = cast(octets)x"feffe9928665731c6d6a8f9467308308";
	octets iv = cast(octets)
		x"9313225df88406e555909c5aff5269aa
          6a7a9538534f7da1e4c303d2a318a728
          c3c0c95156809539fcf0e2429a6b5254
	      16aedbf5a0de6a57a637b39b"; // more than 96 bits

	GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
	gcm.init(true, new ParametersWithIV(key, iv));

	
	octets aad = cast(octets)(
		x"feedfacedeadbeeffeedfacedeadbeef
          abaddad2"
		);

	octets plaintext = cast(octets)(
		x"d9313225f88406e5a55909c5aff5269a
          86a7a9531534f7da2e4c303d8a318a72
          1c3c0c95956809532fcf0e2449a6b525
          b16aedf5aa0de657ba637b39"
		);

	ubyte[] output = new ubyte[gcm.getOutputSize(plaintext.length)];
	ubyte[] oBuf = output;
	size_t outLen;

	outLen = gcm.processBytes(plaintext, oBuf);
	oBuf = oBuf[outLen..$];

	gcm.processAADBytes(aad);
	
	outLen = gcm.doFinal(oBuf);
	oBuf = oBuf[outLen..$];

	octets expectedCiphertext = cast(octets) (
		x"8ce24998625615b603a033aca13fb894
          be9112a5c3a211a8ba262a3cca7e2ca7
          01e4a9a4fba43c90ccdcb281d48c7c6f
          d62875d2aca417034c34aee5
          619cc5aefffe0bfa462af43c1699d050"
		);
	
	assert(output == expectedCiphertext);
}

/// test GCM with different MAC sizes
unittest { 

	import dcrypt.crypto.engines.aes;

	string[] keys = [
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
	];
	string[] ivs = [
		"00",
		"00000000",
		"00000000000000",
		"00000000000000000000",
		"00000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000",
	];
	string[] aads = [
		"",
		"00000000000000",
		"0000000000000000000000000000",
		"000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	];
	string[] plains = [
		"",
		"0000000000",
		"00000000000000000000",
		"000000000000000000000000000000",
		"0000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	];
	string[] ciphers = [
		"3c2fa7a9",
		"078bb038e6b2353f0e05",
		"d6a480d4dec719bd36a60efde3aaf1f8",
		"e37dd3785cc7017f206df18d831e37cfe63f9e057a23",
		"3fe95bef64662ddcf19a96cc584d2146499320eef8d518bb5e7e49a7",
		"a3b22b8449afafbcd6c09f2cfa9de2be938f8bbf235863d0cefb4075046c9a4d351e",
		"a0912f3bde077afa3f21725fbcae1c9c2e00b28b6eb462745e9b65a026cc4ba84d13b408b7061fe1",
		"535b0d13cbb1012df5402f748cea5304d52db1e4b997317a54c2296b95e0300c6692f911625bfe617d16b63a237b",
		"547096f9d7a83ba8d128467baac4a9d861ebd51cc2dfff111915cd0b4260b7dc49c8d8723eb15429024ac21eed99ca1338844092",
		"95e67a9eade034290efa90e33f51710f02f3aba4c32873545891924aa52dcc092695e983b529b60e7b13aee5f7d6de278c77410e216d0fdbd7e1",
		"0957e69831df479e8cf7b214e1cef4d3e7a2716e8179deaf8061383f35eeabd017080c3d7972b98009a38b5842a2a08a9123412338e16de05a72b76849629b48",
		"07052b0f8b95c9491ae43bac6693802384688e9dd19d9ce295b4ab550163a2bb4b0dd905012a56094e895ea7a5857f8100af40b4adb6452d0b8e78e709c5c9f1d432b5f59317",
		"e0902e27a95867acaa788920ac71b2f2a61863bdc40ee869bea53470edf02fc71800465c550a58ba69220c67243899d756cf0a5ac4fda582fc6e9d2f8498a0e73e0e809bfb8d86ab5fdf066c",
	];
	uint[] macSizes = [
		32,
		40,
		48,
		56,
		64,
		72,
		80,
		88,
		96,
		104,
		112,
		120,
		128,
	];

	AEADBlockCipherTest(
		new GCMBlockCipher(new AESEngine()), 
		keys,
		ivs,
		plains,
		aads,
		ciphers,
		macSizes);
}

/// OOP Wrapper for GCM
@safe
public class GCMBlockCipher: AEADBlockCipher {

	private GCM!void cipher = void;
	
	public {
		
		/// Params: c = underlying block cipher
		this(BlockCipher c) {
			cipher = GCM!void(c);
		}
		
		/**
		 * initialize the underlying cipher..
		 * Params:
		 * forEncryption = true if we are setting up for encryption, false otherwise.
		 * key = Secret key.
		 * iv = None.
		 * macSize = Size of mac tag in bits.
		 */
		void init(bool forEncryption, in ubyte[] key, in ubyte[] iv, in uint macSize = 128) nothrow @nogc {
			cipher.start(forEncryption, key, iv, macSize);
		}
		
		/**
		 * Return the name of the algorithm.
		 * 
		 * Returns: the algorithm name.
		 */
		string getAlgorithmName() pure nothrow {
			return cipher.getAlgorithmName();
		}
		
		/**
		 * return the cipher this object wraps.
		 *
		 * Returns: the cipher this object wraps.
		 */
		BlockCipher getUnderlyingCipher() pure nothrow {
			return cipher.getUnderlyingCipher();
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
		 * Finish the operation either appending or verifying the MAC at the end of the data.
		 *
		 * Params: out = space for any resulting output data.
		 * Returns: number of bytes written into out.
		 * Throws: IllegalStateError = if the cipher is in an inappropriate state.
		 * dcrypt.exceptions.InvalidCipherTextException =  if the MAC fails to match.
		 */
		size_t doFinal(ubyte[] output){
			return cipher.doFinal(output);
		}
		
		/**
		 * Write the MAC of the processed data to buf
		 * 
		 * Params: buf  = output buffer
		 */
		void getMac(ubyte[] buf) nothrow {
			cipher.getMac(buf);
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
		
		/**
		 * Reset the cipher. After resetting the cipher is in the same state
		 * as it was after the last init (if there was one).
		 */
		void reset() nothrow {
			cipher.reset();
		}
	}

}

/**
 * circular buffer holding 2*BLOCKSIZE bytes of data
 */
@safe
private struct CircularBlockBuffer(size_t BLOCKSIZE) {

	import std.algorithm: min;

	private {
		ubyte[2*BLOCKSIZE] buf;
		size_t offset = 0;
		size_t contentLen = 0;
		ubyte nextOutputBlock = 0;
	}

	invariant {
		assert(offset <= 2*BLOCKSIZE, "offset out of bounds");
		assert(contentLen <= 2*BLOCKSIZE, "contentLen out of bounds");
		assert(nextOutputBlock <= 2, "nextOutputBlock out of bounds");
	}

	
	public nothrow @nogc  {

		/**
		 * try to fill the buffer
		 * 
		 * Returns: number of bytes written to buffer
		 */
		size_t put(in ubyte[] input)
		out (result){
			assert(result <= input.length);
		}
		body {

			size_t procLen = min(input.length, 2*BLOCKSIZE - contentLen);

			const(ubyte)[] iBuf = input;

			// copy input into buffer
			foreach(i;0..procLen) {
				buf[offset] = input[i];
				offset = (offset + 1) % (2*BLOCKSIZE);
			}

			contentLen += procLen;

			return procLen;
		}

		bool isFull() {
			return contentLen == buf.length;
		}

		/**
		 * write max one block to output if buffer is full
		 * 
		 * Returns: number of bytes written to output
		 */
		size_t drainBlock(ubyte[] output)
		in {
			assert(output.length >= BLOCKSIZE, "output buffer too short");
		}
		body {
			if(isFull()) {

				size_t blockOff = nextOutputBlock * BLOCKSIZE;

				// copy one block to output
				output[0..BLOCKSIZE] = buf[blockOff..blockOff+BLOCKSIZE];

				nextOutputBlock ^= 0x01; // 0,1,0,1,...
				contentLen -= BLOCKSIZE;
				return BLOCKSIZE;
			}

			return 0;
		}

		/**
		 * write whole buffer content to output
		 * 
		 * Returns: number of bytes written to output
		 */
		size_t drainAll(ubyte[] output)
		in {
			assert(output.length >= contentLen, "output buffer too short");
		}
		body {

			size_t startOff = nextOutputBlock * BLOCKSIZE;

			// copy data to output
			foreach(i;0..contentLen) {
				output[i] = buf[(startOff + i) % (2*BLOCKSIZE)];
			}

			size_t outLen = contentLen;
			contentLen = 0;
			nextOutputBlock = 0;
			offset = 0;
			return outLen;
		}

		@property
		size_t length() {
			return contentLen;
		}

		void reset() {
			buf[] = 0;
			offset = 0;
			contentLen = 0;
			nextOutputBlock = 0;
		}
		
	}

	
}