module dcrypt.crypto.engines.salsa20;

public import dcrypt.crypto.streamcipher;
public import dcrypt.crypto.params.keyparameter;

import dcrypt.util.bitmanip: rotl=rotateLeft;

import dcrypt.util.pack;
import dcrypt.exceptions;

// test different keys, ivs and plain texts
unittest {
	
	// test vectors generated with bouncycastle Salsa20 implementation
	string[] keys = [
		x"00000000000000000000000000000000",
		x"01010101010101010101010101010101",
		x"02020202020202020202020202020202",
		x"03030303030303030303030303030303",
		x"04040404040404040404040404040404",
		x"05050505050505050505050505050505",
		x"0606060606060606060606060606060606060606060606060606060606060606",
		x"0707070707070707070707070707070707070707070707070707070707070707",
		x"0808080808080808080808080808080808080808080808080808080808080808",
		x"0909090909090909090909090909090909090909090909090909090909090909",
		x"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
		x"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	];

	string[] ivs = [
		x"0101010101010101",
		x"0202020202020202",
		x"0303030303030303",
		x"0404040404040404",
		x"0505050505050505",
		x"0606060606060606",
		x"0707070707070707",
		x"0808080808080808",
		x"0909090909090909",
		x"0a0a0a0a0a0a0a0a",
		x"0b0b0b0b0b0b0b0b",
		x"0c0c0c0c0c0c0c0c",
	];

	string[] plains = [
		x"0202020202020202020202020202020202020202020202020202020202020202",
		x"0303030303030303030303030303030303030303030303030303030303030303",
		x"0404040404040404040404040404040404040404040404040404040404040404",
		x"0505050505050505050505050505050505050505050505050505050505050505",
		x"0606060606060606060606060606060606060606060606060606060606060606",
		x"0707070707070707070707070707070707070707070707070707070707070707",
		x"0808080808080808080808080808080808080808080808080808080808080808",
		x"0909090909090909090909090909090909090909090909090909090909090909",
		x"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
		x"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		x"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		x"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
	];

	string[] ciphers = [
		x"4280c83f61325a4b1c2ba27d5693c016a08b4eb5afe070991307a89a4f6787e7",
		x"3f1d4e1227cd3483068269ed5914a61dedce4e0fe2736d29e9dac4404a994423",
		x"364dc45c17c762f274fcfb1ec04a2c56105e1af3f487f3e72f8dd7d6a9f4d625",
		x"75f0241f020912c83572024d36fa27a97e357de3177e0b66c5855d0492262145",
		x"1a336b436f2fbc172944cb70309b5b683f0348e7dba08536fa7b452bb54ba8b9",
		x"e850390fd95ac10048e85ac9443b2247f72e55215a865f21742ff1a62645d64d",
		x"002d2a162c7143b5c74c4c928101d1479791c1d475beec08d361afdf92e82416",
		x"6955d342676abe02a858d4b0edba48b5a015987643c5bedce850670f7fb5f0bc",
		x"9034ddf6d47e56c8d1b29283794464485390d22669569a58e271b85fe75f62e7",
		x"d39db03f960056879dcc76169e165cb49e9be7c73abead205ec9eeaf0997896e",
		x"b9b544b4299c75723ddaee3f8781748ccf89cfef17a8468000e0e7d2d5359c22",
		x"27760fc0a53dae75e8df893f0281e1ab7f8740bdc52d0527db2fa0d2d4273b0c",
	];

	streamCipherTest(new Salsa20Engine, keys, plains, ciphers, ivs);
}

alias StreamCipherWrapper!Salsa20 Salsa20Engine;

static assert(isStreamCipher!Salsa20, "Salsa20 is not a stream cipher!");

///
///	implementation of the Salsa20/20 stream cipher
///
@safe
public struct Salsa20 {

	public enum stateSize = 16; // 16, 32 bit ints = 64 bytes
	public enum name = "Salsa20/20";

	private {
		// constants

		immutable static {
			ubyte[]
			sigma = cast(immutable ubyte[])"expand 32-byte k",
				tau   = cast(immutable ubyte[])"expand 16-byte k";
		}

		/*
		 * variables to hold the state of the engine
		 * during encryption and decryption
		 */
		uint					index = 0;
		uint[stateSize]		engineState; /// state
		uint[stateSize]		x  ; /// internal buffer
		ubyte[stateSize*4]	keyStream; /// expanded state, 64 bytes
		ubyte[32]			workingKey;
		size_t				workingKeyLength = 32;
		ubyte[8]			workingIV;
		bool				initialized = false;
		
		/*
		 * internal counter
		 */
		uint cW0, cW1, cW2;

		invariant {
			assert(workingKeyLength == 16 || workingKeyLength == 32, "invalid workingKey length: must be 16 or 32 bytes");
		}
		
	}

	@safe @nogc nothrow
	~this() {
		import dcrypt.util.util: wipe;
		
		wipe(engineState);
		wipe(x);
		wipe(keyStream);
		wipe(workingKey);
		wipe(workingIV);
	}

	/// Initialize the cipher.
	/// 
	/// Params:
	/// forEncryption = Not used because encryption and decryption is actually the same.
	/// key = secret key
	/// iv = Use a unique nonce per key.
	public void init(bool forEncryption, in ubyte[] key, in ubyte[] iv) nothrow @nogc
	in {
		assert(key.length == 16 || key.length == 32, "Salsa20 needs 128 or 256 bit keys.");
		assert(iv.length == 8, "Salsa20 needs a 8 byte IV.");
	}
	body {
		setKey(key, iv);
	}

	/**
	 * initialise a Salsa20 cipher.
	 *
	 * Params: forEncryption = whether or not we are for encryption.
	 * params = the parameters required to set up the cipher.
	 * Throws: IllegalArgumentException if the params argument is
	 * inappropriate.
	 */
	public void init(bool forEncryption, KeyParameter params)
	{
		if(auto ivParams = cast(ParametersWithIV) params) {
			init(ivParams);
		} else {
			assert(false, "Salsa20 needs a ParametersWithIV parameter");
		}
	}

	/// initialize the cipher
	/// Params:
	/// ivParams = key and iv
	/// 
	/// Throws:
	/// IllegalArgumentException = if iv length or key length are invalid
	private void init(ParametersWithIV ivParams)
	{
		/* 
		 * Salsa20 encryption and decryption is completely
		 * symmetrical, so the 'forEncryption' is 
		 * irrelevant. (Like 90% of stream ciphers)
		 */
		
		init(true, ivParams.getKey(), ivParams.getIV());
		
	}

	/// 
	/// Throws: MaxBytesExceededException = if limit of 2^70 bytes is exceeded
	///
	public ubyte returnByte(ubyte input)
	{
		if (limitExceeded())
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV. Change IV");
		}
		
		if (index == 0)
		{
			generateKeyStream(keyStream);
			
			if (++engineState[8] == 0)
			{
				++engineState[9];
			}
		}
		
		ubyte output = keyStream[index]^input;
		index = (index + 1) & 63;
		
		return output;
	}

	///
	/// encrypt or decrypt input bytes but no more than 2^70!
	/// 
	/// Params:
	/// input = input bytes
	/// output = buffer for output bytes. length must match input length.
	/// 
	/// Throws: MaxBytesExceededException = if limit of 2^70 bytes is exceeded
	///
	public void processBytes(in ubyte[] input, ubyte[] output)
	in {
		assert(output.length >= input.length, "output buffer too short");
		assert(initialized, "Salsa20Engine not initialized!");
	}
	body {

		// can't encrypt more than 2^70 bytes per iv
		if (limitExceeded(input.length))
		{
			throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded. Change IV!");
		}

		for (size_t i = 0; i < input.length; i++)
		{
			if (index == 0)
			{
				generateKeyStream(keyStream);
				
				if (++engineState[8] == 0)
				{
					++engineState[9];
				}
			}
			
			output[i] = (keyStream[index]^input[i]);
			index = (index + 1) & 63;
		}
	}

	/// reset the cipher to its initial state
	public void reset() nothrow @nogc
	in {
		assert(initialized, "not yet initialized");
	}
	body {
		setKey(workingKey, workingIV);
	}

	
	/**
	 * Salsa20 function
	 *
	 * Params:
	 * rounds = number of rounds (20 in default implementation)
	 * input = input data
	 * x = output buffer where keystream gets written to
	 */    
	public final static void salsaCore(uint rounds)(in uint[] input, uint[] x) pure nothrow @nogc
	in {
		assert(input.length == stateSize, "invalid input length");
		assert(x.length == stateSize, "x: invalid length");

	}
	body {

		static assert(rounds % 2 == 0 || rounds > 0, "rounds must be a even number and > 0");

		x[] = input[];
		
		for (int i = rounds; i > 0; i -= 2)
		{
			x[ 4] ^= rotl((x[ 0]+x[12]), 7);
			x[ 8] ^= rotl((x[ 4]+x[ 0]), 9);
			x[12] ^= rotl((x[ 8]+x[ 4]),13);
			x[ 0] ^= rotl((x[12]+x[ 8]),18);
			x[ 9] ^= rotl((x[ 5]+x[ 1]), 7);
			x[13] ^= rotl((x[ 9]+x[ 5]), 9);
			x[ 1] ^= rotl((x[13]+x[ 9]),13);
			x[ 5] ^= rotl((x[ 1]+x[13]),18);
			x[14] ^= rotl((x[10]+x[ 6]), 7);
			x[ 2] ^= rotl((x[14]+x[10]), 9);
			x[ 6] ^= rotl((x[ 2]+x[14]),13);
			x[10] ^= rotl((x[ 6]+x[ 2]),18);
			x[ 3] ^= rotl((x[15]+x[11]), 7);
			x[ 7] ^= rotl((x[ 3]+x[15]), 9);
			x[11] ^= rotl((x[ 7]+x[ 3]),13);
			x[15] ^= rotl((x[11]+x[ 7]),18);
			x[ 1] ^= rotl((x[ 0]+x[ 3]), 7);
			x[ 2] ^= rotl((x[ 1]+x[ 0]), 9);
			x[ 3] ^= rotl((x[ 2]+x[ 1]),13);
			x[ 0] ^= rotl((x[ 3]+x[ 2]),18);
			x[ 6] ^= rotl((x[ 5]+x[ 4]), 7);
			x[ 7] ^= rotl((x[ 6]+x[ 5]), 9);
			x[ 4] ^= rotl((x[ 7]+x[ 6]),13);
			x[ 5] ^= rotl((x[ 4]+x[ 7]),18);
			x[11] ^= rotl((x[10]+x[ 9]), 7);
			x[ 8] ^= rotl((x[11]+x[10]), 9);
			x[ 9] ^= rotl((x[ 8]+x[11]),13);
			x[10] ^= rotl((x[ 9]+x[ 8]),18);
			x[12] ^= rotl((x[15]+x[14]), 7);
			x[13] ^= rotl((x[12]+x[15]), 9);
			x[14] ^= rotl((x[13]+x[12]),13);
			x[15] ^= rotl((x[14]+x[13]),18);
		}
		
		// element wise addition
		x[] += input[];
		
	}

	//
	// Private implementation
	//

private:

	/// Params:
	/// keyBytes = key, 16 or 32 bytes
	/// ivBytes = iv, exactly 8 bytes
	void setKey(in ubyte[] keyBytes, in ubyte[] ivBytes) nothrow @nogc
	in {
		assert(keyBytes.length == 16 || keyBytes.length == 32, "invalid key length");
		assert(ivBytes.length == 8, "invalid iv length");
	}
	body {
		workingKeyLength = keyBytes.length;
		workingKey[0..workingKeyLength] = keyBytes[];
		workingIV[]  = ivBytes[];

		index = 0;
		resetCounter();
		uint offset = 0;
		ubyte[sigma.length] constants;
		
		// Key
		fromLittleEndian(workingKey[0..16], engineState[1..5]);
		
		if (workingKeyLength == 32)
		{
			constants[] = sigma[];
			offset = 16;
		}
		else
		{
			constants[] = tau[];
		}

		fromLittleEndian(workingKey[offset..offset+16], engineState[11..11+4]);

		engineState[0] = fromLittleEndian!uint(constants[0..$]);
		engineState[5] = fromLittleEndian!uint(constants[4..$]);
		engineState[10] = fromLittleEndian!uint(constants[8..$]);
		engineState[15] = fromLittleEndian!uint(constants[12..$]);

		// IV

		engineState[6] = fromLittleEndian!uint(workingIV[0..$]);
		engineState[7] = fromLittleEndian!uint(workingIV[4..$]);
		engineState[8] = 0;
		engineState[9] = 0;

		initialized = true;
	}

	/// generate a block (64 bytes) of keystream
	void generateKeyStream(ubyte[] output) nothrow @nogc
	in {
		assert(output.length == stateSize*4, "invalid length of output buffer: 64 bytes required");
	}
	body {
		salsaCore!20(engineState, x);
		toLittleEndian(x, output);
	}

	void resetCounter() nothrow @nogc
	{
		cW0 = 0;
		cW1 = 0;
		cW2 = 0;
	}
	
	bool limitExceeded() nothrow @nogc
	{
		if (++cW0 == 0)
		{
			if (++cW1 == 0)
			{
				return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
			}
		}
		
		return false;
	}
	
	/*
	 * test if limit will be exceeded for input of size len
	 */
	bool limitExceeded(size_t len) nothrow @nogc
	{
		cW0 += len;
		if (cW0 < len && cW0 >= 0)
		{
			if (++cW1 == 0)
			{
				return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
			}
		}
		
		return false;
	}
}

