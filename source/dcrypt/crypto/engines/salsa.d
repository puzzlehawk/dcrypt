module dcrypt.crypto.engines.salsa;

public import dcrypt.crypto.streamcipher;

import dcrypt.util.bitmanip: rotl=rotateLeft;

import dcrypt.util.pack;
import dcrypt.exceptions;

import std.algorithm: min;
import std.conv: text;

// test different keys, ivs and plain texts
unittest {
	
	// test vectors generated with bouncycastle Salsa20 implementation
	string[] keys = [
		x"00000000000000000000000000000000",
		x"01010101010101010101010101010101",
		x"0202020202020202020202020202020202020202020202020202020202020202",
		x"0303030303030303030303030303030303030303030303030303030303030303",
	];

	string[] ivs = [
		x"0101010101010101",
		x"0202020202020202",
		x"0303030303030303",
		x"0404040404040404",
	];

	string[] plains = [
		x"0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
		x"0303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
		x"0404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
		x"0505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
	];

	string[] ciphers = [
		x"4280c83f61325a4b1c2ba27d5693c016a08b4eb5afe070991307a89a4f6787e734ef067bb35521ea44a4e07d90e64140959e10db4de238918956fc9a8b45245c6df266aed0f064f8be9d769380049b173f3ea0a665dcb46b85f5a9f01406e0cb7186fab2328ddc39051722caeaf2166c00a93e447df93eae9610b82af86c0ed9",
		x"3f1d4e1227cd3483068269ed5914a61dedce4e0fe2736d29e9dac4404a994423feb51748ba99e1f94599c53ee97f58d5b002c9bf04f9a0c2cc4d186620b7a23e312bfaf3d90b76f1fabaaa7a1526160d38fe64acb4af703e2d084424efcdf975825f5fcf39f3286375532ff7206b64b81ae65a0ada0005a5af6d035fb6b38221",
		x"e390de08ceb0eca5c373e7fbc62ae1a76eea14b3302bda97833801da174ef6464f1592d563c30b3da9c99c2b7850a6f93d036bdaf82788aa870a20e2fc384c61f33e45f52e03903a0ab55807b18920db7481bf5f4975faa4e0fc595dc3e8d23145b288e48ae4b895ce58198624b660867eb8226582f72879f4b90eb9a5e67067",
		x"a64037f78e86e53cade29afa3533719ea5b7b71162911bd06e351f172692602cc5c90b022652292f0a78530e4961004cd38b14a22c8a483f386987293c1c24fe1882cb13221d4ec6fa63082c586aab1e2d9fed293b17b1159f1c2f4fdc007df5c9a8c1b026d254262c6e28c0d2f0c8b3cfa83be5b3dbc29166f74123c7dfc54c",
	];

	streamCipherTest(new Salsa20Engine, keys, plains, ciphers, ivs);
}

alias Salsa!20 Salsa20;
alias StreamCipherWrapper!Salsa20 Salsa20Engine;

static assert(isStreamCipher!Salsa20, "Salsa20 is not a stream cipher!");

///
///	implementation of the Salsa20/20 stream cipher
///
/// Params:
/// rounds = Number of rounds. 12 and 20 are allowed. Default is 20.
///
@safe
public struct Salsa(uint rounds = 20)
	if(rounds == 12 || rounds == 20)
{

	public enum name = text("Salsa20/", rounds);

	private {
		// constants

		enum uint[4] sigma	= [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; //cast(ubyte[16])"expand 32-byte k";
		enum uint[4] tau	= [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]; //cast(ubyte[16])"expand 16-byte k";

		enum stateSize = 16; // 16, 32 bit ints = 64 bytes
		
		/*
		 * variables to hold the state of the engine
		 * during encryption and decryption
		 */
		uint				index = 0;
		uint[stateSize]		engineState; /// state
		ubyte[stateSize*4]	keyStream; /// expanded state, 64 bytes
		bool				initialized = false;
		
		/*
		 * internal counter
		 */
		uint cW0, cW1, cW2;
		
	}

	@safe @nogc nothrow
	~this() {
		import dcrypt.util.util: wipe;
		
		wipe(engineState);
		wipe(keyStream);
	}

	/// Initialize the cipher.
	/// 
	/// Params:
	/// forEncryption = Not used because encryption and decryption is actually the same.
	/// key = secret key
	/// iv = Use a unique nonce per key.
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] iv) nothrow @nogc
	in {
		assert(key.length == 16 || key.length == 32, "Salsa20 needs 128 or 256 bit keys.");
		assert(iv.length == 8, "Salsa20 needs a 8 byte IV.");
	}
	body {
		setKey(key, iv);
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
		index = (index + 1) % keyStream.length;
		
		return output;
	}

	///
	/// encrypt or decrypt input bytes but no more than 2^70!
	/// 
	/// Params:
	/// input = input bytes
	/// output = buffer for output bytes. length must match input length.
	/// 
	/// Returns: Slice pointing to processed data which might be smaller than `output`.
	/// 
	/// Throws: MaxBytesExceededException = if limit of 2^70 bytes is exceeded
	///
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output)
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

		ubyte[] initialOutputSlice = output;
		const (ubyte)[] inp = input;

		while(inp.length > 0) {

			if (index == 0)
			{
				generateKeyStream(keyStream);

				// increment counter
				// engineState[9] += ++engineState[8] == 0;
				if (++engineState[8] == 0)
				{
					++engineState[9];
				}
			}

			size_t len = min(keyStream.length-index, inp.length);
			output[0..len] = inp[0..len]^keyStream[index..index+len];
			index = (index + len) % keyStream.length;
			inp = inp[len..$];
			output = output[len..$];
		}

		
		return initialOutputSlice[0..input.length];
	}

	/// reset the cipher to its initial state
	deprecated("The reset() function might lead to insecure use of a stream cipher.")
		public void reset() nothrow @nogc
	in {
		assert(initialized, "not yet initialized");
	}
	body {
		//setKey(workingKey, workingIV);
		// reset counter
		engineState[8..10] = 0;
	}

	
	/// Salsa20 function
	///
	/// Params:
	/// rounds = number of rounds (20 in default implementation)
	/// input = input data
	/// x = output buffer where keystream gets written to   
	public final static void salsaCore(uint rounds)(in uint[] input, uint[] output) pure nothrow @nogc
		if(rounds % 2 == 0 || rounds > 0)
		in {
			assert(input.length == stateSize, "invalid input length");
			assert(output.length == stateSize, "invalid output buffer length");
		} body {

		uint[stateSize] x = input;
		
		foreach (i; 0..rounds/2)
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
		output[] = x[] + input[];
		
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

		index = 0;
		resetCounter();
		uint[4] constants;
		
		// Key
		fromLittleEndian(keyBytes[0..16], engineState[1..5]);
		
		if (keyBytes.length == 32)
		{
			constants = sigma;

			fromLittleEndian(keyBytes[16..32], engineState[11..15]);
		}
		else
		{
			constants = tau;
			fromLittleEndian(keyBytes[0..16], engineState[11..15]);
		}

		engineState[0] = constants[0];
		engineState[5] = constants[1];
		engineState[10] = constants[2];
		engineState[15] = constants[3];

		// IV
		fromLittleEndian!uint(ivBytes[0..$], engineState[6..8]);
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
		uint[stateSize] x;
		salsaCore!rounds(engineState, x);
		toLittleEndian!uint(x, output);
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

void HSalsa(uint rounds = 20)(ubyte[] output, in ubyte[] key, in ubyte[] nonce)
	if(rounds == 12 || rounds == 20)
in {
		assert(output.length == 16, "HSalsa requires 128 bit output buffer.");
		assert(key.length == 32, "HSalsa requires 256 bit key.");
		assert(nonce.length == 24, "HSalsa requires 192 bit nonce.");
} body {
	uint[16] x;
	uint[8] z;

	scope(exit) {
		wipe(x);
		wipe(z);
	}

	x[0] = Salsa.sigma[0];
	x[5] = Salsa.sigma[1];
	x[10] = Salsa.sigma[2];
	x[15] = Salsa.sigma[3];

	fromLittleEndian!uint(key[0..4], x[1..5]);
	fromLittleEndian!uint(key[4..8], x[11..15]);

	fromLittleEndian!uint(nonce, x[6..10]);

	Salsa.salsaCore!rounds(x, x);

	z[0] = x[0];
	z[1] = x[5];
	z[2] = x[10];
	z[3] = x[15];
	z[4..8] = x[6..10];

	toLittleEndian!uint(z, output);
}