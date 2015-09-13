module dcrypt.crypto.engines.salsa;

public import dcrypt.crypto.streamcipher;

import dcrypt.bitmanip: rotl=rotateLeft;
import dcrypt.util: wipe;

import dcrypt.bitmanip;
import dcrypt.exceptions;

import std.algorithm: min;
import std.conv: text;

// Test Salsa20
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

// Test XSalsa
unittest {
	
	// test vectors generated with bouncycastle XSalsa20 implementation
	string[] keys = [
		x"86e2f31305b14bc42caf3f9c7fb4112cc7ae64cf43e0d429a27fa63b70d0939e",
		x"b96baefe0fa3144455926da4a8583643107bda7926b2ea4577776f9ca89a9d00",
		x"a5f519c06ede84d97d0d6dc8a9cfa52cfe532908e0dfdb03a875a948866cd77b",
		x"c758bac8a6a4a405aa057a9d90621afa9f23eeb5157f65474e0cdb11284bea77",
	];
	string[] ivs = [
		x"24eaeaac41c512e3eb77bc051c4e98ab565122ea4d274b4f",
		x"17af8f7d0a89e15c6587d3a4f6bb20a75a7ea9d70c96e01c",
		x"0a702d29a25362429c5a5f5e3dd86580c733fb94aff70037",
		x"4201c53a16675ee4b95a85572c59c6e6cdc2faad8c77bc49",
	];
	string[] plains = [
		x"dfe73782b7b40e000084dcd8170f95549180c8b546b8cce7823a38b11fd78f0fb94fa0720cffae5411e5108c9bd186b9f6ab7630477d8b2ca4160c9deeda271ded4a6dd782962b68315c0b9220b122a70bfee4d426eda7f1a44b562659c525bf23a5c692c8c79bb37d11e4386e5a8a096c333038ac590598ef59b6dd7b8969d6",
		x"1107c901f7330c80f24d02581bcd027c6a58cbc2809eebfd1c9182227875571da45c9db20e51421d2b970846e5c72ef1b5b8fdae6e7b59ad9d583dc87133c47686b123627b98e0422fb86495f73060c882302b9c20d310e4e0eddd5daca2f028952d925394afe04a9718f3e5fbe7879665c618a9e05c86bb286dc455898f53da",
		x"a2262bc781d520f799b31a18ad51501072670fa33e6d1c799c7e9c97322485b44800f33f81d9c85c750045f8acedfd61b31f064c4c36771586ea86b2441273936af2644644c3aa8a521ee03ddabdcb6a05177ebab78143ea0dcfd98ef3301f5b76f1f847fb24464f41bba616feb75c2cbb8629807b3dc9fe63bb7b4abcf94a60",
		x"a840111122d4db70f5fbfdea485a37f3ab621855ff44b29843b49d26499f6acbc809bd51d19f7ebab48d99265dddab8832795b526ab688048ce80a0f6b2e938e9568bdb7e90aae58f665f653a1c5b606b0cfac4a8fdb48e340a9c128a5aadea33c8258ea57d1660096cf0858c0e5bb98c7431121b7435e82c62df79ce11a99a1",
	];
	string[] ciphers = [
		x"7b64de1c7c6dec7eb70b79edf5c9d5812309a344e0f9ca53f18c922f03604d616a8008363bd82fc53341c32825ddb8ae371b242fa8eed90afdd38659a2304c13c774816e6c1b3022eebb8092971d3393406f8c70c8a02471146813906ac74e66751bb3dbb21a07913a69c1fcd8e9af0d3b23f13c74872da21eeef0a8578e5873",
		x"80d4be693aa49d763ec1dffa251a6bb0f83402902a8175f5759d40046bc2e0ced8a8239f5a2d2caf28846f8b0e8e0b471ec6d61ed19b268c5d4ed2aff87bb1f07adf0297d305767b70eda08a29c16f04825b7edefdcbc77fcfbd2c9fad63e0d8409dc7a661add37babf814d76aec15ad435b8d9393793189c76f3e51cce31e3b",
		x"8303327859df863abf0b932e3609b862b0e2399f277bbdc194fe19d9f6ad83685f0f2881db383677962d0ef5ae15e30c80cd03b994abc20a5e27a2b7c4c23ab2b045df862a315e5b5329e41183c98acfb2434ebccdf19005204b4d0c7541c3c517bbfc555c54c5d164be5b50ce22182dcb37b9e1a42a19390107683160e97c00",
		x"b8c77c22f789d71679afd50aeb51dcbca26066fc55cee32e5ce3647d89de1bc664f9760ca6ae3037104387ffd1ae6aaae76f7ea1a3c2cac7dc5e5fedf581f8ba3c5025c163cfe7f03337a5ada2e34c573da2149994e805101f829e774e91338e730f07ad870b94bf71a575af3dd029fabe8e874eb655843d8f37bc01a5cfc818",
	];

	streamCipherTest(new XSalsa20Engine, keys, plains, ciphers, ivs);
}

alias Salsa!20 Salsa20;
alias StreamCipherWrapper!Salsa20 Salsa20Engine;

alias Salsa!(20, true) XSalsa20;
alias StreamCipherWrapper!XSalsa20 XSalsa20Engine;

static assert(isStreamCipher!Salsa20, "Salsa20 is not a stream cipher!");
static assert(isStreamCipher!XSalsa20, "XSalsa20 is not a stream cipher!");

///
///	implementation of the Salsa20/20 stream cipher
///
/// Params:
/// rounds = Number of rounds. 12 and 20 are allowed. Default is 20.
///
@safe
public struct Salsa(uint rounds = 20, bool xsalsa = false)
	if(rounds == 12 || rounds == 20)
{

	public enum name = text(xsalsa ? "X" : "", "Salsa20/", rounds);

	private {

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
		static if(xsalsa) {
			assert(key.length == 32, "XSalsa requires a 256 bit key.");
			assert(iv.length == 24, "XSalsa needs a 192 bit nonce.");
		} else {
			assert(key.length == 16 || key.length == 32, "Salsa20 needs 128 or 256 bit keys.");
			assert(iv.length == 8, "Salsa20 needs a 8 byte IV.");
		}
	}
	body {
		static if(xsalsa) {
			// XSalsa
			ubyte[32] xkey = HSalsa(key, iv[0..16]);
			setKey(xkey, iv[16..24]);
			wipe(xkey);
		} else {
			// Salsa
			setKey(key, iv);
		}
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

	
	//
	// Private implementation
	//

private:

	/// Params:
	/// keyBytes = key, 16 or 32 bytes.
	/// ivBytes = iv, exactly 8 bytes.
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
			// repeat the 128 bit key
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

private {
	// constants
	
	enum uint[4] sigma	= [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; //cast(ubyte[16])"expand 32-byte k";
	enum uint[4] tau	= [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]; //cast(ubyte[16])"expand 16-byte k";

}

/// Salsa20/rounds function
///
/// Params:
/// rounds = number of rounds (20 in default implementation)
/// input = input data
/// x = output buffer where keystream gets written to   
public void salsaCore(uint rounds)(in uint[] input, uint[] output) pure nothrow @nogc
	if(rounds % 2 == 0 || rounds > 0)
	in {
		assert(input.length == 16, "invalid input length");
		assert(output.length == 16, "invalid output buffer length");
} body {
	
	uint[16] x = input;
	
	salsaDoubleRound!rounds(x);

	// element wise addition
	x[] += input[];
	output[] = x[];
	
}

/// Executes the double round function rounds/2 times.
///
/// Params:
/// rounds = number of rounds.
/// x = the state. 
private void salsaDoubleRound(uint rounds)(uint[] x) pure nothrow @nogc
	if(rounds % 2 == 0 || rounds > 0)
	in {
		assert(x.length == 16, "invalid state length");
} body {
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
}

/// HSalsa as defined in http://cr.yp.to/snuffle/xsalsa-20110204.pdf
/// Params:
/// key = 32 byte key.
/// nonce = 24 byte nonce.
/// 
/// Returns: 256 bit value.
ubyte[32] HSalsa(uint rounds = 20)(in ubyte[] key, in ubyte[] nonce) pure nothrow @nogc
	if(rounds == 12 || rounds == 20)
	in {
		assert(key.length == 32, "HSalsa requires 256 bit key.");
		assert(nonce.length == 16, "HSalsa requires 128 bit nonce.");
} body {
	uint[16] x;
	uint[8] z;

	scope(exit) {
		wipe(x);
		wipe(z);
	}

	x[0] = sigma[0];
	x[5] = sigma[1];
	x[10] = sigma[2];
	x[15] = sigma[3];

	fromLittleEndian!uint(key[0*4..4*4], x[1..5]);
	fromLittleEndian!uint(key[4*4..8*4], x[11..15]);

	fromLittleEndian!uint(nonce, x[6..10]);

	salsaDoubleRound!rounds(x);

	z[0] = x[0];
	z[1] = x[5];
	z[2] = x[10];
	z[3] = x[15];
	z[4..8] = x[6..10];

	ubyte[32] output;
	toLittleEndian!uint(z, output);
	return output;
}