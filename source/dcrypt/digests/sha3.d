module dcrypt.digests.sha3;

/// Implementation of Keccak, SHA3 and extendable output functions SHAKE128/256.
/// 
/// Standard: FIPS 202, SHA 3

import dcrypt.digest;
import dcrypt.bitmanip;

import std.conv: text;
import std.algorithm: min;

alias Keccak!(224*2) Keccak224;
alias Keccak!(256*2) Keccak256;
alias Keccak!(288*2) Keccak288;
alias Keccak!(384*2) Keccak384;
alias Keccak!(512*2) Keccak512;

alias SHA3!224 SHA3_224;
alias SHA3!256 SHA3_256;
alias SHA3!384 SHA3_384;
alias SHA3!512 SHA3_512;

alias WrapperDigest!SHA3_224 SHA3_224Digest;
alias WrapperDigest!SHA3_256 SHA3_256Digest;
alias WrapperDigest!SHA3_384 SHA3_384Digest;
alias WrapperDigest!SHA3_512 SHA3_512Digest;

static assert(isDigest!Keccak224);
static assert(isDigest!Keccak256);
static assert(isDigest!Keccak384);
static assert(isDigest!Keccak512);

static assert(isDigest!SHA3_224);
static assert(isDigest!SHA3_256);
static assert(isDigest!SHA3_384);
static assert(isDigest!SHA3_512);

/// Test Keccak
unittest {

	string msg1600 = x"8C3798E51BC68482D7337D3ABB75DC9FFE860714A9AD73551E120059860DDE24AB87327222B64CF774415A70F724CDF270DE3FE47DDA07B61C9EF2A3551F45A5584860248FABDE676E1CD75F6355AA3EAEABE3B51DC813D9FB2EAA4F0F1D9F834D7CAD9C7C695AE84B329385BC0BEF895B9F1EDF44A03D4B410CC23A79A6B62E4F346A5E8DD851C2857995DDBF5B2D717AEB847310E1F6A46AC3D26A7F9B44985AF656D2B7C9406E8A9E8F47DCB4EF6B83CAACF9AEFB6118BFCFF7E44BEF6937EBDDC89186839B77";

	immutable string[] plaintexts = [x"",x"",x"",x"",
		// https://cloud.github.com/downloads/johanns/sha3/KeccakTestVectors.zip
		x"CC",
		msg1600,
		x"CC",
		msg1600,
		x"CC",
		msg1600,
		x"CC",
		msg1600
	];

	immutable string[] hexHashes = [
		x"f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
		x"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		x"2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
		x"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
		// https://cloud.github.com/downloads/johanns/sha3/KeccakTestVectors.zip
		x"A9CAB59EB40A10B246290F2D6086E32E3689FAF1D26B470C899F2802",
		x"1029CA117957D80F3C859E8394DD34969331CA3BCEDC436B1EAB0849",
		x"EEAD6DBFC7340A56CAEDC044696A168870549A6A7F6F56961E84A54BD9970B8A",
		x"E83EA21F5BC0976953AF86069A10EB6024A1AC59D609688E4A9759BB8B6C9441",
		x"1B84E62A46E5A201861754AF5DC95C4A1A69CAF4A796AE405680161E29572641F5FA1E8641D7958336EE7B11C58F73E9",
		x"B5A7160112E0825A7C03643BEB98B1FC2549B81F01C3C4271DFF99BE57D472A7FAD133808D7D2D414D6011E9A2E8DFEC",
		x"8630C13CBD066EA74BBE7FE468FEC1DEE10EDC1254FB4C1B7C5FD69B646E44160B8CE01D05A0908CA790DFB080F4B513BC3B6225ECE7A810371441A5AC666EB9",
		x"2A11CB6921EA662A39DDEE7982E3CF5B317195661D5505AD04D11EE23E178ED65F3E06A7F096F4EAF1FF6A09239CF5A0A39DC9F4C92AF63FDF7211E1CF467653",

	];
	

	for(size_t i = 0; i < plaintexts.length; ++i) {
		const (ubyte)[] plain = cast(const ubyte[]) plaintexts[i];
		const ubyte[] expectedHash = cast(const ubyte[]) hexHashes[i];
		ubyte[] actualHash;

		switch(expectedHash.length*8) {
			case 224: 
				Keccak224 k;
				k.put(plain);
				actualHash = k.finish!224();
				break;
			case 256: 
				Keccak256 k;
				k.put(plain);
				actualHash = k.finish!256();
				break;
			case 384: 
				Keccak384 k;
				k.put(plain);
				actualHash = k.finish!384();
				break;
			case 512: 
				Keccak512 k;
				k.put(plain);
				actualHash = k.finish!512();
				break;
			default: assert(0);
		}
		
		assert(expectedHash == actualHash, "Keccak Produced wrong hash.");
	}
}

unittest {
	SHA3!224 sha3;

	// empty message
	assert(sha3.finish() == x"
		6B 4E 03 42 36 67 DB B7 3B 6E 15 45 4F 0E B1 AB
		D4 59 7F 9A 1B 07 8E 3F 5B 5A 6B C7",
		sha3.name~" failed.");

	ubyte[200] msg = 0b10100011;
	sha3.put(msg);

	assert(sha3.finish() == x"
		93 76 81 6A BA 50 3F 72 F9 6C E7 EB 65 AC 09 5D 
		EE E3 BE 4B F9 BB C2 A1 CB 7E 11 E0",
		sha3.name~" failed.");
}

unittest {
	SHA3!256 sha3;

	// empty message
	assert(sha3.finish() == x"A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62
		F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A", 
		sha3.name~" failed.");
}

unittest {
	SHA3!384 sha3;
	
	// empty message
	assert(sha3.finish() == x"
		0C 63 A7 5B 84 5E 4F 7D 01 10 7D 85 2E 4C 24 85
		C5 1A 50 AA AA 94 FC 61 99 5E 71 BB EE 98 3A 2A
		C3 71 38 31 26 4A DB 47 FB 6B D1 E0 58 D5 F0 04", 
		sha3.name~" failed.");
}

unittest {
	SHA3!512 sha3;
	
	// empty message
	assert(sha3.finish() == x"A6 9F 73 CC A2 3A 9A C5 C8 B5 67 DC 18 5A 75 6E
		97 C9 82 16 4F E2 58 59 E0 D1 DC C1 47 5C 80 A6
		15 B2 12 3A F1 F5 F9 4C 11 E3 E9 40 2C 3A C5 58
		F5 00 19 9D 95 B6 D3 E3 01 75 85 86 28 1D CD 26",
		sha3.name~" failed.");
}

/// Implementation of SHA3.
/// 
/// Standard: FIPS 202, SHA 3
@safe
public struct SHA3(uint bitLength)
	if(bitLength == 224 || bitLength == 256 || bitLength == 384 || bitLength == 512)
{
	private Keccak!(bitLength*2) keccak;

	enum name = text("SHA3-", bitLength);
	enum digestLength = keccak.digestLength;

	enum blockSize = [224: 144, 256: 136, 384: 104, 512: 72][bitLength]; /// Block size for HMAC as defined in FIPS 202, section 7, table 3.

	void start() nothrow @nogc {
		keccak.start();
	}

	public void put(in ubyte[] b...) nothrow @nogc {
		keccak.put(b);
	}

	/// Calculate the final hash value.
	/// Params:
	/// output = buffer for hash value.
	/// Returns: length of hash value in bytes.
	ubyte[] finish(ubyte[] output) nothrow @nogc
	in {
		assert(output.length == digestLength, "output.length != digestLength.");
	} body {

		keccak.absorbBits(0b10, 2);

		return keccak.finish(output);
	}
	
	/// Calculate the final hash value.
	/// Returns: the hash value
	ubyte[digestLength] finish() nothrow @nogc {
		ubyte[digestLength] hash;
		finish(hash);
		return hash;
	}
}


/// Implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
@safe
public struct Keccak(uint capacity)
	if(capacity % 8 == 0)
{

	public {
		//static assert(bitLength == 224 || bitLength == 256 || bitLength == 288 || bitLength == 384 || bitLength == 512);
		enum name = text("Keccak[", capacity, ", ", rate, "]");
		enum digestLength = bitLength / 8;

		public enum blockSize = 0;

		@nogc
		void put(in ubyte[] input...) nothrow
		{
			absorb(input);
		}

		/// Fills the output buffer with the hash value.
		/// Note: Hash will be as long as the output buffer.
		/// Params:
		/// output = buffer for hash value.
		/// Returns: Slice of `output` containing the hash.
		ubyte[] finish(ubyte[] output) nothrow @nogc {
			squeeze(output);
			start();
			return output;
		}

		/// Calculate the final hash value.
		/// Params:
		/// outputLen = Hash size in bits.
		/// Returns: the hash value
		ubyte[outputLen/8] finish(uint outputLen = bitLength)() nothrow @nogc 
			if (outputLen % 8 == 0)
		{
			ubyte[outputLen/8] buf;
			finish(buf);
			return buf;
		}

		void start() nothrow @nogc
		{
			initSponge();
		}
	}

	private {

		enum rate = 1600 - capacity;
		enum bitLength = capacity / 2;
		enum byteStateLength = 1600 / 8;
		enum longStateLength = byteStateLength / 8;
		enum rounds = 24;

		uint bitsInQueue;
		bool squeezing;
		uint bitsAvailableForSqueezing;
		ulong[longStateLength] state;
		ubyte[rate / 8] dataQueue;
	}

private:
	nothrow @nogc:

	void clearDataQueueSection(in size_t off, in size_t len) {
		dataQueue[off..off+len] = 0;
	}

	/// Handles data with arbitrary bit size.
	void doUpdate(in ubyte[] data, in size_t databitlen)
	in {
		assert(data.length == (databitlen+7) / 8);
	} body	{
		if ((databitlen % 8) == 0)
		{
			assert(databitlen == data.length * 8);
			absorb(data);
		}
		else
		{
			if(databitlen > 8) {
				// Absorb all bytes except the last.
				absorb(data[0..$-2]);
			}

			immutable size_t bitLen = databitlen % 8;

			ubyte lastByte = cast(ubyte)(data[(databitlen / 8)] >>> (8 - bitLen));
			//absorb(lastByte, databitlen % 8);
			absorbBits(lastByte, bitLen);
		}
	}

	/// Resets Keccak.
	void initSponge() 
	{
		state[] = 0;
		dataQueue[] = 0;
		bitsInQueue = 0;
		squeezing = false;
		bitsAvailableForSqueezing = 0;
	}

	void absorbQueue()
	{
		KeccakAbsorb!rounds(state, dataQueue[0..rate / 8]);
		bitsInQueue = 0;
	}

	package void absorbBits(in ubyte partialByte, in ulong bitLen) 
	in {
		assert(bitLen < 8, "bitLen must be < 8.");
		assert ((bitsInQueue % 8) == 0, "attempt to absorb with odd length queue.");
		assert(!squeezing, "attempt to absorb while squeezing.");
	}
	body {
		if (bitsInQueue == rate)
		{
			absorbQueue();
		}
		uint mask = (1 << bitLen) - 1;
		dataQueue[bitsInQueue / 8] = cast(ubyte)(partialByte & mask);
		bitsInQueue += bitLen;
	}

	/// Absorb even bytes.
	void absorb(in ubyte[] data) 
	in {
		assert ((bitsInQueue % 8) == 0, "attempt to absorb with odd length queue.");
		assert(!squeezing, "attempt to absorb while squeezing.");
	}
	body {

		const (ubyte)[] iBuf = data;

		while (iBuf.length > 0)
		{
			assert(bitsInQueue % 8 == 0);

			if ((bitsInQueue == 0) && (iBuf.length >= rate/8))
			{
				while(iBuf.length > rate/8)
				{
					KeccakAbsorb!rounds(state, iBuf[0..rate / 8]);
					iBuf = iBuf[rate / 8..$];
				}
			} else {
				immutable size_t partialBlock = min(iBuf.length, rate/8 - bitsInQueue/8);

				dataQueue[bitsInQueue / 8 .. bitsInQueue / 8 + partialBlock]
				= iBuf[0 .. partialBlock];
				iBuf = iBuf[partialBlock..$];
				
				bitsInQueue += partialBlock*8;

				if (bitsInQueue == rate)
				{
					absorbQueue();
				}
			}
		}
	}

	void padAndSwitchToSqueezingPhase()
	{
		if (bitsInQueue + 1 == rate)
		{
			dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
			absorbQueue();
			dataQueue[0..rate/8] = 0;
		}
		else
		{
			clearDataQueueSection((bitsInQueue + 7) / 8, rate / 8 - (bitsInQueue + 7) / 8);
			dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
		}
		dataQueue[(rate - 1) / 8] |= 1 << ((rate - 1) % 8);
		absorbQueue();

		KeccakExtract(state, dataQueue, rate / 64);

		bitsAvailableForSqueezing = rate;
		
		squeezing = true;
	}

	
	package void squeeze(ubyte[] output)
	{
		immutable size_t outputLength = output.length*8;
		uint partialBlock;

		if (!squeezing)
		{
			padAndSwitchToSqueezingPhase();
		}

		while (output.length > 0)
		{
			if (bitsAvailableForSqueezing == 0)
			{
				keccakPermutation!rounds(state);

				KeccakExtract(state, dataQueue, rate / 64);
				bitsAvailableForSqueezing = rate;
				
			}
			partialBlock = min(bitsAvailableForSqueezing/8, output.length);

			output[0..partialBlock] = dataQueue[(rate/8 - bitsAvailableForSqueezing/8)..(rate/8 - bitsAvailableForSqueezing/8) + partialBlock];
			output = output[partialBlock..$];

			bitsAvailableForSqueezing -= partialBlock*8;
		}
	}


	/// Note: This can safely be @trusted because array indices are fixed and
	/// do never depend on input data.
	@safe
	static void keccakPermutation(uint rounds)(ref ulong[25] state) pure
	{
		foreach (uint i; 0..rounds)
		{
			immutable ulong c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
			immutable ulong c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
			immutable ulong c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
			immutable ulong c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
			immutable ulong c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];
			
			immutable ulong d0 = rol(c0, 1) ^ c3;
			immutable ulong d1 = rol(c1, 1) ^ c4;
			immutable ulong d2 = rol(c2, 1) ^ c0;
			immutable ulong d3 = rol(c3, 1) ^ c1;
			immutable ulong d4 = rol(c4, 1) ^ c2;
			
			immutable ulong b00 = state[ 0] ^ d1;
			immutable ulong b01 = rol(state[6] ^ d2, 44);
			immutable ulong b02 = rol(state[12] ^ d3, 43);
			immutable ulong b03 = rol(state[18] ^ d4, 21);
			immutable ulong b04 = rol(state[24] ^ d0, 14);
			immutable ulong b05 = rol(state[3] ^ d4, 28);
			immutable ulong b06 = rol(state[9] ^ d0, 20);
			immutable ulong b07 = rol(state[10] ^ d1, 3);
			immutable ulong b08 = rol(state[16] ^ d2, 45);
			immutable ulong b09 = rol(state[22] ^ d3, 61);
			immutable ulong b10 = rol(state[1] ^ d2, 1);
			immutable ulong b11 = rol(state[7] ^ d3, 6);
			immutable ulong b12 = rol(state[13] ^ d4, 25);
			immutable ulong b13 = rol(state[19] ^ d0, 8);
			immutable ulong b14 = rol(state[20] ^ d1, 18);
			immutable ulong b15 = rol(state[4] ^ d0, 27);
			immutable ulong b16 = rol(state[5] ^ d1, 36);
			immutable ulong b17 = rol(state[11] ^ d2, 10);
			immutable ulong b18 = rol(state[17] ^ d3, 15);
			immutable ulong b19 = rol(state[23] ^ d4, 56);
			immutable ulong b20 = rol(state[2] ^ d3, 62);
			immutable ulong b21 = rol(state[8] ^ d4, 55);
			immutable ulong b22 = rol(state[14] ^ d0, 39);
			immutable ulong b23 = rol(state[15] ^ d1, 41);
			immutable ulong b24 = rol(state[21] ^ d2, 2);
			
			state[0] = b00 ^ (~b01 & b02);
			state[1] = b01 ^ (~b02 & b03);
			state[2] = b02 ^ (~b03 & b04);
			state[3] = b03 ^ (~b04 & b00);
			state[4] = b04 ^ (~b00 & b01);
			state[5] = b05 ^ (~b06 & b07);
			state[6] = b06 ^ (~b07 & b08);
			state[7] = b07 ^ (~b08 & b09);
			state[8] = b08 ^ (~b09 & b05);
			state[9] = b09 ^ (~b05 & b06);
			state[10] = b10 ^ (~b11 & b12);
			state[11] = b11 ^ (~b12 & b13);
			state[12] = b12 ^ (~b13 & b14);
			state[13] = b13 ^ (~b14 & b10);
			state[14] = b14 ^ (~b10 & b11);
			state[15] = b15 ^ (~b16 & b17);
			state[16] = b16 ^ (~b17 & b18);
			state[17] = b17 ^ (~b18 & b19);
			state[18] = b18 ^ (~b19 & b15);
			state[19] = b19 ^ (~b15 & b16);
			state[20] = b20 ^ (~b21 & b22);
			state[21] = b21 ^ (~b22 & b23);
			state[22] = b22 ^ (~b23 & b24);
			state[23] = b23 ^ (~b24 & b20);
			state[24] = b24 ^ (~b20 & b21);
			
			state[0] ^= KeccakRoundConstants[i];
		}
	}

	
	static void KeccakAbsorb(uint rounds)(ref ulong[longStateLength] longState, in ubyte[] data) pure
	in {
		assert(data.length <= longState.length*8);
		assert(data.length % 8 == 0);
	} body {
		ubyte[byteStateLength] byteBuf;
		byteBuf[0..data.length] = data;
		ulong[longStateLength] buf;
		fromLittleEndian!ulong(byteBuf, buf);
		longState[] ^= buf[];
		keccakPermutation!rounds(longState);
	}

	static void KeccakExtract(in ulong[] longState, ubyte[] data, size_t laneCount) pure
	{
		toLittleEndian(longState[0..laneCount], data[0..laneCount*8]);
	}
}


// Keccak constants
private @safe {
	immutable ulong[24] KeccakRoundConstants = keccakInitializeRoundConstants();
	
	static ulong[24] keccakInitializeRoundConstants() pure nothrow @nogc
	{
		ulong[24] keccakRoundConstants;
		ubyte[1] LFSRstate;
		
		LFSRstate[0] = 0x01;
		uint i, j, bitPosition;
		
		for (i = 0; i < 24; i++)
		{
			keccakRoundConstants[i] = 0;
			for (j = 0; j < 7; j++)
			{
				bitPosition = (1 << j) - 1;
				if (LFSR86540(LFSRstate))
				{
					keccakRoundConstants[i] ^= 1L << bitPosition;
				}
			}
		}
		
		return keccakRoundConstants;
	}
	
	static bool LFSR86540(ubyte[] LFSR) pure nothrow @nogc
	{
		bool result = (((LFSR[0]) & 0x01) != 0);
		if (((LFSR[0]) & 0x80) != 0)
		{
			LFSR[0] = cast(ubyte)(((LFSR[0]) << 1) ^ 0x71);
		}
		else
		{
			LFSR[0] <<= 1;
		}
		
		return result;
	}
}

alias SHAKE!128 SHAKE128;
alias SHAKE!256 SHAKE256;
alias SHAKE!(128, true) RawSHAKE128;
alias SHAKE!(256, true) RawSHAKE256;

/// Implementation of the SHAKE extendable output function (XOF).
/// Standard: FIPS 202, SHA 3, Section 6.3
public struct SHAKE(uint bitsize, bool raw = false) if(bitsize == 128 || bitsize == 256) {

	public enum name = text(raw ? "RawSHAKE" : "SHAKE", bitsize);

	private {
		Keccak!(bitsize*2) keccak;
		bool squeezing = false;
	}

	public void start() {
		keccak.start();
		squeezing = false;
	}

	public void put(in ubyte[] b...) {
		assert(!squeezing, name~": Illegal state. Can't absorb data while after extracting some. Use start() to reset.");

		keccak.put(b);
	}

	public void nextBytes(ubyte[] buf) {

		if(!squeezing) {
			// switch to squeezing
			static if(raw) {
				keccak.absorbBits(0b11, 2);
			} else {
				keccak.absorbBits(0b1111, 4);
			}
			squeezing = true;
		}

		keccak.squeeze(buf);
	}

}

/// Test SHAKE128
unittest {
	import std.stdio;

	SHAKE128 shake;
	ubyte[32] buf;

	shake.nextBytes(buf);

	assert(buf == x"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", shake.name~" failed.");

	shake.start();
	shake.put(cast(const ubyte[]) "The quick brown fox jumps over the lazy dog");
	shake.nextBytes(buf);
	assert(buf == x"f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e", shake.name~" failed.");
}

/// Test SHAKE256
unittest {
	import std.stdio;
	
	SHAKE256 shake;
	ubyte[64] buf;
	
	shake.nextBytes(buf);
	
	assert(buf == x"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", shake.name~" failed.");
}