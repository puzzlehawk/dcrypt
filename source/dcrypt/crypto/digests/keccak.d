module dcrypt.crypto.digests.keccak;

import dcrypt.crypto.digest;
import dcrypt.util.bitmanip: rol;
import dcrypt.util.pack;

import std.conv:text;
import std.algorithm: min;

alias WrapperDigest!Keccak224 Keccak224Digest;
alias WrapperDigest!Keccak256 Keccak256Digest;
alias WrapperDigest!Keccak288 Keccak288Digest;
alias WrapperDigest!Keccak384 Keccak384Digest;
alias WrapperDigest!Keccak512 Keccak512Digest;

alias Keccak!224 Keccak224;
alias Keccak!256 Keccak256;
alias Keccak!288 Keccak288;
alias Keccak!384 Keccak384;
alias Keccak!512 Keccak512;

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
static assert(isDigest!Keccak288);
static assert(isDigest!Keccak384);
static assert(isDigest!Keccak512);

static assert(isDigest!SHA3_224);
static assert(isDigest!SHA3_256);
static assert(isDigest!SHA3_384);
static assert(isDigest!SHA3_512);

/// Test Keccak
unittest {
	import dcrypt.util.encoders.hex;

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
		Digest digest;

		const (ubyte)[] plain = cast(const ubyte[]) plaintexts[i];
		const ubyte[] expectedHash = cast(const ubyte[]) hexHashes[i];

		switch(expectedHash.length*8) {
			case 224: digest = new Keccak224Digest; break;
			case 256: digest = new Keccak256Digest; break;
			case 384: digest = new Keccak384Digest; break;
			case 512: digest = new Keccak512Digest; break;
			default: assert(0);
		}
		
		digest.start();
		digest.put(plain);
		
		ubyte[] actualHash = digest.finish();
		
		assert(expectedHash == actualHash, "produced wrong hash: " ~ toHexStr(actualHash)
			~ " instead of " ~ toHexStr(expectedHash));
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


@safe
public struct SHA3(uint bitLength)
	if(bitLength == 224 || bitLength == 256 || bitLength == 384 || bitLength == 512)
{
	private Keccak!bitLength keccak;

	enum name = text("SHA3-", bitLength);
	enum digestLength = keccak.digestLength;
	enum byteLength = keccak.byteLength; /// size of block that the compression function is applied to in bytes
	enum blockSize = 0;

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
	uint doFinal(ubyte[] output) nothrow @nogc {

		enum ubyte tail = 0b00000010;
		keccak.absorbBits(tail, 2);

		return keccak.doFinal(output);
	}
	
	/// Calculate the final hash value.
	/// Returns: the hash value
	ubyte[digestLength] finish() nothrow @nogc {
		ubyte[digestLength] hash;
		doFinal(hash);
		return hash;
	}
}


/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
@safe
public struct Keccak(uint bitLength)
	if(bitLength == 224 || bitLength == 256 || bitLength == 288 || bitLength == 384 || bitLength == 512)
{

	alias put update;

	public {

		enum name = text("Keccak", bitLength);
		enum digestLength = bitLength / 8;
		enum byteLength = rate / 8; /// size of block that the compression function is applied to in bytes
		enum blockSize = 0;

		@nogc
		void put(in ubyte[] input...) nothrow
		{
			doUpdate(input, input.length*8);
		}

		/// Calculate the final hash value.
		/// Params:
		/// output = buffer for hash value.
		/// Returns: length of hash value in bytes.
		uint doFinal(ubyte[] output) nothrow @nogc {
			squeeze(output);
			start();
			return bitLength/8;
		}

		/// Calculate the final hash value.
		/// Returns: the hash value
		ubyte[digestLength] finish() nothrow @nogc {
			ubyte[digestLength] buf;
			doFinal(buf);
			return buf;
		}

		void start() nothrow @nogc
		{
			initSponge();
		}
	}

	private {

		enum capacity = bitLength*2;
		enum rate = 1600 - capacity;
		enum byteStateLength = 1600 / 8;

		uint bitsInQueue;
		bool squeezing;
		uint bitsAvailableForSqueezing;
		ubyte[byteStateLength] state;
		ubyte[rate / 8] dataQueue;
	}

	private nothrow @nogc:

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
		KeccakAbsorb(state, dataQueue[0..rate / 8]);
		bitsInQueue = 0;
	}

	void absorbBits(in ubyte partialByte, in ulong bitLen) 
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
					KeccakAbsorb(state, iBuf[0..rate / 8]);
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
			clearDataQueueSection(0, rate / 8);
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

	
	void squeeze(ubyte[] output)
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
				keccakPermutation(state);

				KeccakExtract(state, dataQueue, rate / 64);
				bitsAvailableForSqueezing = rate;
				
			}
			partialBlock = min(bitsAvailableForSqueezing/8, output.length);

			output[0..partialBlock] = dataQueue[(rate/8 - bitsAvailableForSqueezing/8)..(rate/8 - bitsAvailableForSqueezing/8) + partialBlock];
			output = output[partialBlock..$];

			bitsAvailableForSqueezing -= partialBlock*8;
		}
	}

	static void keccakPermutation(ref ubyte[byteStateLength] state) pure
	{
		ulong[25] longState;

		fromLittleEndian(state[], longState[]);
		keccakPermutationOnWords(longState);
		toLittleEndian(longState[], state[]);
	}

	static void keccakPermutationAfterXor(ref ubyte[byteStateLength] state, in ubyte[] data) pure
	in {
		assert(data.length <= state.length);
	} body {
		state[0..data.length] ^= data[];
		keccakPermutation(state);
	}

	static void keccakPermutationOnWords(ref ulong[25] state) pure
	{
		foreach (uint i; 0..24)
		{
			theta(state);
			rho(state);
			pi(state);
			chi(state);
			iota(state, i);
		}
	}

	static void theta(ref ulong[25] A) pure
	{
		ulong[5] C;
		foreach (uint x; 0..5)
		{
			foreach (uint y; 0..5)
			{
				C[x] ^= A[x + 5 * y];
			}
		}
		foreach (uint x; 0..5)
		{
			ulong dX = rol(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
			foreach (uint y; 0..5)
			{
				A[x + 5 * y] ^= dX;
			}
		}
	}

	/// Rotate each element of A by the index in the KeccakRhoOffsets table.
	static void rho(ref ulong[25] A) pure
	{
		foreach (uint index; 0..25)
		{
			immutable uint rhoOffset = KeccakRhoOffsets[index];
			A[index] = rol(A[index], rhoOffset);
		}
	}

	
	static void pi(ref ulong[25] A) pure
	{
		ulong[25] tempA = A;

		foreach (uint x; 0..5)
		{
			foreach (uint y; 0..5)
			{
				A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
			}
		}
	}

	
	static void chi(ref ulong[25] A) pure
	{
		ulong[5] chiC;
		foreach (uint y; 0..5)
		{
			foreach (uint x; 0..5)
			{
				chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
			}

			A[5*y..5*y+5] = chiC[];
		}
	}

	
	static void iota(ref ulong[25] A, in uint indexRound) pure
	{
		A[0] ^= KeccakRoundConstants[indexRound];
	}

	static void KeccakAbsorb(ref ubyte[byteStateLength] byteState, in ubyte[] data) pure
	{
		keccakPermutationAfterXor(byteState, data);
	}

	static void KeccakExtract(in ubyte[] byteState, ubyte[] data, in uint laneCount) pure
	{
		data[0..laneCount*8] = byteState[0..laneCount*8];
	}
}


// Keccak constants
private @safe {
	enum ulong[24] KeccakRoundConstants = keccakInitializeRoundConstants();
	enum uint[25] KeccakRhoOffsets = keccakInitializeRhoOffsets();
	
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
	
	static uint[25] keccakInitializeRhoOffsets() pure nothrow @nogc
	{
		uint[25] keccakRhoOffsets;
		uint x, y, t, newX, newY;
		
		keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
		x = 1;
		y = 0;
		for (t = 0; t < 24; t++)
		{
			keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
			newX = (0 * x + 1 * y) % 5;
			newY = (2 * x + 3 * y) % 5;
			x = newX;
			y = newY;
		}
		
		return keccakRhoOffsets;
	}
}