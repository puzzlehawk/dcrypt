module dcrypt.crypto.digests.keccak;

import dcrypt.crypto.digest;
import dcrypt.util.bitmanip: rol;
import dcrypt.util.pack;
import dcrypt.exceptions;

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


static assert(isDigest!Keccak224);
static assert(isDigest!Keccak256);
static assert(isDigest!Keccak288);
static assert(isDigest!Keccak384);
static assert(isDigest!Keccak512);

/// Test Keccak
unittest {
	import dcrypt.util.encoders.hex;
	
	
	immutable string[] plaintexts = ["","","","",
		"00",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	];
	immutable uint[] bitLen = [224,256,384,512, 256, 256,512];
	
	
	immutable string[] hexHashes = [
		"f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
		"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
		"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
		"bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a", // 00
		"290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563", // 32x0
		"a8620b2ebeca41fbc773bb837b5e724d6eb2de570d99858df0d7d97067fb8103b21757873b735097b35d3bea8fd1c359a9e8a63c1540c76c9784cf8d975e995c",
	];
	
	Digest[] digests = [
		new Keccak224Digest,
		new Keccak256Digest,
		new Keccak384Digest,
		new Keccak512Digest,
		new Keccak256Digest,
		new Keccak256Digest,
		new Keccak512Digest
	];
	
	for(size_t i = 0; i < plaintexts.length; ++i) {
		Digest digest = digests[i];
		ubyte[] plain = hexDecode(plaintexts[i]);
		ubyte[] expectedHash = hexDecode(hexHashes[i]);
		
		digest.start();
		digest.put(plain);
		
		ubyte[] actualHash = digest.doFinal();
		
		assert(expectedHash == actualHash, "produced wrong hash: " ~ toHexStr(actualHash)
			~ " instead of " ~ toHexStr(expectedHash));
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
		ubyte[1536 / 8] dataQueue;
		ubyte[rate / 8] chunk;
	}

	private nothrow @nogc:

	void clearDataQueueSection(in size_t off, in size_t len) {
		dataQueue[off..off+len] = 0;
	}

	/// Handles data with arbitrary bit size.
	void doUpdate(in ubyte[] data, in ulong databitlen)
	{
		if ((databitlen % 8) == 0)
		{
			absorb(data);
		}
		else
		{
			absorb(data, databitlen - (databitlen % 8));

			ubyte[1] lastByte;

			lastByte[0] = cast(ubyte)(data[(databitlen / 8)] >>> (8 - (databitlen % 8)));
			absorb(lastByte, databitlen % 8);
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

	void absorb(in ubyte[] data, ulong databitlen) 
	in {
		assert ((bitsInQueue % 8) == 0, "attempt to absorb with odd length queue.");
		assert(!squeezing, "attempt to absorb while squeezing.");
	}
	body {
		ulong i, j, wholeBlocks;

		i = 0;
		while (i < databitlen)
		{
			if ((bitsInQueue == 0) && (databitlen >= rate) && (i <= (databitlen - rate)))
			{
				wholeBlocks = (databitlen - i) / rate;

				for (j = 0; j < wholeBlocks; j++)
				{
					KeccakAbsorb(state, data[(i / 8) + (j * rate / 8)..$]);
				}

				i += wholeBlocks * rate;
			}
			else
			{
				uint partialBlock = cast(uint)(databitlen - i);
				if (partialBlock + bitsInQueue > rate)
				{
					partialBlock = rate - bitsInQueue;
				}
				uint partialByte = partialBlock % 8;
				partialBlock -= partialByte;

				dataQueue[bitsInQueue / 8 .. bitsInQueue / 8 + partialBlock / 8]
				= data[i / 8 .. i / 8 + partialBlock / 8];

				bitsInQueue += partialBlock;
				i += partialBlock;
				if (bitsInQueue == rate)
				{
					absorbQueue();
				}
				if (partialByte > 0)
				{
					uint mask = (1 << partialByte) - 1;
					dataQueue[bitsInQueue / 8] = cast(ubyte)(data[(i / 8)] & mask);
					bitsInQueue += partialByte;
					i += partialByte;
				}
			}
		}
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