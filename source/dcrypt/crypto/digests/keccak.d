module dcrypt.crypto.digests.keccak;


import dcrypt.crypto.digest;
import std.conv:text;
import dcrypt.exceptions;
import dcrypt.errors;
import std.exception: enforce;
/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p/>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
@safe
public class KeccakDigest: Digest
{
    
	alias put update;

    public {
        this () nothrow
        {
            init(0);
        }

        this (uint bitLength) nothrow
        {
            init(bitLength);
        }

		@property
        override string name() pure nothrow
        {
            return text("Keccak-", fixedOutputLength);
        }

        @nogc
        override  uint getDigestSize() pure nothrow
        {
            return fixedOutputLength / 8;
        }

        @nogc
        void put(ubyte input) nothrow
        {
			ubyte[1] oneByte;
            oneByte[0] = input;

            doUpdate(oneByte, 8L);
        }
        
        @nogc
        void put(in ubyte[] input) nothrow
        {
            doUpdate(input, input.length*8);
        }


        override uint doFinal(ubyte[] output) {
            squeeze(output, fixedOutputLength);
            reset();
            return fixedOutputLength/8;
        }

        override  void reset() nothrow
        {
            init(fixedOutputLength);
        }

        /**
         * Return the size of block that the compression function is applied to in bytes.
         *
         * Returns: internal byte length of a block.
         */
        override  uint getByteLength()
        {
            return rate / 8;
        }
        
        override uint blockSize() {
        	return 0;
        }
        
        @property    
	    override KeccakDigest dup() nothrow {
	    	KeccakDigest clone = new KeccakDigest();
	    	clone.state = state;
	    	clone.dataQueue = dataQueue;
	    	clone.rate = rate;
	    	clone.bitsInQueue = bitsInQueue;
	    	clone.fixedOutputLength = fixedOutputLength;
	    	clone.squeezing = squeezing;
	    	clone.bitsAvailableForSqueezing = bitsAvailableForSqueezing;
	    	clone.chunk = chunk.dup;
	    	return clone;
	    }
    }

private:

    static {
        enum ulong[24] KeccakRoundConstants = keccakInitializeRoundConstants();
        enum uint[25] KeccakRhoOffsets = keccakInitializeRhoOffsets();

        pure  ulong[24] keccakInitializeRoundConstants()
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

        bool LFSR86540(ubyte[] LFSR) pure nothrow @nogc
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

        uint[25] keccakInitializeRhoOffsets() pure nothrow @nogc
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

    private {
        ubyte[1600/8] state;
        ubyte[1536 / 8] dataQueue;
        uint rate;
        uint bitsInQueue;
        uint fixedOutputLength;
        bool squeezing;
        uint bitsAvailableForSqueezing;
        ubyte[] chunk;
    }

    @nogc
    private void clearDataQueueSection(uint off, uint len) nothrow
    {
        dataQueue[off..off+len] = 0;
    }

    private void init(uint bitLength) nothrow
		in {
	}
    body {
        switch (bitLength)
        {
        case 0:
        case 224:
            initSponge(1152, 448);
            break;
        case 256:
            initSponge(1088, 512);
            break;
        case 288:
            initSponge(1024, 576);
            break;
        case 384:
            initSponge(832, 768);
            break;
        case 512:
            initSponge(576, 1024);
            break;
        default:
            assert(false, "bitLength must be one of 224, 256, 384, or 512.");
        }
    }

private nothrow:

    @nogc
    private void doUpdate(in ubyte[] data, ulong databitlen) nothrow
    {
        if ((databitlen % 8) == 0)
        {
            absorb(data, databitlen);
        }
        else
        {
            absorb(data, databitlen - (databitlen % 8));

            ubyte[1] lastByte;

            lastByte[0] = cast(ubyte)(data[(databitlen / 8)] >>> (8 - (databitlen % 8)));
            absorb(lastByte, databitlen % 8);
        }
    }

    private void initSponge(uint rate, uint capacity) nothrow
    in {
        assert (rate + capacity == 1600, "illegal state: rate + capacity != 1600");
    
        if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        {
            throw new IllegalStateError("invalid rate value");
        }
    }
    body {

        this.rate = rate;
        // this is never read, need to check to see why we want to save it
        //  this.capacity = capacity;
        this.fixedOutputLength = 0;
        state[0..$] = 0;
        dataQueue[0..$] = 0;
        this.bitsInQueue = 0;
        this.squeezing = false;
        this.bitsAvailableForSqueezing = 0;
        this.fixedOutputLength = capacity / 2;
        this.chunk = new ubyte[rate / 8];
    }

    @nogc
    private void absorbQueue()
    {
        KeccakAbsorb(state, dataQueue[0..rate / 8]);

        bitsInQueue = 0;
    }

    @nogc
    private void absorb(in ubyte[] data, ulong databitlen) nothrow
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
                    //arrayCopy(data, cast(uint)((i / 8) + (j * chunk.length)), chunk, 0, chunk.length);
                    chunk[0..$] = data[(i / 8) + (j * chunk.length)..$];

//                  displayIntermediateValues.displayBytes(1, "Block to be absorbed", curData, rate / 8);

                    KeccakAbsorb(state, chunk);
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
                arrayCopy(data, cast(uint)(i / 8), dataQueue, bitsInQueue / 8, partialBlock / 8);

//                ulong dataOff = off + cast(uint)(i / 8);
//                trustedArrayCopy(data[dataOff..dataOff+partialBlock / 8], dataQueue[bitsInQueue / 8..$]);

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

    @nogc
    private void padAndSwitchToSqueezingPhase()
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


//            displayIntermediateValues.displayText(1, "--- Switching to squeezing phase ---");


        if (rate == 1024)
        {
            KeccakExtract1024bits(state, dataQueue);
            bitsAvailableForSqueezing = 1024;
        }
        else

        {
            KeccakExtract(state, dataQueue, rate / 64);
            bitsAvailableForSqueezing = rate;
        }

//            displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

        squeezing = true;
    }


    @nogc
    private void squeeze(ubyte[] output, ulong outputLength)
    in {
    	assert(outputLength % 8 == 0, "outputLength not a multiple of 8");
    }
    body {
        ulong i;
        uint partialBlock;

        if (!squeezing)
        {
            padAndSwitchToSqueezingPhase();
        }
        i = 0;
        while (i < outputLength)
        {
            if (bitsAvailableForSqueezing == 0)
            {
                keccakPermutation(state);

                if (rate == 1024)
                {
                    KeccakExtract1024bits(state, dataQueue);
                    bitsAvailableForSqueezing = 1024;
                }
                else

                {
                    KeccakExtract(state, dataQueue, rate / 64);
                    bitsAvailableForSqueezing = rate;
                }

//                    displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

            }
            partialBlock = bitsAvailableForSqueezing;
            if (cast(ulong)partialBlock > outputLength - i)
            {
                partialBlock = cast(uint)(outputLength - i);
            }

//            arrayCopy(dataQueue, (rate - bitsAvailableForSqueezing) / 8, output, cast(uint)(i / 8), partialBlock / 8);

            output[i/8..i/8+partialBlock / 8] = dataQueue[(rate - bitsAvailableForSqueezing) / 8..(rate - bitsAvailableForSqueezing) / 8+partialBlock / 8];

//            ulong dataOff = (rate - bitsAvailableForSqueezing) / 8;
//            trustedArrayCopy(dataQueue[dataOff..dataOff+partialBlock / 8], output);


            bitsAvailableForSqueezing -= partialBlock;
            i += partialBlock;
        }
    }

    @nogc
    private void fromBytesToWords(ulong[] stateAsWords, in ubyte[] state)
    {
        for (uint i = 0; i < (1600 / 64); i++)
        {
            stateAsWords[i] = 0;
            uint index = i * (64 / 8);
            for (uint j = 0; j < (64 / 8); j++)
            {
                stateAsWords[i] |= (cast(ulong)state[index + j] & 0xff) << ((8 * j));
            }
        }
    }
    
    @nogc
    private void fromWordsToBytes(ubyte[] state, in ulong[] stateAsWords)
    {
        for (uint i = 0; i < (1600 / 64); i++)
        {
            uint index = i * (64 / 8);
            for (uint j = 0; j < (64 / 8); j++)
            {
                state[index + j] = cast(ubyte)((stateAsWords[i] >>> ((8 * j))) & 0xFF);
            }
        }
    }

    private ulong[state.length / 8] longState;

    @nogc
    private void keccakPermutation(ubyte[] state) nothrow
    {
//        ulong[] longState = new ulong[state.length / 8];

        fromBytesToWords(longState, state);

//        displayIntermediateValues.displayStateAsBytes(1, "Input of permutation", longState);

        keccakPermutationOnWords(longState);

//        displayIntermediateValues.displayStateAsBytes(1, "State after permutation", longState);

        fromWordsToBytes(state, longState);
    }

    @nogc
    private void keccakPermutationAfterXor(ubyte[] state, ubyte[] data) nothrow
    {
        uint i;

        state[0..data.length] ^= data[];

        keccakPermutation(state);
    }

    @nogc
    private void keccakPermutationOnWords(ulong[] state)
    {

//        displayIntermediateValues.displayStateAs64bitWords(3, "Same, with lanes as 64-bit words", state);

        foreach (uint i; 0..24)
        {
//            displayIntermediateValues.displayRoundNumber(3, i);

            theta(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After theta", state);

            rho(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After rho", state);

            pi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After pi", state);

            chi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After chi", state);

            iota(state, i);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After iota", state);
        }
    }

    private ulong[5] C;

    @nogc
    private void theta(ulong[] A)
    {
        foreach (uint x; 0..5)
        {
            C[x] = 0;
            foreach (uint y; 0..5)
            {
                C[x] ^= A[x + 5 * y];
            }
        }
        foreach (uint x; 0..5)
        {
            ulong dX = ((((C[(x + 1) % 5]) << 1) ^ ((C[(x + 1) % 5]) >>> (64 - 1)))) ^ C[(x + 4) % 5];
            foreach (uint y; 0..5)
            {
                A[x + 5 * y] ^= dX;
            }
        }
    }

    @nogc
    private void rho(ulong[] A) nothrow
    {
        foreach (uint x; 0..5)
        {
            foreach (uint y; 0..5)
            {
                uint index = x + 5 * y;
                A[index] = ((KeccakRhoOffsets[index] != 0) ? (((A[index]) << KeccakRhoOffsets[index]) ^ ((A[index]) >>> (64 - KeccakRhoOffsets[index]))) : A[index]);
            }
        }
    }


    @nogc
    private void pi(ulong[] A) nothrow
    {
		ulong[25] tempA;
        //arrayCopy(A, 0, tempA, 0, tempA.length);
        tempA[0..$] = A[0..$];

        foreach (uint x; 0..5)
        {
            foreach (uint y; 0..5)
            {
                A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
            }
        }
    }


    @nogc
    private void chi(ulong[] A) nothrow
    {
		ulong[5] chiC;
        foreach (uint y; 0..5)
        {
            foreach (uint x; 0..5)
            {
                chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
            }
            foreach (uint x; 0..5)
            {
                A[x + 5 * y] = chiC[x];
            }
        }
    }

    @nogc
    private void iota(ulong[] A, uint indexRound)
    {
        // A[(((0) % 5) + 5 * ((0) % 5))] ^= KeccakRoundConstants[indexRound];
        A[0] ^= KeccakRoundConstants[indexRound];
    }

    @nogc
    private void KeccakAbsorb(ubyte[] byteState, ubyte[] data) nothrow
    {
        keccakPermutationAfterXor(byteState, data);
    }

    @nogc
    private void KeccakExtract1024bits(in ubyte[] byteState, ubyte[] data) nothrow
    {
        //arrayCopy(byteState, 0, data, 0, 128);
        data[0..128] = byteState[0..128];
    }

    @nogc
    private void KeccakExtract(in ubyte[] byteState, ubyte[] data, uint laneCount) nothrow
    {
        //arrayCopy(byteState, 0, data, 0, laneCount * 8);
        data[0..laneCount*8] = byteState[0..laneCount*8];
    }

    @safe @nogc
    private void arrayCopy(T)(in T[] a, ulong inOff,T[] b, ulong outOff, ulong len) nothrow {
        b[outOff..outOff+len] = a[inOff..inOff+len];
    }
}

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
	
	for(size_t i = 0; i < plaintexts.length; ++i) {
		Digest digest = new KeccakDigest(bitLen[i]);
		ubyte[] plain = Hex.decode(plaintexts[i]);
		ubyte[] expectedHash = Hex.decode(hexHashes[i]);
		
		digest.reset();
		digest.put(plain);
		
		ubyte[] actualHash = digest.doFinal();
		
		assert(expectedHash == actualHash, "produced wrong hash: " ~ Hex.encode(actualHash)
			~ " instead of " ~ Hex.encode(expectedHash));
	}
}