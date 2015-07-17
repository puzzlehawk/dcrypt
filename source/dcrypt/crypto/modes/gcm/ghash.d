module dcrypt.crypto.modes.gcm.ghash;

import dcrypt.crypto.modes.gcm.galoisfield;
import dcrypt.crypto.modes.gcm.multiplier;


// BUG: llvm crashes when using GCMMultiplier64kTable
alias GHashGeneral!GCMMultiplier8kTable GHash;

/// Params:
/// Multiplier = a GCM Multiplier like GCMMultiplier8kTable
@safe
public struct GHashGeneral(Multiplier) if(isGCMMultiplier!Multiplier)
{
	enum BLOCKSIZE = 16;				/// block size in bytes

	alias ubyte T;
	alias T[BLOCKSIZE/(T.sizeof)] block;

	private {

		block stateCipher;	/// state for cipher data hashing
		block H;
		block stateAAD;		/// state for AAD hashing
		block stateAADPre; 	/// stateAAD before first cipher byte is processed
	
		ubyte stateAADOff = 0; 			/// offset in stateAAD buffer
		ubyte stateCipherOff = 0; 		/// offset in stateCipher buffer

		ulong lenAAD = 0;				/// length of additional authenticated data (AAD) in bits
		ulong lenAADPre = 0;			/// length of AAD before first cipher byte is processed
		ulong lenCipher = 0;			/// length of authenticated cipher data in bits

		bool aadInput = true; 			/// AAD or cipher input

		Multiplier gcmMult;
	}

	invariant {
		// offsets should never exceed their boundaries
		assert(stateAADOff <= BLOCKSIZE);
		assert(stateCipherOff <= BLOCKSIZE);
	}

	/// Params:
	/// H = element of GF(2^128)
	this(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == BLOCKSIZE, "H must be 16 bytes");
	}
	body {
		init(H);
	}

	/// initialize the hash
	/// Params:
	/// H = the factor used for multiplication.
	public void init(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == BLOCKSIZE, "H must be 16 bytes");
	}
	body {
		this.H[] = H[];
		
		// init the multiplier
		gcmMult.init(H);
	}

	
	/// add data to the AAD stream
	/// Params:
	/// aad = data to be authenticated only
	public void updateAAD(in ubyte[] aad...) nothrow @nogc
	{
		update(stateAAD, stateAADOff, aad);
		lenAAD += aad.length*8;
	}

	/// Call this before processing any cipher data for better performance.
	private void finalizeAAD() nothrow @nogc {

		stateCipher[] = stateAAD[];

		if(lenAAD > 0) {
			stateAADPre[] = stateAAD[];
			lenAADPre = lenAAD;
		}

		if(stateAADOff > 0) {
			// process partial block
			multiplyH(stateCipher);
			stateAADOff = 0;
		}
		aadInput = false;
	}

	/**
	 * Params:
	 * input = encrypted data
	 */
	public void updateCipherData(in ubyte[] input...) nothrow @nogc 
	{
		if(aadInput) {
			finalizeAAD(); // sets aadInput = false
		}
		update(stateCipher, stateCipherOff, input);
		lenCipher += input.length*8;
	}

	/// do final hash round and copy hash to buf
	/// resets GHASH
	/// Params: buf = output buffer for hash value
	public void doFinal(ubyte[] buf) nothrow @nogc
	in {
		assert(buf.length >= BLOCKSIZE, "output buffer too short");	
	}
	body {

		if(stateAADOff > 0) {
			// process last partial AAD block
			multiplyH(stateAAD);
			stateAADOff = 0;
		}

		// process last incomplete block
		if(stateCipherOff > 0) {
			multiplyH(stateCipher);
			stateCipherOff = 0;
		}

		if(lenAAD > lenAADPre) {
			// some AAD has been processed after first cipher bytes arrived
			// need to adjust the MAC state

			// caluculate the difference
			stateAADPre[] ^= stateAAD[];

			ulong blockDiff = (lenCipher + 127) / 128;	// number of cipher data blocks. 
			// + 127 added for rounding up.

			// calculate H^blockDiff
			ubyte[BLOCKSIZE] expH;
			expH[] = H[];
			GF128.power(expH, blockDiff);

			// propagate the difference to the current block
			GF128.multiply(stateAADPre, expH);

			// add the difference to the current block
			stateCipher[] ^= stateAADPre[];
		}

		// Add a block containing the length of both streams:	X ^ (len(A)||len(C)) * H
		foreach(i;0..8) {
			stateCipher[i] ^= lenAAD >> (56-8*i);
			stateCipher[i+8] ^= lenCipher >> (56-8*i);
		}

		multiplyH(stateCipher);

		buf[0..BLOCKSIZE] = stateCipher[];

		reset();
	}

	/// Reset the internal state.
	public void reset() nothrow @nogc {
		stateAAD[] = 0;
		stateAADOff = 0;	
		stateCipher[] = 0;
		stateCipherOff = 0;
		lenCipher = 0;
		lenAAD = 0;

		lenAADPre = 0;
		stateAADPre[] = 0;

		aadInput = true;
	}

	/// xor X with input bytes and do GF multiplication by H if buffer is full
	/// Params:
	/// input = incoming data
	/// state = update this state
	/// statePos = pointer to the location where the next byte gets written
	private void update(ubyte[] state, ref ubyte statePos, in ubyte[] input...) nothrow @nogc
	in {
		assert(state.length == 16);
	}
	body {
		import std.algorithm: min;
		
		const(ubyte)[] iBuf = input;

		if(statePos == BLOCKSIZE) {
			multiplyH(state);
			statePos = 0;
		}
		
		while(iBuf.length > 0) {
			
			size_t procLen = min(iBuf.length, BLOCKSIZE-statePos);

			state[statePos..statePos+procLen] ^= iBuf[0..procLen];
			
			statePos += procLen;
			iBuf = iBuf[procLen..$];

			if(statePos == BLOCKSIZE) {
				multiplyH(state);
				statePos = 0;
			}
		}
	}

	/// Multiply x by H, store result in x.
	private void multiplyH(ubyte[] x) nothrow @nogc {
		gcmMult.multiply(x);
	}

	// unittests

	unittest {
		GHash gHash = GHash(cast(const(ubyte)[])x"66e94bd4ef8a2c3b884cfa59ca342b2e");
		
		ubyte[16] token;
		gHash.doFinal(token);
		
		const(ubyte)[] EK0 = cast(const(ubyte)[])x"58e2fccefa7e3061367f1d57a4e7455a";
		token[] ^= EK0[];

		assert(token == cast(const(ubyte)[])x"58e2fccefa7e3061367f1d57a4e7455a");
	}

	unittest {

		GHash gHash = GHash(cast(const(ubyte)[])x"66e94bd4ef8a2c3b884cfa59ca342b2e");

		gHash.updateCipherData(cast(const(ubyte)[])x"0388dace60b6a392f328c2b971b2fe78");

		// check X1
		assert(gHash.stateCipher == cast(const(ubyte)[])x"5e2ec746917062882c85b0685353deb7");

		ubyte[16] hash;
		gHash.doFinal(hash);

		assert(hash == cast(const(ubyte[]))x"f38cbb1ad69223dcc3457ae5b6b0f885");
	}

	// test vectors from
	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	// section 2.1.1
	unittest {

		GHash gHash = GHash(cast(const(ubyte)[])x"73A23D80121DE2D5A850253FCF43120E");

		gHash.updateAAD(cast(const(ubyte)[])x"D609B1F056637A0D46DF998D88E5222A");
		gHash.updateAAD(cast(const(ubyte)[])x"B2C2846512153524C0895E8108000F10");
		gHash.updateAAD(cast(const(ubyte)[])x"1112131415161718191A1B1C1D1E1F20");
		gHash.updateAAD(cast(const(ubyte)[])x"2122232425262728292A2B2C2D2E2F30");
		gHash.updateAAD(cast(const(ubyte)[])x"313233340001");

		ubyte[16] token;
		gHash.doFinal(token);

		assert(token == cast(const(ubyte)[])x"1BDA7DB505D8A165264986A703A6920D");
	}

	// test vectors from
	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	// section 2.4.1
	unittest {

		GHash gHash = GHash(cast(const(ubyte)[])x"E4E01725D724C1215C7309AD34539257");
		
		gHash.updateAAD(cast(const(ubyte)[])x"E20106D7CD0DF0761E8DCD3D88E54C2A");
		gHash.updateAAD(cast(const(ubyte)[])x"76D457ED");

		gHash.updateCipherData(cast(const(ubyte)[])x"13B4C72B389DC5018E72A171DD85A5D3");
		gHash.updateCipherData(cast(const(ubyte)[])x"752274D3A019FBCAED09A425CD9B2E1C");
		gHash.updateCipherData(cast(const(ubyte)[])x"9B72EEE7C9DE7D52B3F3");

		ubyte[16] ghash;
		gHash.doFinal(ghash);
		
		assert(ghash == cast(const(ubyte)[])x"2A807BDE4AF8A462D467D2FFA3E1D868");
	}

	// test vectors from
	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	// section 2.8.1
	unittest {
		
		GHash gHash = GHash(cast(const(ubyte)[])x"AE19118C3B704FCE42AE0D15D2C15C7A");
		
		gHash.updateAAD(cast(const(ubyte)[])x"68F2E77696CE7AE8E2CA4EC588E54D00");
		gHash.updateAAD(cast(const(ubyte)[])x"2E58495C");

		gHash.updateCipherData(cast(const(ubyte)[])x"C31F53D99E5687F7365119B832D2AAE7");
		gHash.updateCipherData(cast(const(ubyte)[])x"0741D593F1F9E2AB3455779B078EB8FE");
		gHash.updateCipherData(cast(const(ubyte)[])x"ACDFEC1F8E3E5277F8180B43361F6512");
		gHash.updateCipherData(cast(const(ubyte)[])x"ADB16D2E38548A2C719DBA7228D840");
		
		ubyte[16] ghash;
		gHash.doFinal(ghash);
		
		assert(ghash == cast(const(ubyte)[])x"5AAA6FD11F06A18BE6E77EF2BC18AF93");
	}

	/// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
	/// test case 16
	unittest {

		// init gHash with H = acbef...
		GHash gHash = GHash(cast(const(ubyte)[])x"acbef20579b4b8ebce889bac8732dad7");

		// process AAD
		gHash.updateAAD(cast(const(ubyte)[])x"feedfacedeadbeeffeedfacedeadbeef");
		gHash.updateAAD(cast(const(ubyte)[])x"abaddad2");

		// process cipher data
		gHash.updateCipherData(cast(const(ubyte)[])x"522dc1f099567d07f47f37a32a84427d");
		gHash.updateCipherData(cast(const(ubyte)[])x"643a8cdcbfe5c0c97598a2bd2555d1aa");
		gHash.updateCipherData(cast(const(ubyte)[])x"8cb08e48590dbb3da7b08b1056828838");
		gHash.updateCipherData(cast(const(ubyte)[])x"c5f61e6393ba7a0abcc9f662");

		// get the final hash value
		ubyte[16] ghash;
		gHash.doFinal(ghash);
		
		assert(ghash == cast(const(ubyte)[])x"8bd0c4d8aacd391e67cca447e8c38f65");
	}

	// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
	// test case 16
	// AAD and cipher data come out of order
	unittest {

		GHash gHash = GHash(cast(const(ubyte)[])x"acbef20579b4b8ebce889bac8732dad7");

		gHash.updateAAD(cast(const(ubyte)[])x"feedfacedeadbeeffeedfacedeadbeef");

		gHash.updateCipherData(cast(const(ubyte)[])x"522dc1f099567d07f47f37a32a84427d");
		gHash.updateCipherData(cast(const(ubyte)[])x"643a8cdcbfe5c0c97598a2bd2555d1aa");
		gHash.updateCipherData(cast(const(ubyte)[])x"8cb08e48590dbb3da7b08b1056828838");
		gHash.updateCipherData(cast(const(ubyte)[])x"c5f61e6393ba7a0abcc9f662");

		gHash.updateAAD(cast(const(ubyte)[])x"abaddad2");

		
		ubyte[16] ghash;
		gHash.doFinal(ghash);

		assert(ghash == cast(const(ubyte)[])x"8bd0c4d8aacd391e67cca447e8c38f65");

		// gHash should now be resetted, so do the same thing again

		gHash.updateAAD(cast(const(ubyte)[])x"feedfacedeadbeeffeedfacedeadbeef");
		
		gHash.updateCipherData(cast(const(ubyte)[])x"522dc1f099567d07f47f37a32a84427d");
		gHash.updateCipherData(cast(const(ubyte)[])x"643a8cdcbfe5c0c97598a2bd2555d1aa");
		gHash.updateCipherData(cast(const(ubyte)[])x"8cb08e48590dbb3da7b08b1056828838");
		
		gHash.updateAAD(cast(const(ubyte)[])x"abaddad2");
		
		gHash.updateCipherData(cast(const(ubyte)[])x"c5f61e6393ba7a0abcc9f662");

		gHash.doFinal(ghash);
		
		assert(ghash == cast(const(ubyte)[])x"8bd0c4d8aacd391e67cca447e8c38f65");
	}

}

