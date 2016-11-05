module dcrypt.streamcipher.chacha;

import std.algorithm: min;
import std.conv: text;
import std.range;

import dcrypt.streamcipher.streamcipher;
import dcrypt.util;
import dcrypt.bitmanip;

/// Implementation of the ChaCha stream cipher as first described by D. J. Bernstein (http://cr.yp.to/chacha.html),
/// following RFC 7539.
/// 
/// Standard: RFC 7539
/// 
/// Note: This might not be compatible with BouncyCastle's implementation because that one uses a 64-bit counter. 
/// 

alias ChaCha!20 ChaCha20;
alias ChaCha!12 ChaCha12;

static assert(isStreamCipher!ChaCha20, "ChaCha20 is not a stream cipher!");
static assert(isStreamCipher!ChaCha12, "ChaCha12 is not a stream cipher!");

public struct ChaCha(uint rounds) if(rounds % 2 == 0)  {

	@safe nothrow @nogc:

	public {
		enum name = text("ChaCha", rounds);
	}

	private {
		static immutable uint[4] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

		uint[16] state;

		ubyte[16*4] keyStream;
		size_t keyStreamIndex = 0;

		bool initialized = false;
	}

	~this () {
		wipe(state);
		wipe(keyStream);
	}

	/// Initialize the ChaCha20 stream cipher.
	/// 
	/// Params:
	/// forEncryption = Not used, because encryption and decryptioin are the same.
	/// key = A secret key of 32 bytes length (256 bit).
	/// iv = A nonce of 12 bytes length (96 bit).
	/// initial_counter = The initial value of the counter. The default is 1. (Set this to 2 to skip the first block.)
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] iv, in uint initial_counter = 1)
	in {
		assert(key.length == 32, "ChaCha requires a 32 byte key.");
		assert(iv.length == 12, "ChaCha requires a 12 byte nonce.");
	} body {

		ubyte[32] _key = key;
		ubyte[12] _iv = iv;

		initState(state, _key, initial_counter, _iv);
		keyStreamIndex = 0;
		initialized = true;
	}

	/// Returns: Slice pointing to processed data which might be smaller than `output`.
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output)
	in {
		assert(initialized, "ChaCha not initialized.");
		assert(output.length >= input.length, "Output buffer too small.");
	} body {
		
		const (ubyte)[] inp = input;
		ubyte[] initialOutput = output;
		
		while(inp.length > 0) {
			
			if (keyStreamIndex == 0) {
				genKeyStream();
			}
			
			size_t len = min(keyStream.length-keyStreamIndex, inp.length);
			output[0..len] = inp[0..len] ^ keyStream[keyStreamIndex..keyStreamIndex+len];
			keyStreamIndex = (keyStreamIndex + len) % keyStream.length;

			inp = inp[len..$];
			output = output[len..$];
		}

		return initialOutput[0..input.length]; // Return slice to processed data.
	}

	ubyte processByte(in ubyte b)
	in {
		assert(initialized, "ChaCha not initialized.");
	} body {
		
		if (keyStreamIndex == 0) {
			genKeyStream();
		}
		
		enum len = 1;
		ubyte o = b ^ keyStream[keyStreamIndex];
		keyStreamIndex = (keyStreamIndex + len) % keyStream.length;

		return o;
	}
	
	/// Performs a ChaCha quarter round on a, b, c, d
	/// Params:
	/// a, b, c, d = Values to perform the round on. They get modified.
	private static void quarterRound(ref uint a, ref uint b, ref uint c, ref uint d) pure {
		a += b;  d = rol(d^a, 16);
		c += d;  b = rol(b^c, 12);
		a += b;  d = rol(d^a, 8);
		c += d;  b = rol(b^c, 7);
	}
	
	// Test quarter round.
	// Test vectors from RFC7539, section 2.1.1
	unittest {
		uint a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
		quarterRound(a, b, c, d);
		
		assert(a == 0xea2a92f4 && b == 0xcb1cf8ce && c == 0x4581472e && d == 0x5881c4bb,
			"ChaCha quarter round is doing weird things...");
	}

	/// Do a ChaCha permutation on the input by applying n times the inner round function.
	/// This is actually the block function without adding the input to the permutation.
	public static void permute(ref uint[16] state) pure {
		foreach(i; 0..rounds / 2) {
			innerRound(state);
		}
	}

	private static void innerRound(ref uint[16] state) pure {
		quarterRound(state[0], state[4], state[8], state[12]);
		quarterRound(state[1], state[5], state[9], state[13]);
		quarterRound(state[2], state[6], state[10], state[14]);
		quarterRound(state[3], state[7], state[11], state[15]);

		quarterRound(state[0], state[5], state[10], state[15]);
		quarterRound(state[1], state[6], state[11], state[12]);
		quarterRound(state[2], state[7], state[8], state[13]);
		quarterRound(state[3], state[4], state[9], state[14]);
	}

	/// Set the state as follows:
	/// state = constants ~ key ~ counter ~ nonce
	/// 
	/// Params:
	/// state = The state.
	/// key = 32 bytes.
	/// nonce = 12 bytes.
	private static void initState(ref uint[16] state, in ubyte[] key, in uint counter, in ubyte[] nonce) pure 
	in {
		assert(key.length == 32, "ChaCha requires 256 bit key.");
		assert(nonce.length == 12, "ChaCha requires 96 bit nonce.");
	} body {
		state[0..4] = constants;
		fromLittleEndian(key[0..32], state[4..12]);
		state[12] = counter;
		fromLittleEndian(nonce[0..12], state[13..16]);
	}

	/// Performs the ChaCha block function on `inState`, result in `outState`
	/// Params:
	/// inState = the state created with `initState()`
	/// outState = buffer for the new state
	private static void block(in ref uint[16] inState, ref uint[16] outState) pure
	{
		uint[16] workingState = inState;

		permute(workingState);

		workingState[] += inState[];
		outState[] = workingState[];
	}

	/// Performs the ChaCha block function on `inState`, result in `outState`
	/// Params:
	/// inState = the state created with `initState()`
	/// outState = buffer for the new state
	private static void block(in ref uint[16] inState, ref ubyte[16*4] outState) pure 
	{
		uint[16] key;
		block(inState, key);
		toLittleEndian!uint(key, outState);
	}

	/// Generate a block of key stream and write it to `keyStream`.
	private void genKeyStream() 
	in {
		assert(initialized, "ChaCha not initialized.");
		assert(state[12] < uint.max, "ChaCha: Counter overflow.");
	} body {
		// generate the key stream
		block(state, keyStream);
		++state[12];
	}
}



// test the ChaCha20 block function.
unittest {
	
	ubyte[32] key = cast(const ubyte[]) x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	uint counter = 1;
	ubyte[12] nonce = cast(const ubyte[]) x"000000090000004a00000000";
	
	uint[16] state;
	
	ChaCha20.initState(state, key, counter, nonce);
	
	enum uint[16] expectedInitialState = [
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000
	];

	assert(state == expectedInitialState, "initState() failed!");

	ChaCha20.block(state, state);
	
	enum uint[16] expectedState= [
		0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
		0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
		0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
		0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
	];
	
	assert(state == expectedState, "chaCha20Block() failed!");
	
	ubyte[16*4] keyStream;
	
	toLittleEndian!uint(state, keyStream);
	
	ubyte[16*4] expectedKeyStream = cast(const ubyte[]) x"
			10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
			c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
			d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
			b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e";
	
	assert(keyStream == expectedKeyStream, "Got unexpected key stream.");
}