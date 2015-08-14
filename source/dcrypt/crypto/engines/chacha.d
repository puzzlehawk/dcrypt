module dcrypt.crypto.engines.chacha;

import dcrypt.util.util;
import dcrypt.util.bitmanip;
import dcrypt.util.pack;

@safe nothrow @nogc
public struct ChaCha {

	public {
		enum name = "ChaCha"~rounds;
	}

	private {
		enum rounds = 20;
		enum uint[4] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

		uint[16] state;
		ubyte[16*4] keyStream;
	}

	~this () {
		wipe(state);
		wipe(keyStream);
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
	private static void initState(ref uint[16] state, in ref ubyte[32] key, in uint counter, in ref ubyte[12] nonce) pure {
		state[0..4] = constants;
		fromLittleEndian(key[], state[4..12]);
		state[12] = counter;
		fromLittleEndian(nonce[], state[13..16]);
	}

	private static void chaCha20Block(in ref uint[16] inState, ref uint[16] outState) pure {
	
		uint[16] workingState = inState;

		static assert(rounds % 2 == 0, "'rounds' must be even.");
		foreach(i; 0..rounds / 2) {
			innerRound(workingState);
		}

		workingState[] += inState[];
		outState[] = workingState[];
	}

	private void incrementCounter() {
		state[12]++;
	}

	/// Generate a block of key stream and write it to `keyStream`.
	private void genKeyStream() {

		uint[16] key;
		chaCha20Block(state, key);
		toLittleEndian!uint(key, keyStream);

		incrementCounter();

	}

	// test the ChaCha20 block function.
	unittest {
		ubyte[32] key = cast(const ubyte[]) x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		uint counter = 1;
		ubyte[12] nonce = cast(const ubyte[]) x"000000090000004a00000000";

		uint[16] state;

		ChaCha.initState(state, key, counter, nonce);
		ChaCha.chaCha20Block(state, state);

		enum uint[16] expectedState= [
			0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
			0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
			0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
			0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
		];

		assert(state == expectedState, "chaCha20Block() failed!");
	}

}