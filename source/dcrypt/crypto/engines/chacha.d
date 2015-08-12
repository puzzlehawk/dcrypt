module dcrypt.crypto.engines.chacha;

import dcrypt.util.bitmanip;
import dcrypt.util.pack;

@safe nothrow @nogc
public struct ChaCha {

	private {
		enum uint[4] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
		uint[16] state;
	}

	/// Performs a ChaCha quarter round on a, b, c, d
	/// Params:
	/// a, b, c, d = Values to perform the round on. They get modified.
	private static void quarterRound(ref uint a, ref uint b, ref uint c, ref uint d) {
		a += b; d ^= a; d = rol(d, 16);
		c += d; b ^= c; b = rol(b, 12);
		a += b; d ^= a; d = rol(d, 8);
		c += d; b ^= c; b = rol(b, 7);
	}
	
	// Test quarter round.
	// Test vectors from RFC7539, section 2.1.1
	unittest {
		uint a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
		quarterRound(a, b, c, d);
		
		assert(a == 0xea2a92f4 && b == 0xcb1cf8ce && c == 0x4581472e && d == 0x5881c4bb,
			"ChaCha quarter round is doing weird things...");
	}

	private void innerRound(ref uint[16] state) {
		quarterRound(state[0], state[4], state[8], state[12]);
		quarterRound(state[1], state[5], state[9], state[13]);
		quarterRound(state[2], state[6], state[10], state[14]);
		quarterRound(state[3], state[7], state[11], state[15]);

		quarterRound(state[0], state[5], state[10], state[15]);
		quarterRound(state[1], state[6], state[11], state[12]);
		quarterRound(state[2], state[7], state[8], state[13]);
		quarterRound(state[3], state[4], state[9], state[14]);
	}

	private void chaCha20Block(in ubyte[32] key, in uint counter, in ubyte[12] nonce) {
	
		state[0..4] = constants;
		fromLittleEndian(key[], state[4..12]);
		state[12] = counter;
		fromLittleEndian(nonce[], state[13..16]);

		uint[16] workingState = state;

		foreach(i; 0..10) {
			innerRound(workingState);
		}

		state[] += workingState[];

	}

	unittest {
		ubyte[32] key = cast(const ubyte[]) x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		uint counter = 1;
		ubyte[12] nonce = cast(const ubyte[]) x"000000090000004a00000000";

		ChaCha chacha;
		chacha.chaCha20Block(key, counter, nonce);

		import std.stdio;
		import dcrypt.util.encoders.hex;

		ubyte[16*4] byteState;
		toLittleEndian!uint(chacha.state, byteState);

		writeln(toHexStr(byteState[]));
	}

}