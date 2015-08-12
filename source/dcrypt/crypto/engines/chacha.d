module dcrypt.crypto.engines.chacha;

import dcrypt.util.bitmanip;

@safe
public struct ChaCha {

	static void quarterRound(ref uint a, ref uint b, ref uint c, ref uint d) {
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

}