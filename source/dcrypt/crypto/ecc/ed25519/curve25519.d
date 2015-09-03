module dcrypt.crypto.ecc.ed25519.curve25519;

import dcrypt.crypto.ecc.ed25519.fieldElement;

/// Generate a public key from a secret. 
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;
	
	key_t secretKey = cast(key_t) x"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	
	key_t publicKey = crypto_scalarmult(secretKey);
	
	auto expectedPublic = x"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

	assert(publicKey == expectedPublic, "crypto_scalarmult with base point failed!");
}

unittest {
	alias ubyte[32] key_t;
	key_t a = 1;
	key_t b = 2;

	key_t A = crypto_scalarmult(a);
	key_t B = crypto_scalarmult(b);

	key_t sa = crypto_scalarmult(a, B);
	key_t sb = crypto_scalarmult(b, A);

	assert(sa == sb, "DH failed.");
}

public enum ubyte[32] publicBasePoint = cast(immutable (ubyte[32]) ) x"0900000000000000000000000000000000000000000000000000000000000000";

/// 
/// 
/// Params:
/// n = your secret key, the 'exponent'
/// p = public key. Default: base point 9
/// 
/// Returns: p^n.
/// 
/// Examples:
/// 
/// ubyte[32] publicKey = crypto_scalarmult(secretKey);
/// 
/// ubyte[32] sharedKey = crypto_scalarmult(mySecretKey, herPublicKey);
/// 
ubyte[32] crypto_scalarmult(in ref ubyte[32] n, in ref ubyte[32] p = publicBasePoint)
{
	ubyte[32] e;
	uint i;
	fe x1;
	fe x2;
	fe z2;
	fe x3;
	fe z3;
	fe tmp0;
	fe tmp1;
	int pos;
	uint swap, b;

	// TODO refactor
	for (i = 0;i < 32;++i) e[i] = n[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	x1 = fe.fromBytes(p);
	x2 = fe.one;
	z2 = fe.zero;
	x3 = x1;
	z3 = fe.one;
	
	swap = 0;
	for (pos = 254;pos >= 0;--pos) {
		b = e[pos / 8] >> (pos & 7);
		b &= 1;
		swap ^= b;
		fe_cswap(x2,x3,swap);
		fe_cswap(z2,z3,swap);
		swap = b;

		tmp0 = x3 - z3;

		tmp1 = x2 - z2;
		x2 += z2;
		z2 = x3 + z3;

		z3 = tmp0 * x2;

		z2 *= tmp1;
		tmp0 = tmp1.sq;
		tmp1 = x2.sq;
		x3 = z2 + z3;

		z2 = z3 - z2;
		x2 = tmp0 * tmp1;

		tmp1 -= tmp0;
		
		z2 = z2.sq;

		z3 = fe_mul121666(tmp1);

		x3 = x3.sq;

		tmp0 += z3;
		z3 = x1 * z2;

		z2 = tmp0 * tmp1;
	}
	fe_cswap(x2,x3,swap);
	fe_cswap(z2,z3,swap);

	z2 = z2.inverse;
	x2 *= z2;
	return x2.toBytes;
}

