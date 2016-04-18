module dcrypt.ecc.curve25519;

import dcrypt.ecc.curved25519.fieldElement;
import dcrypt.util: wipe;

/// Implementation of Curve25519.
///
///


/// Generate a public key from a secret. 
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;
	
	key_t secretKey = cast(key_t) x"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	
	key_t publicKey = curve25519_scalarmult(secretKey);
	
	auto expectedPublic = x"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
	
	assert(publicKey == expectedPublic, "curve25519 public key generation failed!");
}

/// Generate a public key from a secret. 
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;
	
	key_t secretKey = cast(key_t) x"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
	
	key_t publicKey = curve25519_scalarmult(secretKey);
	
	auto expectedPublic = x"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
	
	assert(publicKey == expectedPublic, "curve25519 public key generation failed!");
}

/// DH key exchange
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;
	
	key_t priv1, priv2, pub1, pub2;
	priv1[] = cast(key_t) x"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	priv2[] = cast(key_t) x"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
	
	pub1 = curve25519_scalarmult(priv1);
	pub2 = curve25519_scalarmult(priv2);
	
	key_t shared1, shared2;
	
	// Generate the shared keys. Both should be equal.
	shared1 = curve25519_scalarmult(priv1, pub2);
	shared2 = curve25519_scalarmult(priv2, pub1);
	
	auto expectedSharedSecret = x"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
	
	assert(shared1 == expectedSharedSecret, "curve25519 DH key agreement failed!");
	assert(shared1 == shared2, "curve25519 DH key agreement failed!");
}

unittest {
	alias ubyte[32] key_t;
	key_t a = 1;
	key_t b = 2;

	key_t A = curve25519_scalarmult(a);
	key_t B = curve25519_scalarmult(b);

	key_t sa = curve25519_scalarmult(a, B);
	key_t sb = curve25519_scalarmult(b, A);

	assert(sa == sb, "DH failed.");
}

/// The default public base point.
public enum ubyte[32] publicBasePoint = cast(immutable (ubyte[32]) ) x"0900000000000000000000000000000000000000000000000000000000000000";

@safe nothrow @nogc:

/// 
/// 
/// Params:
/// secret = Your secret key, the 'exponent'.
/// p = Receivers public key. Default base point = 9.
/// 
/// Returns: p^secret.
/// 
/// Examples:
/// 
/// ubyte[32] publicKey = curve25519_scalarmult(secretKey);
/// 
/// ubyte[32] sharedKey = curve25519_scalarmult(mySecretKey, herPublicKey);
/// 
ubyte[32] curve25519_scalarmult(in ubyte[] secret, in ubyte[] p = publicBasePoint) @safe nothrow @nogc
in {
	assert(secret.length == 32, "Secret key must be 32 bytes long.");
	assert(p.length == 32, "Public key must be 32 bytes long.");
} body {
	ubyte[32] sec = secret;
	scope(exit) {
		wipe(sec);
	}

	ubyte[32] pub = p;

	return curve25519_scalarmult(sec, pub);
}

/// 
/// 
/// Params:
/// secret = Your secret key, the 'exponent'.
/// p = Receivers public key. Default base point = 9.
/// 
/// Returns: p^secret.
/// 
/// Examples:
/// 
/// ubyte[32] publicKey = curve25519_scalarmult(secretKey);
/// 
/// ubyte[32] sharedKey = curve25519_scalarmult(mySecretKey, herPublicKey);
/// 
ubyte[32] curve25519_scalarmult(in ref ubyte[32] secret, in ref ubyte[32] p = publicBasePoint) @safe nothrow @nogc
{
	ubyte[32] e = secret;
	scope(exit) {
		wipe(e);
	}
	clamp(e);

	fe x1, x2, x3, z2, z3, tmp0, tmp1;
	scope(exit) {
		wipe(x1);
		wipe(x2);
		wipe(x3);
		wipe(z2);
		wipe(z3);
		wipe(tmp0);
		wipe(tmp1);
	}

	x1 = fe.fromBytes(p);
	x2 = fe.one;
	z2 = fe.zero;
	x3 = x1;
	z3 = fe.one;

	uint swap = 0, b;
	for (int pos = 254; pos >= 0;--pos) {
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

	x2 *= z2.inverse;
	return x2.toBytes;
}

/// Transforms 32 random bytes into a valid secret key.
/// 
/// Params:
/// sk = 32 byte secret key.
package void clamp(ubyte[] sk) pure
in {
	assert(sk.length == 32);
} body {
	sk[0] &= 248;
	sk[31] &= 63;
	sk[31] |= 64;
}