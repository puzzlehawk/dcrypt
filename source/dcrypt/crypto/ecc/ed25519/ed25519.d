module dcrypt.crypto.ecc.ed25519.ed25519;

import dcrypt.crypto.ecc.ed25519.groupElement;
import dcrypt.crypto.digests.sha2: SHA512;

/// Generate a ed25519 public key from a secret key.
unittest {
	//	draft-josefsson-eddsa-ed25519-03
	//	-----TEST 1
	
	immutable ubyte[32] sk = cast(const ubyte[]) x"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
	immutable ubyte[32] expectedPk = cast(const ubyte[]) x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

	immutable ubyte[32] pk = secret_to_public(sk);

	assert(pk == expectedPk, "ed25519 crypto_sign_pubkey failed.");
}

/// Test signing and verifying.
/// Test vectors from http://ed25519.cr.yp.to/python/sign.input.
unittest {

	immutable ubyte[32] sk = cast(const ubyte[]) x"9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60";
	immutable ubyte[32] pk = secret_to_public(sk);

	assert(pk == x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "Ed25519 generated unexpected public key.");

	immutable ubyte[0] message = cast(const ubyte[]) "";

	immutable ubyte[64] signature = sign(message, sk);

	immutable auto expectedSig = x"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
	assert(signature[0..32] == expectedSig[0..32], "Ed25519 signature: wrong R.");
	assert(signature[32..64] == expectedSig[32..64], "Ed25519 produced unexpected signature.");

	immutable bool valid = verify(signature, message, pk);
	assert(valid, "Ed25519 signature verificaton failed.");

	assert(!verify(signature, cast(const ubyte[]) "asdf", pk), "Ed25519 signature verificaton failed.");
}

@safe nothrow @nogc:

/// Params:
/// sig = buffer for signature
/// m = message
/// sk = secret key
/// pk = public key
public ubyte[64] sign(
	in ubyte[] m,
	in ubyte[] sk
	//in ubyte[] pk
	)
in {
	assert(sk.length == 32);
	//assert(pk.length == 32);
} body {
	ubyte[64] sig;
	ubyte[32] r, h;

	ge_p3 R;

	immutable ubyte[64] expandedSecret = secret_expand(sk);

	immutable ubyte[32] pk = secret_to_public(sk); // TODO optimize, use expanded secret
	//ge_scalarmult_base(A, expandedSecret[0..32]);

	// sha512_modq
	SHA512 sha;
	sha.put(expandedSecret[32..64]);
	sha.put(m);
	r = sc_reduce(sha.finish());

	R = ge_scalarmult_base(r);
	ge_p3_tobytes(sig[0..32], R);

	// sha512modq
	sha.put(sig[0..32]);
	sha.put(pk[0..32]);
	sha.put(m);
	h = sc_reduce(sha.finish());

	sig[32..64] = sc_muladd(h, expandedSecret[0..32], r);

	return sig;
}

//private ubyte[32] sha512modq(T)(in T s...) {
//	SHA512 hash;
//	foreach(a; s) {
//		hash.put(a);
//	}
//	return sc_reduce(hash.finish());
//}

/// ref10
//int crypto_sign(
//	unsigned char *sm,unsigned long long *smlen,
//	const unsigned char *m,unsigned long long mlen,
//	const unsigned char *sk
//	)
//{
//	unsigned char pk[32];
//	unsigned char az[64];
//	unsigned char nonce[64];
//	unsigned char hram[64];
//	ge_p3 R;
//	
//	memmove(pk,sk + 32,32);
//	
//	crypto_hash_sha512(az,sk,32);
//	az[0] &= 248;
//	az[31] &= 63;
//	az[31] |= 64;
//	
//	*smlen = mlen + 64;
//	memmove(sm + 64,m,mlen);
//	memmove(sm + 32,az + 32,32);
//	crypto_hash_sha512(nonce,sm + 32,mlen + 32);
//	memmove(sm + 32,pk,32);
//	
//	sc_reduce(nonce);
//	ge_scalarmult_base(&R,nonce);
//	ge_p3_tobytes(sm,&R);
//	
//	crypto_hash_sha512(hram,sm,mlen + 64);
//	sc_reduce(hram);
//	sc_muladd(sm + 32,hram,az,nonce);
//	
//	return 0;
//}

/// Params:
/// signature = 64 bytes signature.
/// m = The signed message.
/// pk = The public key.
public bool verify(
	in ubyte[] signature,
	in ubyte[] m,
	in ubyte[] pk
	)
in {
	assert(signature.length == 64);
	assert(pk.length == 32);
} body {
	ubyte[32] rCopy, sCopy, rCheck;
	ge_p3 A;
	ge_p2 R;

	if (signature[63] & 224) return false;	// bad signature
	if (!ge_frombytes_negate_vartime(A, pk)) return false; // bad signature

	//	memmove(pkcopy,pk,32);
	//	memmove(rcopy,signature,32);
	//	memmove(scopy,signature + 32,32);

	rCopy[] = signature[0..32];
	sCopy[] = signature[32..64];

	SHA512 sha;
	sha.put(rCopy);
	sha.put(pk[0..32]);
	sha.put(m);
	//crypto_hash_sha512_3(h, rcopy, 32, pkcopy, 32, m, mlen);
	immutable ubyte[32] h = sc_reduce(sha.finish());
	
	ge_double_scalarmult_vartime(R, h, A, sCopy);
	ge_tobytes(rCheck, R);

	
	return crypto_equals(rCheck, rCopy);
}


///* Modified for Tor: new API, 64-byte secret keys. */
///
//#include <string.h>
//#include "randombytes.h"
//#include "crypto_sign.h"
//#include "crypto_hash_sha512.h"
//#include "ge.h"
//
//int crypto_sign_seckey(unsigned char *sk)
//{
//	unsigned char seed[32];
//	
//	if (randombytes(seed,32) < 0)
//		return -1;
//	
//	crypto_sign_seckey_expand(sk, seed);
//	
//	memwipe(seed, 0, 32);
//	
//	return 0;
//}

//void crypto_sign_seckey_expand(ref ubyte[32] sk, in ref ubyte[32] skSeed)
//{
//	SHA512 hash;
//	hash.put(skSeed);
//	sk = hash.finish()[0..32];
//	//crypto_hash_sha512(sk,skseed,32);
//	clamp(sk[0..32]);
//}

/// Generate public key from secret key. Secret key must be clamped.
ubyte[32] secret_to_public(in ubyte[] sk)
in {
	assert(sk.length == 32, "Invalid secret key length. Must be 32.");
	//assert((sk[0] & ~248) == 0 || (sk[31] & ~63) == 0 || (sk[31] & 64) == 64, "Invalid secret key!");
} body {
	ge_p3 A;
	ubyte[32] secret = secret_expand(sk)[0..32];
	ubyte[32] pk;
	assert((secret[0] & ~248) == 0 || (secret[31] & ~63) == 0 || (secret[31] & 64) == 64, "Invalid secret key!");
	A = ge_scalarmult_base(secret);
	ge_p3_tobytes(pk[], A);

	return pk;
}

ubyte[64] secret_expand(in ubyte[] sk) 
in {
	assert(sk.length == 32, "Invalid secret key length. Must be 32.");
} body {
	ubyte[64] secret;
	
	SHA512 hash;
	hash.put(sk[0..32]);
	secret = hash.finish();

	clamp(secret[0..32]);

	return secret;
}


/// Generate a keypair.
//void crypto_sign_keypair(ref ubyte[32] pk, ref ubyte[32] sk)
//{
//	crypto_sign_seckey(sk[]);
//	crypto_sign_pubkey(pk[], sk[]);
//}

/* Added to ref10 for Tor. We place this in the public domain.  Alternatively,
 * you may have it under the Creative Commons 0 "CC0" license. */
//#include "fe.h"
//#include "ed25519_ref10.h"

void ed25519_ref10_pubkey_from_curve25519_pubkey(ubyte[] outp,
	in ubyte[] inp,
	in int signbit)
in {
	assert(outp.length == 32, "Output buffer size must be 32.");
	assert(inp.length == 32, "Input size must be 32.");
	assert(signbit == 0 || signbit == 1, "signbit must be either 0 or 1.");
} body {
	fe u;
	fe one;
	fe y;
	fe uplus1;
	fe uminus1;
	fe inv_uplus1;
	
	/* From prop228:

	 Given a curve25519 x-coordinate (u), we can get the y coordinate
	 of the ed25519 key using

	 y = (u-1)/(u+1)
	 */
	fe_frombytes(u, inp);
	uminus1 = u - fe.one;
	uplus1 = u + fe.one;
	y = uminus1 * uplus1.inverse;
	
	outp[0..32] = y.toBytes;
	
	/* propagate sign. */
	outp[31] |= (!!signbit) << 7; // convert non zero values to 128
}

private:

/// Transforms 32 random bytes into a valid secret key.
/// 
/// Params:
/// sk = 32 byte secret key.
void clamp(ubyte[] sk) pure
in {
	assert(sk.length == 32);
} body {
	sk[0] &= 248;
	sk[31] &= 63;
	sk[31] |= 64;
}

/**
 Input:
 s[0]+256*s[1]+...+256^63*s[63] = s

 Output:
 s[0]+256*s[1]+...+256^31*s[31] = s mod l
 where l = 2^252 + 27742317777372353535851937790883648493.
 Overwrites s in place.
 */
ubyte[32] sc_reduce(in ubyte[] inp) pure
in {
	assert(inp.length == 64);
} body {
	long s0 = 0x001FFFFF & load_3(inp[0..3]);
	long s1 = 0x001FFFFF & (load_4(inp[2..6]) >> 5);
	long s2 = 0x001FFFFF & (load_3(inp[5..8]) >> 2);
	long s3 = 0x001FFFFF & (load_4(inp[7..11]) >> 7);
	long s4 = 0x001FFFFF & (load_4(inp[10..14]) >> 4);
	long s5 = 0x001FFFFF & (load_3(inp[13..16]) >> 1);
	long s6 = 0x001FFFFF & (load_4(inp[15..19]) >> 6);
	long s7 = 0x001FFFFF & (load_3(inp[18..21]) >> 3);
	long s8 = 0x001FFFFF & load_3(inp[21..24]);
	long s9 = 0x001FFFFF & (load_4(inp[23..27]) >> 5);
	long s10 = 0x001FFFFF & (load_3(inp[26..29]) >> 2);
	long s11 = 0x001FFFFF & (load_4(inp[28..32]) >> 7);
	long s12 = 0x001FFFFF & (load_4(inp[31..35]) >> 4);
	long s13 = 0x001FFFFF & (load_3(inp[34..37]) >> 1);
	long s14 = 0x001FFFFF & (load_4(inp[36..40]) >> 6);
	long s15 = 0x001FFFFF & (load_3(inp[39..42]) >> 3);
	long s16 = 0x001FFFFF & load_3(inp[42..45]);
	long s17 = 0x001FFFFF & (load_4(inp[44..48]) >> 5);
	long s18 = 0x001FFFFF & (load_3(inp[47..50]) >> 2);
	long s19 = 0x001FFFFF & (load_4(inp[49..53]) >> 7);
	long s20 = 0x001FFFFF & (load_4(inp[52..56]) >> 4);
	long s21 = 0x001FFFFF & (load_3(inp[55..58]) >> 1);
	long s22 = 0x001FFFFF & (load_4(inp[57..61]) >> 6);
	long s23 = (load_4(inp[60..64]) >> 3);
	long carry0;
	long carry1;
	long carry2;
	long carry3;
	long carry4;
	long carry5;
	long carry6;
	long carry7;
	long carry8;
	long carry9;
	long carry10;
	long carry11;
	long carry12;
	long carry13;
	long carry14;
	long carry15;
	long carry16;
	
	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;
	s23 = 0;
	
	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;
	s22 = 0;
	
	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;
	s21 = 0;
	
	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;
	s20 = 0;
	
	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;
	s19 = 0;
	
	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;
	s18 = 0;
	
	carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= SHL64(carry12,21);
	carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= SHL64(carry14,21);
	carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= SHL64(carry16,21);
	
	carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= SHL64(carry13,21);
	carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= SHL64(carry15,21);
	
	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;
	s17 = 0;
	
	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;
	s16 = 0;
	
	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;
	s15 = 0;
	
	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;
	s14 = 0;
	
	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;
	s13 = 0;
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	
	carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = s0 >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry1 = s1 >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry2 = s2 >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry3 = s3 >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry4 = s4 >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry5 = s5 >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry6 = s6 >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry7 = s7 >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry8 = s8 >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry9 = s9 >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry10 = s10 >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	carry11 = s11 >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = s0 >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry1 = s1 >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry2 = s2 >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry3 = s3 >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry4 = s4 >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry5 = s5 >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry6 = s6 >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry7 = s7 >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry8 = s8 >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry9 = s9 >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry10 = s10 >> 21; s11 += carry10; s10 -= SHL64(carry10,21);

	ubyte[32] s;
	s[0] = cast(ubyte) (s0 >> 0);
	s[1] = cast(ubyte) (s0 >> 8);
	s[2] = cast(ubyte) ((s0 >> 16) | SHL64(s1,5));
	s[3] = cast(ubyte) (s1 >> 3);
	s[4] = cast(ubyte) (s1 >> 11);
	s[5] = cast(ubyte) ((s1 >> 19) | SHL64(s2,2));
	s[6] = cast(ubyte) (s2 >> 6);
	s[7] = cast(ubyte) ((s2 >> 14) | SHL64(s3,7));
	s[8] = cast(ubyte) (s3 >> 1);
	s[9] = cast(ubyte) (s3 >> 9);
	s[10] = cast(ubyte) ((s3 >> 17) | SHL64(s4,4));
	s[11] = cast(ubyte) (s4 >> 4);
	s[12] = cast(ubyte) (s4 >> 12);
	s[13] = cast(ubyte) ((s4 >> 20) | SHL64(s5,1));
	s[14] = cast(ubyte) (s5 >> 7);
	s[15] = cast(ubyte) ((s5 >> 15) | SHL64(s6,6));
	s[16] = cast(ubyte) (s6 >> 2);
	s[17] = cast(ubyte) (s6 >> 10);
	s[18] = cast(ubyte) ((s6 >> 18) | SHL64(s7,3));
	s[19] = cast(ubyte) (s7 >> 5);
	s[20] = cast(ubyte) (s7 >> 13);
	s[21] = cast(ubyte) (s8 >> 0);
	s[22] = cast(ubyte) (s8 >> 8);
	s[23] = cast(ubyte) ((s8 >> 16) | SHL64(s9,5));
	s[24] = cast(ubyte) (s9 >> 3);
	s[25] = cast(ubyte) (s9 >> 11);
	s[26] = cast(ubyte) ((s9 >> 19) | SHL64(s10,2));
	s[27] = cast(ubyte) (s10 >> 6);
	s[28] = cast(ubyte) ((s10 >> 14) | SHL64(s11,7));
	s[29] = cast(ubyte) (s11 >> 1);
	s[30] = cast(ubyte) (s11 >> 9);
	s[31] = cast(ubyte) (s11 >> 17);

	return s;
}


/// Calculates (a*b + c) mod l
/// Input:
/// a[0]+256*a[1]+...+256^31*a[31] = a
/// b[0]+256*b[1]+...+256^31*b[31] = b
/// c[0]+256*c[1]+...+256^31*c[31] = c
///
/// Returns:
/// (a*b + c) mod l
/// s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
/// where l = 2^252 + 27742317777372353535851937790883648493.
ubyte[32] sc_muladd(in ubyte[] a, in ubyte[] b, in ubyte[] c) pure
in {
	assert(a.length == 32);
	assert(b.length == 32);
	assert(c.length == 32);
} body {
	// assign 21-bit slices to a*, b*, c*
	long a0 = 0x001FFFFF & load_3(a[0..3]);
	long a1 = 0x001FFFFF & (load_4(a[2..6]) >> 5);
	long a2 = 0x001FFFFF & (load_3(a[5..8]) >> 2);
	long a3 = 0x001FFFFF & (load_4(a[7..11]) >> 7);
	long a4 = 0x001FFFFF & (load_4(a[10..14]) >> 4);
	long a5 = 0x001FFFFF & (load_3(a[13..16]) >> 1);
	long a6 = 0x001FFFFF & (load_4(a[15..19]) >> 6);
	long a7 = 0x001FFFFF & (load_3(a[18..21]) >> 3);
	long a8 = 0x001FFFFF & load_3(a[21..24]);
	long a9 = 0x001FFFFF & (load_4(a[23..27]) >> 5);
	long a10 = 0x001FFFFF & (load_3(a[26..29]) >> 2);
	long a11 = (load_4(a[28..32]) >> 7);

	long b0 = 0x001FFFFF & load_3(b[0..3]);
	long b1 = 0x001FFFFF & (load_4(b[2..6]) >> 5);
	long b2 = 0x001FFFFF & (load_3(b[5..8]) >> 2);
	long b3 = 0x001FFFFF & (load_4(b[7..11]) >> 7);
	long b4 = 0x001FFFFF & (load_4(b[10..14]) >> 4);
	long b5 = 0x001FFFFF & (load_3(b[13..16]) >> 1);
	long b6 = 0x001FFFFF & (load_4(b[15..19]) >> 6);
	long b7 = 0x001FFFFF & (load_3(b[18..21]) >> 3);
	long b8 = 0x001FFFFF & load_3(b[21..24]);
	long b9 = 0x001FFFFF & (load_4(b[23..27]) >> 5);
	long b10 = 0x001FFFFF & (load_3(b[26..29]) >> 2);
	long b11 = (load_4(b[28..32]) >> 7);

	long c0 = 0x001FFFFF & load_3(c[0..3]);
	long c1 = 0x001FFFFF & (load_4(c[2..6]) >> 5);
	long c2 = 0x001FFFFF & (load_3(c[5..8]) >> 2);
	long c3 = 0x001FFFFF & (load_4(c[7..11]) >> 7);
	long c4 = 0x001FFFFF & (load_4(c[10..14]) >> 4);
	long c5 = 0x001FFFFF & (load_3(c[13..16]) >> 1);
	long c6 = 0x001FFFFF & (load_4(c[15..19]) >> 6);
	long c7 = 0x001FFFFF & (load_3(c[18..21]) >> 3);
	long c8 = 0x001FFFFF & load_3(c[21..24]);
	long c9 = 0x001FFFFF & (load_4(c[23..27]) >> 5);
	long c10 = 0x001FFFFF & (load_3(c[26..29]) >> 2);
	long c11 = (load_4(c[28..32]) >> 7);

	long s0;
	long s1;
	long s2;
	long s3;
	long s4;
	long s5;
	long s6;
	long s7;
	long s8;
	long s9;
	long s10;
	long s11;
	long s12;
	long s13;
	long s14;
	long s15;
	long s16;
	long s17;
	long s18;
	long s19;
	long s20;
	long s21;
	long s22;
	long s23;
	long carry0;
	long carry1;
	long carry2;
	long carry3;
	long carry4;
	long carry5;
	long carry6;
	long carry7;
	long carry8;
	long carry9;
	long carry10;
	long carry11;
	long carry12;
	long carry13;
	long carry14;
	long carry15;
	long carry16;
	long carry17;
	long carry18;
	long carry19;
	long carry20;
	long carry21;
	long carry22;
	
	s0 = c0 + a0*b0;
	s1 = c1 + a0*b1 + a1*b0;
	s2 = c2 + a0*b2 + a1*b1 + a2*b0;
	s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
	s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
	s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
	s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
	s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
	s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
	s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
	s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
	s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
	s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
	s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
	s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
	s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
	s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
	s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
	s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
	s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
	s20 = a9*b11 + a10*b10 + a11*b9;
	s21 = a10*b11 + a11*b10;
	s22 = a11*b11;
	s23 = 0;
	
	carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= SHL64(carry12,21);
	carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= SHL64(carry14,21);
	carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= SHL64(carry16,21);
	carry18 = (s18 + (1<<20)) >> 21; s19 += carry18; s18 -= SHL64(carry18,21);
	carry20 = (s20 + (1<<20)) >> 21; s21 += carry20; s20 -= SHL64(carry20,21);
	carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= SHL64(carry22,21);
	
	carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= SHL64(carry13,21);
	carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= SHL64(carry15,21);
	carry17 = (s17 + (1<<20)) >> 21; s18 += carry17; s17 -= SHL64(carry17,21);
	carry19 = (s19 + (1<<20)) >> 21; s20 += carry19; s19 -= SHL64(carry19,21);
	carry21 = (s21 + (1<<20)) >> 21; s22 += carry21; s21 -= SHL64(carry21,21);
	
	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;
	s23 = 0;
	
	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;
	s22 = 0;
	
	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;
	s21 = 0;
	
	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;
	s20 = 0;
	
	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;
	s19 = 0;
	
	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;
	s18 = 0;
	
	carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= SHL64(carry12,21);
	carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= SHL64(carry14,21);
	carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= SHL64(carry16,21);
	
	carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= SHL64(carry13,21);
	carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= SHL64(carry15,21);
	
	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;
	s17 = 0;
	
	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;
	s16 = 0;
	
	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;
	s15 = 0;
	
	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;
	s14 = 0;
	
	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;
	s13 = 0;
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	
	carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = s0 >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry1 = s1 >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry2 = s2 >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry3 = s3 >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry4 = s4 >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry5 = s5 >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry6 = s6 >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry7 = s7 >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry8 = s8 >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry9 = s9 >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry10 = s10 >> 21; s11 += carry10; s10 -= SHL64(carry10,21);
	carry11 = s11 >> 21; s12 += carry11; s11 -= SHL64(carry11,21);
	
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	
	carry0 = s0 >> 21; s1 += carry0; s0 -= SHL64(carry0,21);
	carry1 = s1 >> 21; s2 += carry1; s1 -= SHL64(carry1,21);
	carry2 = s2 >> 21; s3 += carry2; s2 -= SHL64(carry2,21);
	carry3 = s3 >> 21; s4 += carry3; s3 -= SHL64(carry3,21);
	carry4 = s4 >> 21; s5 += carry4; s4 -= SHL64(carry4,21);
	carry5 = s5 >> 21; s6 += carry5; s5 -= SHL64(carry5,21);
	carry6 = s6 >> 21; s7 += carry6; s6 -= SHL64(carry6,21);
	carry7 = s7 >> 21; s8 += carry7; s7 -= SHL64(carry7,21);
	carry8 = s8 >> 21; s9 += carry8; s8 -= SHL64(carry8,21);
	carry9 = s9 >> 21; s10 += carry9; s9 -= SHL64(carry9,21);
	carry10 = s10 >> 21; s11 += carry10; s10 -= SHL64(carry10,21);

	ubyte[32] s;
	s[0] = cast(ubyte) (s0 >> 0);
	s[1] = cast(ubyte) (s0 >> 8);
	s[2] = cast(ubyte) ((s0 >> 16) | SHL64(s1,5));
	s[3] = cast(ubyte) (s1 >> 3);
	s[4] = cast(ubyte) (s1 >> 11);
	s[5] = cast(ubyte) ((s1 >> 19) | SHL64(s2,2));
	s[6] = cast(ubyte) (s2 >> 6);
	s[7] = cast(ubyte) ((s2 >> 14) | SHL64(s3,7));
	s[8] = cast(ubyte) (s3 >> 1);
	s[9] = cast(ubyte) (s3 >> 9);
	s[10] = cast(ubyte) ((s3 >> 17) | SHL64(s4,4));
	s[11] = cast(ubyte) (s4 >> 4);
	s[12] = cast(ubyte) (s4 >> 12);
	s[13] = cast(ubyte) ((s4 >> 20) | SHL64(s5,1));
	s[14] = cast(ubyte) (s5 >> 7);
	s[15] = cast(ubyte) ((s5 >> 15) | SHL64(s6,6));
	s[16] = cast(ubyte) (s6 >> 2);
	s[17] = cast(ubyte) (s6 >> 10);
	s[18] = cast(ubyte) ((s6 >> 18) | SHL64(s7,3));
	s[19] = cast(ubyte) (s7 >> 5);
	s[20] = cast(ubyte) (s7 >> 13);
	s[21] = cast(ubyte) (s8 >> 0);
	s[22] = cast(ubyte) (s8 >> 8);
	s[23] = cast(ubyte) ((s8 >> 16) | SHL64(s9,5));
	s[24] = cast(ubyte) (s9 >> 3);
	s[25] = cast(ubyte) (s9 >> 11);
	s[26] = cast(ubyte) ((s9 >> 19) | SHL64(s10,2));
	s[27] = cast(ubyte) (s10 >> 6);
	s[28] = cast(ubyte) ((s10 >> 14) | SHL64(s11,7));
	s[29] = cast(ubyte) (s11 >> 1);
	s[30] = cast(ubyte) (s11 >> 9);
	s[31] = cast(ubyte) (s11 >> 17);

	return s;
}

// test sc_muladd
unittest {
	immutable auto expected = x"4b1aa2e4462a167d92e224e89293eaa7809accfcf60ad08497350a206ce2ec04";
	immutable ubyte[32] a = cast(const ubyte[]) x"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
	immutable ubyte[32] b = cast(const ubyte[]) x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
	immutable ubyte[32] c = cast(const ubyte[]) x"3e9a9575a249d64080e109b8851daa7026df4135a7195ad2d36252c5a90d0f03";

	// calculate (a*a + a) mod q

	assert(sc_muladd(a, b, c) == expected, "sc_muladd failed.");
	assert(sc_muladd(b, a, c) == expected, "sc_muladd failed.");
}