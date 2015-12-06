module dcrypt.crypto.ecc.ed25519;

import dcrypt.crypto.ecc.curved25519.groupElement;
import dcrypt.crypto.ecc.curve25519: clamp;
import dcrypt.crypto.digests.sha2: SHA512;
import dcrypt.util;

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

/// Sign a message with your secret key.
/// 
/// Params:
/// sig = buffer for signature
/// m = message
/// sk = secret key
/// pk = public key. Not necessary to provide it, but a bit faster.
public ubyte[64] sign(
	in ubyte[] m,
	in ubyte[] sk,
	in ubyte[] publicKey = null
	)
in {
	assert(sk.length == 32, "Secret key must be 32 bytes.");
	if(publicKey !is null) {
		assert(publicKey.length == 32, "Public key must be 32 bytes.");
	}
} body {
	ubyte[64] sig;
	ubyte[32] r, h;

	ge_p3 R;

	immutable ubyte[64] expandedSecret = secret_expand(sk);

	ubyte[32] pk; /// public key

	if(publicKey !is null) {
		pk = publicKey;
	} else {
		// shortcut for: pk = secret_to_public(sk);
		pk = ge_scalarmult_base(expandedSecret[0..32]).toBytes;
	}


	// sha512_modq
	SHA512 sha;
	sha.put(expandedSecret[32..64]);
	sha.put(m);
	r = sc_reduce(sha.finish());

	R = ge_scalarmult_base(r);
	sig[0..32] = R.toBytes;

	// sha512modq
	sha.put(sig[0..32]);
	sha.put(pk[0..32]);
	sha.put(m);
	h = sc_reduce(sha.finish());

	sig[32..64] = sc_muladd(h, expandedSecret[0..32], r);

	return sig;
}


/// Verify a signature `sig` of message `m` with public key `pk`.
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

	rCopy[] = signature[0..32];
	sCopy[] = signature[32..64];

	SHA512 sha;
	sha.put(rCopy);
	sha.put(pk[0..32]);
	sha.put(m);
	//crypto_hash_sha512_3(h, rcopy, 32, pkcopy, 32, m, mlen);
	immutable ubyte[32] h = sc_reduce(sha.finish());
	
	R = ge_double_scalarmult_vartime(h, A, sCopy);
		
	return crypto_equals(R.toBytes, rCopy);
}

/// Generate public key from secret key.
ubyte[32] secret_to_public(in ubyte[] sk)
in {
	assert(sk.length == 32, "Invalid secret key length. Must be 32.");
	//assert((sk[0] & ~248) == 0 || (sk[31] & ~63) == 0 || (sk[31] & 64) == 64, "Invalid secret key!");
} body {

	ubyte[32] secret = secret_expand(sk)[0..32];

	assert((secret[0] & ~248) == 0 || (secret[31] & ~63) == 0 || (secret[31] & 64) == 64, "Invalid secret key!");

	return ge_scalarmult_base(secret).toBytes;
}

private ubyte[64] secret_expand(in ubyte[] sk) 
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

// TODO:
//ubyte[32] ed25519_ref10_pubkey_from_curve25519_pubkey(in ubyte[] pk,
//	in int signbit)
//in {
//	assert(outp.length == 32, "Output buffer size must be 32.");
//	assert(inp.length == 32, "Input size must be 32.");
//	assert(signbit == 0 || signbit == 1, "signbit must be either 0 or 1.");
//} body {
//	fe u;
//	fe one;
//	fe y;
//	fe uplus1;
//	fe uminus1;
//	fe inv_uplus1;
//	
//	/* From prop228:
//
//	 Given a curve25519 x-coordinate (u), we can get the y coordinate
//	 of the ed25519 key using
//
//	 y = (u-1)/(u+1)
//	 */
//	u = fe.fromBytes(pk);
//	uminus1 = u - fe.one;
//	uplus1 = u + fe.one;
//	y = uminus1 * uplus1.inverse;
//
//	ubyte[32] outp = y.toBytes;
//	/* propagate sign. */
//	outp[31] |= (!!signbit) << 7; // convert non zero values to 128
//
//	return outp;
//}

private:

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

private:

version(unittest) {
	/// Extended tests for ed25519 from http://ed25519.cr.yp.to/python/sign.input.
	
	import dcrypt.crypto.ecc.ed25519;
	import std.algorithm;
	
	unittest {
		foreach(v; testVectors) {
			immutable ubyte[32] sk = cast(const ubyte[]) v[0][0..32];
			immutable ubyte[32] pk = cast(const ubyte[]) v[1];
			immutable ubyte[] msg = cast(immutable ubyte[]) v[2];
			immutable ubyte[64] signature = cast(const ubyte[]) v[3][0..64];
			
			assert(secret_to_public(sk) == pk, "Public key generation failed.");
			assert(sign(msg, sk) == signature, "Ed25519 signature failed.");
			assert(verify(signature, msg, pk), "Ed25519 signature verification failed.");
		}
	}
	
	// test vectors from http://ed25519.cr.yp.to/python/sign.input
	// Converted with this python script:
	//
	//#!/bin/python
	//# use with http://ed25519.cr.yp.to/python/sign.input as input
	//import fileinput
	//	
	//	print("immutable string[][] testVectors = [");
	//for line in fileinput.input():
	//fields = line.split(":")
	//	print("\t[x\""+fields[0]+"\", x\"" + fields[1] + "\", x\"" + fields[2] + "\", x\"" + fields[3] + "\"],")
	//		
	//		print("];");
	
	private immutable string[4][64] testVectors = [
		[x"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", x"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", x"", x"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
		[x"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", x"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", x"72", x"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072"],
		[x"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", x"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", x"af82", x"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40aaf82"],
		[x"0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057", x"e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057", x"cbc77b", x"d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00ccbc77b"],
		[x"6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebbc0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7", x"c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7", x"5f4c8989", x"124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c075f4c8989"],
		[x"b780381a65edf8b78f6945e8dbec7941ac049fd4c61040cf0c324357975a293ce253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01", x"e253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01", x"18b6bec097", x"b2fc46ad47af464478c199e1f8be169f1be6327c7f9a0a6689371ca94caf04064a01b22aff1520abd58951341603faed768cf78ce97ae7b038abfe456aa17c0918b6bec097"],
		[x"78ae9effe6f245e924a7be63041146ebc670dbd3060cba67fbc6216febc44546fbcfbfa40505d7f2be444a33d185cc54e16d615260e1640b2b5087b83ee3643d", x"fbcfbfa40505d7f2be444a33d185cc54e16d615260e1640b2b5087b83ee3643d", x"89010d855972", x"6ed629fc1d9ce9e1468755ff636d5a3f40a5d9c91afd93b79d241830f7e5fa29854b8f20cc6eecbb248dbd8d16d14e99752194e4904d09c74d639518839d230089010d855972"],
		[x"691865bfc82a1e4b574eecde4c7519093faf0cf867380234e3664645c61c5f7998a5e3a36e67aaba89888bf093de1ad963e774013b3902bfab356d8b90178a63", x"98a5e3a36e67aaba89888bf093de1ad963e774013b3902bfab356d8b90178a63", x"b4a8f381e70e7a", x"6e0af2fe55ae377a6b7a7278edfb419bd321e06d0df5e27037db8812e7e3529810fa5552f6c0020985ca17a0e02e036d7b222a24f99b77b75fdd16cb05568107b4a8f381e70e7a"],
		[x"3b26516fb3dc88eb181b9ed73f0bcd52bcd6b4c788e4bcaf46057fd078bee073f81fb54a825fced95eb033afcd64314075abfb0abd20a970892503436f34b863", x"f81fb54a825fced95eb033afcd64314075abfb0abd20a970892503436f34b863", x"4284abc51bb67235", x"d6addec5afb0528ac17bb178d3e7f2887f9adbb1ad16e110545ef3bc57f9de2314a5c8388f723b8907be0f3ac90c6259bbe885ecc17645df3db7d488f805fa084284abc51bb67235"],
		[x"edc6f5fbdd1cee4d101c063530a30490b221be68c036f5b07d0f953b745df192c1a49c66e617f9ef5ec66bc4c6564ca33de2a5fb5e1464062e6d6c6219155efd", x"c1a49c66e617f9ef5ec66bc4c6564ca33de2a5fb5e1464062e6d6c6219155efd", x"672bf8965d04bc5146", x"2c76a04af2391c147082e33faacdbe56642a1e134bd388620b852b901a6bc16ff6c9cc9404c41dea12ed281da067a1513866f9d964f8bdd24953856c50042901672bf8965d04bc5146"],
		[x"4e7d21fb3b1897571a445833be0f9fd41cd62be3aa04040f8934e1fcbdcacd4531b2524b8348f7ab1dfafa675cc538e9a84e3fe5819e27c12ad8bbc1a36e4dff", x"31b2524b8348f7ab1dfafa675cc538e9a84e3fe5819e27c12ad8bbc1a36e4dff", x"33d7a786aded8c1bf691", x"28e4598c415ae9de01f03f9f3fab4e919e8bf537dd2b0cdf6e79b9e6559c9409d9151a4c40f083193937627c369488259e99da5a9f0a87497fa6696a5dd6ce0833d7a786aded8c1bf691"],
		[x"a980f892db13c99a3e8971e965b2ff3d41eafd54093bc9f34d1fd22d84115bb644b57ee30cdb55829d0a5d4f046baef078f1e97a7f21b62d75f8e96ea139c35f", x"44b57ee30cdb55829d0a5d4f046baef078f1e97a7f21b62d75f8e96ea139c35f", x"3486f68848a65a0eb5507d", x"77d389e599630d934076329583cd4105a649a9292abc44cd28c40000c8e2f5ac7660a81c85b72af8452d7d25c070861dae91601c7803d656531650dd4e5c41003486f68848a65a0eb5507d"],
		[x"5b5a619f8ce1c66d7ce26e5a2ae7b0c04febcd346d286c929e19d0d5973bfef96fe83693d011d111131c4f3fbaaa40a9d3d76b30012ff73bb0e39ec27ab18257", x"6fe83693d011d111131c4f3fbaaa40a9d3d76b30012ff73bb0e39ec27ab18257", x"5a8d9d0a22357e6655f9c785", x"0f9ad9793033a2fa06614b277d37381e6d94f65ac2a5a94558d09ed6ce922258c1a567952e863ac94297aec3c0d0c8ddf71084e504860bb6ba27449b55adc40e5a8d9d0a22357e6655f9c785"],
		[x"940c89fe40a81dafbdb2416d14ae469119869744410c3303bfaa0241dac57800a2eb8c0501e30bae0cf842d2bde8dec7386f6b7fc3981b8c57c9792bb94cf2dd", x"a2eb8c0501e30bae0cf842d2bde8dec7386f6b7fc3981b8c57c9792bb94cf2dd", x"b87d3813e03f58cf19fd0b6395", x"d8bb64aad8c9955a115a793addd24f7f2b077648714f49c4694ec995b330d09d640df310f447fd7b6cb5c14f9fe9f490bcf8cfadbfd2169c8ac20d3b8af49a0cb87d3813e03f58cf19fd0b6395"],
		[x"9acad959d216212d789a119252ebfe0c96512a23c73bd9f3b202292d6916a738cf3af898467a5b7a52d33d53bc037e2642a8da996903fc252217e9c033e2f291", x"cf3af898467a5b7a52d33d53bc037e2642a8da996903fc252217e9c033e2f291", x"55c7fa434f5ed8cdec2b7aeac173", x"6ee3fe81e23c60eb2312b2006b3b25e6838e02106623f844c44edb8dafd66ab0671087fd195df5b8f58a1d6e52af42908053d55c7321010092748795ef94cf0655c7fa434f5ed8cdec2b7aeac173"],
		[x"d5aeee41eeb0e9d1bf8337f939587ebe296161e6bf5209f591ec939e1440c300fd2a565723163e29f53c9de3d5e8fbe36a7ab66e1439ec4eae9c0a604af291a5", x"fd2a565723163e29f53c9de3d5e8fbe36a7ab66e1439ec4eae9c0a604af291a5", x"0a688e79be24f866286d4646b5d81c", x"f68d04847e5b249737899c014d31c805c5007a62c0a10d50bb1538c5f35503951fbc1e08682f2cc0c92efe8f4985dec61dcbd54d4b94a22547d24451271c8b000a688e79be24f866286d4646b5d81c"],
		[x"0a47d10452ae2febec518a1c7c362890c3fc1a49d34b03b6467d35c904a8362d34e5a8508c4743746962c066e4badea2201b8ab484de5c4f94476ccd2143955b", x"34e5a8508c4743746962c066e4badea2201b8ab484de5c4f94476ccd2143955b", x"c942fa7ac6b23ab7ff612fdc8e68ef39", x"2a3d27dc40d0a8127949a3b7f908b3688f63b7f14f651aacd715940bdbe27a0809aac142f47ab0e1e44fa490ba87ce5392f33a891539caf1ef4c367cae54500cc942fa7ac6b23ab7ff612fdc8e68ef39"],
		[x"f8148f7506b775ef46fdc8e8c756516812d47d6cfbfa318c27c9a22641e56f170445e456dacc7d5b0bbed23c8200cdb74bdcb03e4c7b73f0a2b9b46eac5d4372", x"0445e456dacc7d5b0bbed23c8200cdb74bdcb03e4c7b73f0a2b9b46eac5d4372", x"7368724a5b0efb57d28d97622dbde725af", x"3653ccb21219202b8436fb41a32ba2618c4a133431e6e63463ceb3b6106c4d56e1d2ba165ba76eaad3dc39bffb130f1de3d8e6427db5b71938db4e272bc3e20b7368724a5b0efb57d28d97622dbde725af"],
		[x"77f88691c4eff23ebb7364947092951a5ff3f10785b417e918823a552dab7c7574d29127f199d86a8676aec33b4ce3f225ccb191f52c191ccd1e8cca65213a6b", x"74d29127f199d86a8676aec33b4ce3f225ccb191f52c191ccd1e8cca65213a6b", x"bd8e05033f3a8bcdcbf4beceb70901c82e31", x"fbe929d743a03c17910575492f3092ee2a2bf14a60a3fcacec74a58c7334510fc262db582791322d6c8c41f1700adb80027ecabc14270b703444ae3ee7623e0abd8e05033f3a8bcdcbf4beceb70901c82e31"],
		[x"ab6f7aee6a0837b334ba5eb1b2ad7fcecfab7e323cab187fe2e0a95d80eff1325b96dca497875bf9664c5e75facf3f9bc54bae913d66ca15ee85f1491ca24d2c", x"5b96dca497875bf9664c5e75facf3f9bc54bae913d66ca15ee85f1491ca24d2c", x"8171456f8b907189b1d779e26bc5afbb08c67a", x"73bca64e9dd0db88138eedfafcea8f5436cfb74bfb0e7733cf349baa0c49775c56d5934e1d38e36f39b7c5beb0a836510c45126f8ec4b6810519905b0ca07c098171456f8b907189b1d779e26bc5afbb08c67a"],
		[x"8d135de7c8411bbdbd1b31e5dc678f2ac7109e792b60f38cd24936e8a898c32d1ca281938529896535a7714e3584085b86ef9fec723f42819fc8dd5d8c00817f", x"1ca281938529896535a7714e3584085b86ef9fec723f42819fc8dd5d8c00817f", x"8ba6a4c9a15a244a9c26bb2a59b1026f21348b49", x"a1adc2bc6a2d980662677e7fdff6424de7dba50f5795ca90fdf3e96e256f3285cac71d3360482e993d0294ba4ec7440c61affdf35fe83e6e04263937db93f1058ba6a4c9a15a244a9c26bb2a59b1026f21348b49"],
		[x"0e765d720e705f9366c1ab8c3fa84c9a44370c06969f803296884b2846a652a47fae45dd0a05971026d410bc497af5be7d0827a82a145c203f625dfcb8b03ba8", x"7fae45dd0a05971026d410bc497af5be7d0827a82a145c203f625dfcb8b03ba8", x"1d566a6232bbaab3e6d8804bb518a498ed0f904986", x"bb61cf84de61862207c6a455258bc4db4e15eea0317ff88718b882a06b5cf6ec6fd20c5a269e5d5c805bafbcc579e2590af414c7c227273c102a10070cdfe80f1d566a6232bbaab3e6d8804bb518a498ed0f904986"],
		[x"db36e326d676c2d19cc8fe0c14b709202ecfc761d27089eb6ea4b1bb021ecfa748359b850d23f0715d94bb8bb75e7e14322eaf14f06f28a805403fbda002fc85", x"48359b850d23f0715d94bb8bb75e7e14322eaf14f06f28a805403fbda002fc85", x"1b0afb0ac4ba9ab7b7172cddc9eb42bba1a64bce47d4", x"b6dcd09989dfbac54322a3ce87876e1d62134da998c79d24b50bd7a6a797d86a0e14dc9d7491d6c14a673c652cfbec9f962a38c945da3b2f0879d0b68a9213001b0afb0ac4ba9ab7b7172cddc9eb42bba1a64bce47d4"],
		[x"c89955e0f7741d905df0730b3dc2b0ce1a13134e44fef3d40d60c020ef19df77fdb30673402faf1c8033714f3517e47cc0f91fe70cf3836d6c23636e3fd2287c", x"fdb30673402faf1c8033714f3517e47cc0f91fe70cf3836d6c23636e3fd2287c", x"507c94c8820d2a5793cbf3442b3d71936f35fe3afef316", x"7ef66e5e86f2360848e0014e94880ae2920ad8a3185a46b35d1e07dea8fa8ae4f6b843ba174d99fa7986654a0891c12a794455669375bf92af4cc2770b579e0c507c94c8820d2a5793cbf3442b3d71936f35fe3afef316"],
		[x"4e62627fc221142478aee7f00781f817f662e3b75db29bb14ab47cf8e84104d6b1d39801892027d58a8c64335163195893bfc1b61dbeca3260497e1f30371107", x"b1d39801892027d58a8c64335163195893bfc1b61dbeca3260497e1f30371107", x"d3d615a8472d9962bb70c5b5466a3d983a4811046e2a0ef5", x"836afa764d9c48aa4770a4388b654e97b3c16f082967febca27f2fc47ddfd9244b03cfc729698acf5109704346b60b230f255430089ddc56912399d1122de70ad3d615a8472d9962bb70c5b5466a3d983a4811046e2a0ef5"],
		[x"6b83d7da8908c3e7205b39864b56e5f3e17196a3fc9c2f5805aad0f5554c142dd0c846f97fe28585c0ee159015d64c56311c886eddcc185d296dbb165d2625d6", x"d0c846f97fe28585c0ee159015d64c56311c886eddcc185d296dbb165d2625d6", x"6ada80b6fa84f7034920789e8536b82d5e4678059aed27f71c", x"16e462a29a6dd498685a3718b3eed00cc1598601ee47820486032d6b9acc9bf89f57684e08d8c0f05589cda2882a05dc4c63f9d0431d6552710812433003bc086ada80b6fa84f7034920789e8536b82d5e4678059aed27f71c"],
		[x"19a91fe23a4e9e33ecc474878f57c64cf154b394203487a7035e1ad9cd697b0d2bf32ba142ba4622d8f3e29ecd85eea07b9c47be9d64412c9b510b27dd218b23", x"2bf32ba142ba4622d8f3e29ecd85eea07b9c47be9d64412c9b510b27dd218b23", x"82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c", x"881f5b8c5a030df0f75b6634b070dd27bd1ee3c08738ae349338b3ee6469bbf9760b13578a237d5182535ede121283027a90b5f865d63a6537dca07b44049a0f82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c"],
		[x"1d5b8cb6215c18141666baeefcf5d69dad5bea9a3493dddaa357a4397a13d4de94d23d977c33e49e5e4992c68f25ec99a27c41ce6b91f2bfa0cd8292fe962835", x"94d23d977c33e49e5e4992c68f25ec99a27c41ce6b91f2bfa0cd8292fe962835", x"a9a8cbb0ad585124e522abbfb40533bdd6f49347b55b18e8558cb0", x"3acd39bec8c3cd2b44299722b5850a0400c1443590fd4861d59aae7496acb3df73fc3fdf7969ae5f50ba47dddc435246e5fd376f6b891cd4c2caf5d614b6170ca9a8cbb0ad585124e522abbfb40533bdd6f49347b55b18e8558cb0"],
		[x"6a91b3227c472299089bdce9356e726a40efd840f11002708b7ee55b64105ac29d084aa8b97a6b9bafa496dbc6f76f3306a116c9d917e681520a0f914369427e", x"9d084aa8b97a6b9bafa496dbc6f76f3306a116c9d917e681520a0f914369427e", x"5cb6f9aa59b80eca14f6a68fb40cf07b794e75171fba96262c1c6adc", x"f5875423781b66216cb5e8998de5d9ffc29d1d67107054ace3374503a9c3ef811577f269de81296744bd706f1ac478caf09b54cdf871b3f802bd57f9a6cb91015cb6f9aa59b80eca14f6a68fb40cf07b794e75171fba96262c1c6adc"],
		[x"93eaa854d791f05372ce72b94fc6503b2ff8ae6819e6a21afe825e27ada9e4fb16cee8a3f2631834c88b670897ff0b08ce90cc147b4593b3f1f403727f7e7ad5", x"16cee8a3f2631834c88b670897ff0b08ce90cc147b4593b3f1f403727f7e7ad5", x"32fe27994124202153b5c70d3813fdee9c2aa6e7dc743d4d535f1840a5", x"d834197c1a3080614e0a5fa0aaaa808824f21c38d692e6ffbd200f7dfb3c8f44402a7382180b98ad0afc8eec1a02acecf3cb7fde627b9f18111f260ab1db9a0732fe27994124202153b5c70d3813fdee9c2aa6e7dc743d4d535f1840a5"],
		[x"941cac69fb7b1815c57bb987c4d6c2ad2c35d5f9a3182a79d4ba13eab253a8ad23be323c562dfd71ce65f5bba56a74a3a6dfc36b573d2f94f635c7f9b4fd5a5b", x"23be323c562dfd71ce65f5bba56a74a3a6dfc36b573d2f94f635c7f9b4fd5a5b", x"bb3172795710fe00054d3b5dfef8a11623582da68bf8e46d72d27cece2aa", x"0f8fad1e6bde771b4f5420eac75c378bae6db5ac6650cd2bc210c1823b432b48e016b10595458ffab92f7a8989b293ceb8dfed6c243a2038fc06652aaaf16f02bb3172795710fe00054d3b5dfef8a11623582da68bf8e46d72d27cece2aa"],
		[x"1acdbb793b0384934627470d795c3d1dd4d79cea59ef983f295b9b59179cbb283f60c7541afa76c019cf5aa82dcdb088ed9e4ed9780514aefb379dabc844f31a", x"3f60c7541afa76c019cf5aa82dcdb088ed9e4ed9780514aefb379dabc844f31a", x"7cf34f75c3dac9a804d0fcd09eba9b29c9484e8a018fa9e073042df88e3c56", x"be71ef4806cb041d885effd9e6b0fbb73d65d7cdec47a89c8a994892f4e55a568c4cc78d61f901e80dbb628b86a23ccd594e712b57fa94c2d67ec266348785077cf34f75c3dac9a804d0fcd09eba9b29c9484e8a018fa9e073042df88e3c56"],
		[x"8ed7a797b9cea8a8370d419136bcdf683b759d2e3c6947f17e13e2485aa9d420b49f3a78b1c6a7fca8f3466f33bc0e929f01fba04306c2a7465f46c3759316d9", x"b49f3a78b1c6a7fca8f3466f33bc0e929f01fba04306c2a7465f46c3759316d9", x"a750c232933dc14b1184d86d8b4ce72e16d69744ba69818b6ac33b1d823bb2c3", x"04266c033b91c1322ceb3446c901ffcf3cc40c4034e887c9597ca1893ba7330becbbd8b48142ef35c012c6ba51a66df9308cb6268ad6b1e4b03e70102495790ba750c232933dc14b1184d86d8b4ce72e16d69744ba69818b6ac33b1d823bb2c3"],
		[x"f2ab396fe8906e3e5633e99cabcd5b09df0859b516230b1e0450b580b65f616c8ea074245159a116aa7122a25ec16b891d625a68f33660423908f6bdc44f8c1b", x"8ea074245159a116aa7122a25ec16b891d625a68f33660423908f6bdc44f8c1b", x"5a44e34b746c5fd1898d552ab354d28fb4713856d7697dd63eb9bd6b99c280e187", x"a06a23d982d81ab883aae230adbc368a6a9977f003cebb00d4c2e4018490191a84d3a282fdbfb2fc88046e62de43e15fb575336b3c8b77d19ce6a009ce51f50c5a44e34b746c5fd1898d552ab354d28fb4713856d7697dd63eb9bd6b99c280e187"],
		[x"550a41c013f79bab8f06e43ad1836d51312736a9713806fafe6645219eaa1f9daf6b7145474dc9954b9af93a9cdb34449d5b7c651c824d24e230b90033ce59c0", x"af6b7145474dc9954b9af93a9cdb34449d5b7c651c824d24e230b90033ce59c0", x"8bc4185e50e57d5f87f47515fe2b1837d585f0aae9e1ca383b3ec908884bb900ff27", x"16dc1e2b9fa909eefdc277ba16ebe207b8da5e91143cde78c5047a89f681c33c4e4e3428d5c928095903a811ec002d52a39ed7f8b3fe1927200c6dd0b9ab3e048bc4185e50e57d5f87f47515fe2b1837d585f0aae9e1ca383b3ec908884bb900ff27"],
		[x"19ac3e272438c72ddf7b881964867cb3b31ff4c793bb7ea154613c1db068cb7ef85b80e050a1b9620db138bfc9e100327e25c257c59217b601f1f6ac9a413d3f", x"f85b80e050a1b9620db138bfc9e100327e25c257c59217b601f1f6ac9a413d3f", x"95872d5f789f95484e30cbb0e114028953b16f5c6a8d9f65c003a83543beaa46b38645", x"ea855d781cbea4682e350173cb89e8619ccfddb97cdce16f9a2f6f6892f46dbe68e04b12b8d88689a7a31670cdff409af98a93b49a34537b6aa009d2eb8b470195872d5f789f95484e30cbb0e114028953b16f5c6a8d9f65c003a83543beaa46b38645"],
		[x"ca267de96c93c238fafb1279812059ab93ac03059657fd994f8fa5a09239c821017370c879090a81c7f272c2fc80e3aac2bc603fcb379afc98691160ab745b26", x"017370c879090a81c7f272c2fc80e3aac2bc603fcb379afc98691160ab745b26", x"e05f71e4e49a72ec550c44a3b85aca8f20ff26c3ee94a80f1b431c7d154ec9603ee02531", x"ac957f82335aa7141e96b59d63e3ccee95c3a2c47d026540c2af42dc9533d5fd81827d1679ad187aeaf37834915e75b147a9286806c8017516ba43dd051a5e0ce05f71e4e49a72ec550c44a3b85aca8f20ff26c3ee94a80f1b431c7d154ec9603ee02531"],
		[x"3dff5e899475e7e91dd261322fab09980c52970de1da6e2e201660cc4fce7032f30162bac98447c4042fac05da448034629be2c6a58d30dfd578ba9fb5e3930b", x"f30162bac98447c4042fac05da448034629be2c6a58d30dfd578ba9fb5e3930b", x"938f0e77621bf3ea52c7c4911c5157c2d8a2a858093ef16aa9b107e69d98037ba139a3c382", x"5efe7a92ff9623089b3e3b78f352115366e26ba3fb1a416209bc029e9cadccd9f4affa333555a8f3a35a9d0f7c34b292cae77ec96fa3adfcaadee2d9ced8f805938f0e77621bf3ea52c7c4911c5157c2d8a2a858093ef16aa9b107e69d98037ba139a3c382"],
		[x"9a6b847864e70cfe8ba6ab22fa0ca308c0cc8bec7141fbcaa3b81f5d1e1cfcfc34ad0fbdb2566507a81c2b1f8aa8f53dccaa64cc87ada91b903e900d07eee930", x"34ad0fbdb2566507a81c2b1f8aa8f53dccaa64cc87ada91b903e900d07eee930", x"838367471183c71f7e717724f89d401c3ad9863fd9cc7aa3cf33d3c529860cb581f3093d87da", x"2ab255169c489c54c732232e37c87349d486b1eba20509dbabe7fed329ef08fd75ba1cd145e67b2ea26cb5cc51cab343eeb085fe1fd7b0ec4c6afcd9b979f905838367471183c71f7e717724f89d401c3ad9863fd9cc7aa3cf33d3c529860cb581f3093d87da"],
		[x"575be07afca5d063c238cd9b8028772cc49cda34471432a2e166e096e2219efc94e5eb4d5024f49d7ebf79817c8de11497dc2b55622a51ae123ffc749dbb16e0", x"94e5eb4d5024f49d7ebf79817c8de11497dc2b55622a51ae123ffc749dbb16e0", x"33e5918b66d33d55fe717ca34383eae78f0af82889caf6696e1ac9d95d1ffb32cba755f9e3503e", x"58271d44236f3b98c58fd7ae0d2f49ef2b6e3affdb225aa3ba555f0e11cc53c23ad19baf24346590d05d7d5390582082cf94d39cad6530ab93d13efb3927950633e5918b66d33d55fe717ca34383eae78f0af82889caf6696e1ac9d95d1ffb32cba755f9e3503e"],
		[x"15ffb45514d43444d61fcb105e30e135fd268523dda20b82758b1794231104411772c5abc2d23fd2f9d1c3257be7bc3c1cd79cee40844b749b3a7743d2f964b8", x"1772c5abc2d23fd2f9d1c3257be7bc3c1cd79cee40844b749b3a7743d2f964b8", x"da9c5559d0ea51d255b6bd9d7638b876472f942b330fc0e2b30aea68d77368fce4948272991d257e", x"6828cd7624e793b8a4ceb96d3c2a975bf773e5ff6645f353614058621e58835289e7f31f42dfe6af6d736f2644511e320c0fa698582a79778d18730ed3e8cb08da9c5559d0ea51d255b6bd9d7638b876472f942b330fc0e2b30aea68d77368fce4948272991d257e"],
		[x"fe0568642943b2e1afbfd1f10fe8df87a4236bea40dce742072cb21886eec1fa299ebd1f13177dbdb66a912bbf712038fdf73b06c3ac020c7b19126755d47f61", x"299ebd1f13177dbdb66a912bbf712038fdf73b06c3ac020c7b19126755d47f61", x"c59d0862ec1c9746abcc3cf83c9eeba2c7082a036a8cb57ce487e763492796d47e6e063a0c1feccc2d", x"d59e6dfcc6d7e3e2c58dec81e985d245e681acf6594a23c59214f7bed8015d813c7682b60b3583440311e72a8665ba2c96dec23ce826e160127e18132b030404c59d0862ec1c9746abcc3cf83c9eeba2c7082a036a8cb57ce487e763492796d47e6e063a0c1feccc2d"],
		[x"5ecb16c2df27c8cf58e436a9d3affbd58e9538a92659a0f97c4c4f994635a8cada768b20c437dd3aa5f84bb6a077ffa34ab68501c5352b5cc3fdce7fe6c2398d", x"da768b20c437dd3aa5f84bb6a077ffa34ab68501c5352b5cc3fdce7fe6c2398d", x"56f1329d9a6be25a6159c72f12688dc8314e85dd9e7e4dc05bbecb7729e023c86f8e0937353f27c7ede9", x"1c723a20c6772426a670e4d5c4a97c6ebe9147f71bb0a415631e44406e290322e4ca977d348fe7856a8edc235d0fe95f7ed91aefddf28a77e2c7dbfd8f552f0a56f1329d9a6be25a6159c72f12688dc8314e85dd9e7e4dc05bbecb7729e023c86f8e0937353f27c7ede9"],
		[x"d599d637b3c30a82a9984e2f758497d144de6f06b9fba04dd40fd949039d7c846791d8ce50a44689fc178727c5c3a1c959fbeed74ef7d8e7bd3c1ab4da31c51f", x"6791d8ce50a44689fc178727c5c3a1c959fbeed74ef7d8e7bd3c1ab4da31c51f", x"a7c04e8ba75d0a03d8b166ad7a1d77e1b91c7aaf7befdd99311fc3c54a684ddd971d5b3211c3eeaff1e54e", x"ebf10d9ac7c96108140e7def6fe9533d727646ff5b3af273c1df95762a66f32b65a09634d013f54b5dd6011f91bc336ca8b355ce33f8cfbec2535a4c427f8205a7c04e8ba75d0a03d8b166ad7a1d77e1b91c7aaf7befdd99311fc3c54a684ddd971d5b3211c3eeaff1e54e"],
		[x"30ab8232fa7018f0ce6c39bd8f782fe2e159758bb0f2f4386c7f28cfd2c85898ecfb6a2bd42f31b61250ba5de7e46b4719afdfbc660db71a7bd1df7b0a3abe37", x"ecfb6a2bd42f31b61250ba5de7e46b4719afdfbc660db71a7bd1df7b0a3abe37", x"63b80b7956acbecf0c35e9ab06b914b0c7014fe1a4bbc0217240c1a33095d707953ed77b15d211adaf9b97dc", x"9af885344cc7239498f712df80bc01b80638291ed4a1d28baa5545017a72e2f65649ccf9603da6eb5bfab9f5543a6ca4a7af3866153c76bf66bf95def615b00c63b80b7956acbecf0c35e9ab06b914b0c7014fe1a4bbc0217240c1a33095d707953ed77b15d211adaf9b97dc"],
		[x"0ddcdc872c7b748d40efe96c2881ae189d87f56148ed8af3ebbbc80324e38bdd588ddadcbcedf40df0e9697d8bb277c7bb1498fa1d26ce0a835a760b92ca7c85", x"588ddadcbcedf40df0e9697d8bb277c7bb1498fa1d26ce0a835a760b92ca7c85", x"65641cd402add8bf3d1d67dbeb6d41debfbef67e4317c35b0a6d5bbbae0e034de7d670ba1413d056f2d6f1de12", x"c179c09456e235fe24105afa6e8ec04637f8f943817cd098ba95387f9653b2add181a31447d92d1a1ddf1ceb0db62118de9dffb7dcd2424057cbdff5d41d040365641cd402add8bf3d1d67dbeb6d41debfbef67e4317c35b0a6d5bbbae0e034de7d670ba1413d056f2d6f1de12"],
		[x"89f0d68299ba0a5a83f248ae0c169f8e3849a9b47bd4549884305c9912b46603aba3e795aab2012acceadd7b3bd9daeeed6ff5258bdcd7c93699c2a3836e3832", x"aba3e795aab2012acceadd7b3bd9daeeed6ff5258bdcd7c93699c2a3836e3832", x"4f1846dd7ad50e545d4cfbffbb1dc2ff145dc123754d08af4e44ecc0bc8c91411388bc7653e2d893d1eac2107d05", x"2c691fa8d487ce20d5d2fa41559116e0bbf4397cf5240e152556183541d66cf753582401a4388d390339dbef4d384743caa346f55f8daba68ba7b9131a8a6e0b4f1846dd7ad50e545d4cfbffbb1dc2ff145dc123754d08af4e44ecc0bc8c91411388bc7653e2d893d1eac2107d05"],
		[x"0a3c1844e2db070fb24e3c95cb1cc6714ef84e2ccd2b9dd2f1460ebf7ecf13b172e409937e0610eb5c20b326dc6ea1bbbc0406701c5cd67d1fbde09192b07c01", x"72e409937e0610eb5c20b326dc6ea1bbbc0406701c5cd67d1fbde09192b07c01", x"4c8274d0ed1f74e2c86c08d955bde55b2d54327e82062a1f71f70d536fdc8722cdead7d22aaead2bfaa1ad00b82957", x"87f7fdf46095201e877a588fe3e5aaf476bd63138d8a878b89d6ac60631b3458b9d41a3c61a588e1db8d29a5968981b018776c588780922f5aa732ba6379dd054c8274d0ed1f74e2c86c08d955bde55b2d54327e82062a1f71f70d536fdc8722cdead7d22aaead2bfaa1ad00b82957"],
		[x"c8d7a8818b98dfdb20839c871cb5c48e9e9470ca3ad35ba2613a5d3199c8ab2390d2efbba4d43e6b2b992ca16083dbcfa2b322383907b0ee75f3e95845d3c47f", x"90d2efbba4d43e6b2b992ca16083dbcfa2b322383907b0ee75f3e95845d3c47f", x"783e33c3acbdbb36e819f544a7781d83fc283d3309f5d3d12c8dcd6b0b3d0e89e38cfd3b4d0885661ca547fb9764abff", x"fa2e994421aef1d5856674813d05cbd2cf84ef5eb424af6ecd0dc6fdbdc2fe605fe985883312ecf34f59bfb2f1c9149e5b9cc9ecda05b2731130f3ed28ddae0b783e33c3acbdbb36e819f544a7781d83fc283d3309f5d3d12c8dcd6b0b3d0e89e38cfd3b4d0885661ca547fb9764abff"],
		[x"b482703612d0c586f76cfcb21cfd2103c957251504a8c0ac4c86c9c6f3e429fffd711dc7dd3b1dfb9df9704be3e6b26f587fe7dd7ba456a91ba43fe51aec09ad", x"fd711dc7dd3b1dfb9df9704be3e6b26f587fe7dd7ba456a91ba43fe51aec09ad", x"29d77acfd99c7a0070a88feb6247a2bce9984fe3e6fbf19d4045042a21ab26cbd771e184a9a75f316b648c6920db92b87b", x"58832bdeb26feafc31b46277cf3fb5d7a17dfb7ccd9b1f58ecbe6feb979666828f239ba4d75219260ecac0acf40f0e5e2590f4caa16bbbcd8a155d347967a60729d77acfd99c7a0070a88feb6247a2bce9984fe3e6fbf19d4045042a21ab26cbd771e184a9a75f316b648c6920db92b87b"],
		[x"84e50dd9a0f197e3893c38dbd91fafc344c1776d3a400e2f0f0ee7aa829eb8a22c50f870ee48b36b0ac2f8a5f336fb090b113050dbcc25e078200a6e16153eea", x"2c50f870ee48b36b0ac2f8a5f336fb090b113050dbcc25e078200a6e16153eea", x"f3992cde6493e671f1e129ddca8038b0abdb77bb9035f9f8be54bd5d68c1aeff724ff47d29344391dc536166b8671cbbf123", x"69e6a4491a63837316e86a5f4ba7cd0d731ecc58f1d0a264c67c89befdd8d3829d8de13b33cc0bf513931715c7809657e2bfb960e5c764c971d733746093e500f3992cde6493e671f1e129ddca8038b0abdb77bb9035f9f8be54bd5d68c1aeff724ff47d29344391dc536166b8671cbbf123"],
		[x"b322d46577a2a991a4d1698287832a39c487ef776b4bff037a05c7f1812bdeeceb2bcadfd3eec2986baff32b98e7c4dbf03ff95d8ad5ff9aa9506e5472ff845f", x"eb2bcadfd3eec2986baff32b98e7c4dbf03ff95d8ad5ff9aa9506e5472ff845f", x"19f1bf5dcf1750c611f1c4a2865200504d82298edd72671f62a7b1471ac3d4a30f7de9e5da4108c52a4ce70a3e114a52a3b3c5", x"c7b55137317ca21e33489ff6a9bfab97c855dc6f85684a70a9125a261b56d5e6f149c5774d734f2d8debfc77b721896a8267c23768e9badb910eef83ec25880219f1bf5dcf1750c611f1c4a2865200504d82298edd72671f62a7b1471ac3d4a30f7de9e5da4108c52a4ce70a3e114a52a3b3c5"],
		[x"960cab5034b9838d098d2dcbf4364bec16d388f6376d73a6273b70f82bbc98c05e3c19f2415acf729f829a4ebd5c40e1a6bc9fbca95703a9376087ed0937e51a", x"5e3c19f2415acf729f829a4ebd5c40e1a6bc9fbca95703a9376087ed0937e51a", x"f8b21962447b0a8f2e4279de411bea128e0be44b6915e6cda88341a68a0d818357db938eac73e0af6d31206b3948f8c48a447308", x"27d4c3a1811ef9d4360b3bdd133c2ccc30d02c2f248215776cb07ee4177f9b13fc42dd70a6c2fed8f225c7663c7f182e7ee8eccff20dc7b0e1d5834ec5b1ea01f8b21962447b0a8f2e4279de411bea128e0be44b6915e6cda88341a68a0d818357db938eac73e0af6d31206b3948f8c48a447308"],
		[x"eb77b2638f23eebc82efe45ee9e5a0326637401e663ed029699b21e6443fb48e9ef27608961ac711de71a6e2d4d4663ea3ecd42fb7e4e8627c39622df4af0bbc", x"9ef27608961ac711de71a6e2d4d4663ea3ecd42fb7e4e8627c39622df4af0bbc", x"99e3d00934003ebafc3e9fdb687b0f5ff9d5782a4b1f56b9700046c077915602c3134e22fc90ed7e690fddd4433e2034dcb2dc99ab", x"18dc56d7bd9acd4f4daa78540b4ac8ff7aa9815f45a0bba370731a14eaabe96df8b5f37dbf8eae4cb15a64b244651e59d6a3d6761d9e3c50f2d0cbb09c05ec0699e3d00934003ebafc3e9fdb687b0f5ff9d5782a4b1f56b9700046c077915602c3134e22fc90ed7e690fddd4433e2034dcb2dc99ab"],
		[x"b625aa89d3f7308715427b6c39bbac58effd3a0fb7316f7a22b99ee5922f2dc965a99c3e16fea894ec33c6b20d9105e2a04e2764a4769d9bbd4d8bacfeab4a2e", x"65a99c3e16fea894ec33c6b20d9105e2a04e2764a4769d9bbd4d8bacfeab4a2e", x"e07241dbd3adbe610bbe4d005dd46732a4c25086ecb8ec29cd7bca116e1bf9f53bfbf3e11fa49018d39ff1154a06668ef7df5c678e6a", x"01bb901d83b8b682d3614af46a807ba2691358feb775325d3423f549ff0aa5757e4e1a74e9c70f9721d8f354b319d4f4a1d91445c870fd0ffb94fed64664730de07241dbd3adbe610bbe4d005dd46732a4c25086ecb8ec29cd7bca116e1bf9f53bfbf3e11fa49018d39ff1154a06668ef7df5c678e6a"],
		[x"b1c9f8bd03fe82e78f5c0fb06450f27dacdf716434db268275df3e1dc177af427fc88b1f7b3f11c629be671c21621f5c10672fafc8492da885742059ee6774cf", x"7fc88b1f7b3f11c629be671c21621f5c10672fafc8492da885742059ee6774cf", x"331da7a9c1f87b2ac91ee3b86d06c29163c05ed6f8d8a9725b471b7db0d6acec7f0f702487163f5eda020ca5b493f399e1c8d308c3c0c2", x"4b229951ef262f16978f7914bc672e7226c5f8379d2778c5a2dc0a2650869f7acfbd0bcd30fdb0619bb44fc1ae5939b87cc318133009c20395b6c7eb98107701331da7a9c1f87b2ac91ee3b86d06c29163c05ed6f8d8a9725b471b7db0d6acec7f0f702487163f5eda020ca5b493f399e1c8d308c3c0c2"],
		[x"6d8cdb2e075f3a2f86137214cb236ceb89a6728bb4a200806bf3557fb78fac6957a04c7a5113cddfe49a4c124691d46c1f9cdc8f343f9dcb72a1330aeca71fda", x"57a04c7a5113cddfe49a4c124691d46c1f9cdc8f343f9dcb72a1330aeca71fda", x"7f318dbd121c08bfddfeff4f6aff4e45793251f8abf658403358238984360054f2a862c5bb83ed89025d2014a7a0cee50da3cb0e76bbb6bf", x"a6cbc947f9c87d1455cf1a708528c090f11ecee4855d1dbaadf47454a4de55fa4ce84b36d73a5b5f8f59298ccf21992df492ef34163d87753b7e9d32f2c3660b7f318dbd121c08bfddfeff4f6aff4e45793251f8abf658403358238984360054f2a862c5bb83ed89025d2014a7a0cee50da3cb0e76bbb6bf"],
		[x"47adc6d6bf571ee9570ca0f75b604ac43e303e4ab339ca9b53cacc5be45b2ccba3f527a1c1f17dfeed92277347c9f98ab475de1755b0ab546b8a15d01b9bd0be", x"a3f527a1c1f17dfeed92277347c9f98ab475de1755b0ab546b8a15d01b9bd0be", x"ce497c5ff5a77990b7d8f8699eb1f5d8c0582f70cb7ac5c54d9d924913278bc654d37ea227590e15202217fc98dac4c0f3be2183d133315739", x"4e8c318343c306adbba60c92b75cb0569b9219d8a86e5d57752ed235fc109a43c2cf4e942cacf297279fbb28675347e08027722a4eb7395e00a17495d32edf0bce497c5ff5a77990b7d8f8699eb1f5d8c0582f70cb7ac5c54d9d924913278bc654d37ea227590e15202217fc98dac4c0f3be2183d133315739"],
		[x"3c19b50b0fe47961719c381d0d8da9b9869d312f13e3298b97fb22f0af29cbbe0f7eda091499625e2bae8536ea35cda5483bd16a9c7e416b341d6f2c83343612", x"0f7eda091499625e2bae8536ea35cda5483bd16a9c7e416b341d6f2c83343612", x"8ddcd63043f55ec3bfc83dceae69d8f8b32f4cdb6e2aebd94b4314f8fe7287dcb62732c9052e7557fe63534338efb5b6254c5d41d2690cf5144f", x"efbd41f26a5d62685516f882b6ec74e0d5a71830d203c231248f26e99a9c6578ec900d68cdb8fa7216ad0d24f9ecbc9ffa655351666582f626645395a31fa7048ddcd63043f55ec3bfc83dceae69d8f8b32f4cdb6e2aebd94b4314f8fe7287dcb62732c9052e7557fe63534338efb5b6254c5d41d2690cf5144f"],
		[x"34e1e9d539107eb86b393a5ccea1496d35bc7d5e9a8c5159d957e4e5852b3eb00ecb2601d5f7047428e9f909883a12420085f04ee2a88b6d95d3d7f2c932bd76", x"0ecb2601d5f7047428e9f909883a12420085f04ee2a88b6d95d3d7f2c932bd76", x"a6d4d0542cfe0d240a90507debacabce7cbbd48732353f4fad82c7bb7dbd9df8e7d9a16980a45186d8786c5ef65445bcc5b2ad5f660ffc7c8eaac0", x"32d22904d3e7012d6f5a441b0b4228064a5cf95b723a66b048a087ecd55920c31c204c3f2006891a85dd1932e3f1d614cfd633b5e63291c6d8166f3011431e09a6d4d0542cfe0d240a90507debacabce7cbbd48732353f4fad82c7bb7dbd9df8e7d9a16980a45186d8786c5ef65445bcc5b2ad5f660ffc7c8eaac0"],
		[x"49dd473ede6aa3c866824a40ada4996c239a20d84c9365e4f0a4554f8031b9cf788de540544d3feb0c919240b390729be487e94b64ad973eb65b4669ecf23501", x"788de540544d3feb0c919240b390729be487e94b64ad973eb65b4669ecf23501", x"3a53594f3fba03029318f512b084a071ebd60baec7f55b028dc73bfc9c74e0ca496bf819dd92ab61cd8b74be3c0d6dcd128efc5ed3342cba124f726c", x"d2fde02791e720852507faa7c3789040d9ef86646321f313ac557f4002491542dd67d05c6990cdb0d495501fbc5d5188bfbb84dc1bf6098bee0603a47fc2690f3a53594f3fba03029318f512b084a071ebd60baec7f55b028dc73bfc9c74e0ca496bf819dd92ab61cd8b74be3c0d6dcd128efc5ed3342cba124f726c"],
		[x"331c64da482b6b551373c36481a02d8136ecadbb01ab114b4470bf41607ac57152a00d96a3148b4726692d9eff89160ea9f99a5cc4389f361fed0bb16a42d521", x"52a00d96a3148b4726692d9eff89160ea9f99a5cc4389f361fed0bb16a42d521", x"20e1d05a0d5b32cc8150b8116cef39659dd5fb443ab15600f78e5b49c45326d9323f2850a63c3808859495ae273f58a51e9de9a145d774b40ba9d753d3", x"22c99aa946ead39ac7997562810c01c20b46bd610645bd2d56dcdcbaacc5452c74fbf4b8b1813b0e94c30d808ce5498e61d4f7ccbb4cc5f04dfc6140825a960020e1d05a0d5b32cc8150b8116cef39659dd5fb443ab15600f78e5b49c45326d9323f2850a63c3808859495ae273f58a51e9de9a145d774b40ba9d753d3"],
		[x"5c0b96f2af8712122cf743c8f8dc77b6cd5570a7de13297bb3dde1886213cce20510eaf57d7301b0e1d527039bf4c6e292300a3a61b4765434f3203c100351b1", x"0510eaf57d7301b0e1d527039bf4c6e292300a3a61b4765434f3203c100351b1", x"54e0caa8e63919ca614b2bfd308ccfe50c9ea888e1ee4446d682cb5034627f97b05392c04e835556c31c52816a48e4fb196693206b8afb4408662b3cb575", x"06e5d8436ac7705b3a90f1631cdd38ec1a3fa49778a9b9f2fa5ebea4e7d560ada7dd26ff42fafa8ba420323742761aca6904940dc21bbef63ff72daab45d430b54e0caa8e63919ca614b2bfd308ccfe50c9ea888e1ee4446d682cb5034627f97b05392c04e835556c31c52816a48e4fb196693206b8afb4408662b3cb575"],
		[x"de84f2435f78dedb87da18194ff6a336f08111150def901c1ac418146eb7b54ad3a92bbaa4d63af79c2226a7236e6427428df8b362427f873023b22d2f5e03f2", x"d3a92bbaa4d63af79c2226a7236e6427428df8b362427f873023b22d2f5e03f2", x"205135ec7f417c858072d5233fb36482d4906abd60a74a498c347ff248dfa2722ca74e879de33169fadc7cd44d6c94a17d16e1e630824ba3e0df22ed68eaab", x"471ebc973cfdaceec07279307368b73be35bc6f8d8312b70150567369096706dc471126c3576f9f0eb550df5ac6a525181110029dd1fc11174d1aaced48d630f205135ec7f417c858072d5233fb36482d4906abd60a74a498c347ff248dfa2722ca74e879de33169fadc7cd44d6c94a17d16e1e630824ba3e0df22ed68eaab"],
	];
}