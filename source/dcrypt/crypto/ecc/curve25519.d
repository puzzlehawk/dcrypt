module dcrypt.crypto.ecc.curve25519;


/** 
 * This module is a port of Bernstein's curve25519 to D.
 * Original code can be found here: http://code.google.com/p/curve25519-donna/
 * 
 * Copyright:
 *
 * Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */


@safe pure nothrow @nogc:

public enum publicBasePoint = cast(const ubyte[32]) x"0900000000000000000000000000000000000000000000000000000000000000";

/// Generate a public key from a secret. 
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;

	key_t secretKey = cast(key_t) x"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	
	key_t publicKey = curve25519(secretKey);
	
	auto expectedPublic = x"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
	
	assert(publicKey == expectedPublic, "curve25519 public key generation failed!");
}

/// Generate a public key from a secret. 
/// Test vectors from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
unittest {
	alias ubyte[32] key_t;
	
	key_t secretKey = cast(key_t) x"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

	key_t publicKey = curve25519(secretKey);
	
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
	
	pub1 = curve25519(priv1);
	pub2 = curve25519(priv2);
	
	key_t shared1, shared2;
	
	// Generate the shared keys. Both should be equal.
	shared1 = curve25519(priv1, pub2);
	shared2 = curve25519(priv2, pub1);

	auto expectedSharedSecret = x"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

	assert(shared1 == expectedSharedSecret, "curve25519 DH key agreement failed!");
	assert(shared1 == shared2, "curve25519 DH key agreement failed!");
}

/// 
/// 
/// Params:
/// secret = your secret key, the 'exponent'
/// basepoint = public key. Default: base point 9
/// 
/// Returns: basepoint^secret.
/// 
/// Examples:
/// 
/// ubyte[32] publicKey = curve25519(secretKey);
/// 
/// ubyte[32] sharedKey = curve25519(mySecretKey, herPublicKey);
/// 
public ubyte[32] curve25519(in ref ubyte[32] secret, in ref ubyte[32] basepoint = publicBasePoint) 
in {
	assert(secret.length == 32);
	assert(basepoint.length == 32);
} body {
	limb[10] bp, x, zmone;
	limb[10] z; // TODO: was 11 but I think it should be 10
	ubyte[32] e;
	
	e[] = secret[];
	
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	
	fexpand(bp, basepoint);
	cmult(x, z, e, bp);
	crecip(zmone, z);
	fmul(z, x, zmone);
	
	ubyte[32] myPublic;
	
	fcontract(myPublic, z);
	
	return myPublic;
}

private:

alias long limb;

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide. */

/* Sum two numbers: output += in */
void fsum(limb[] output, in limb[] input)
{
	output[0..10] += input[0..10];
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!). */
void fdifference(limb[] output, in limb[] input)
{
	output[0..10] = input[0..10] - output[0..10];
	//	for (uint i = 0; i < 10; ++i) {
	//		output[i] = input[i] - output[i];
	//	}
}

/* Multiply a number by a scalar: output = in * scalar */
void fscalar_product(limb[] output, in limb[] input, in limb scalar)
{
	output[] = input[] * scalar;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
void fproduct(limb[] output, in limb[] in2, in limb[] in1) 
in {
	assert(output.length == 19);
	assert(in1.length >= 10);
	assert(in2.length >= 10);
} body {
	output[0] =       (cast(limb) (cast(int) in2[0])) * (cast(int) in1[0]);
	output[1] =       (cast(limb) (cast(int) in2[0])) * (cast(int) in1[1]) +
		(cast(limb) (cast(int) in2[1])) * (cast(int) in1[0]);
	output[2] =  2 *  (cast(limb) (cast(int) in2[1])) * (cast(int) in1[1]) +
		(cast(limb) (cast(int) in2[0])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[0]);
	output[3] =       (cast(limb) (cast(int) in2[1])) * (cast(int) in1[2]) +
		(cast(limb) (cast(int) in2[2])) * (cast(int) in1[1]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[3])) * (cast(int) in1[0]);
	output[4] =       (cast(limb) (cast(int) in2[2])) * (cast(int) in1[2]) +
		2 * ((cast(limb) (cast(int) in2[1])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[3])) * (cast(int) in1[1])) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[0]);
	output[5] =       (cast(limb) (cast(int) in2[2])) * (cast(int) in1[3]) +
		(cast(limb) (cast(int) in2[3])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[1])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[1]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[5])) * (cast(int) in1[0]);
	output[6] =  2 * ((cast(limb) (cast(int) in2[3])) * (cast(int) in1[3]) +
		(cast(limb) (cast(int) in2[1])) * (cast(int) in1[5]) +
		(cast(limb) (cast(int) in2[5])) * (cast(int) in1[1])) +
		(cast(limb) (cast(int) in2[2])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[0]);
	output[7] =       (cast(limb) (cast(int) in2[3])) * (cast(int) in1[4]) +
		(cast(limb) (cast(int) in2[4])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[5])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[1])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[1]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[7])) * (cast(int) in1[0]);
	output[8] =       (cast(limb) (cast(int) in2[4])) * (cast(int) in1[4]) +
		2 * ((cast(limb) (cast(int) in2[3])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[5])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[1])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[7])) * (cast(int) in1[1])) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[0]);
	output[9] =       (cast(limb) (cast(int) in2[4])) * (cast(int) in1[5]) +
		(cast(limb) (cast(int) in2[5])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[3])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[7])) * (cast(int) in1[2]) +
			(cast(limb) (cast(int) in2[1])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[1]) +
			(cast(limb) (cast(int) in2[0])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[0]);
	output[10] = 2 * ((cast(limb) (cast(int) in2[5])) * (cast(int) in1[5]) +
		(cast(limb) (cast(int) in2[3])) * (cast(int) in1[7]) +
		(cast(limb) (cast(int) in2[7])) * (cast(int) in1[3]) +
		(cast(limb) (cast(int) in2[1])) * (cast(int) in1[9]) +
		(cast(limb) (cast(int) in2[9])) * (cast(int) in1[1])) +
		(cast(limb) (cast(int) in2[4])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[2]);
	output[11] =      (cast(limb) (cast(int) in2[5])) * (cast(int) in1[6]) +
		(cast(limb) (cast(int) in2[6])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[7])) * (cast(int) in1[4]) +
			(cast(limb) (cast(int) in2[3])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[3]) +
			(cast(limb) (cast(int) in2[2])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[2]);
	output[12] =      (cast(limb) (cast(int) in2[6])) * (cast(int) in1[6]) +
		2 * ((cast(limb) (cast(int) in2[5])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[7])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[3])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[3])) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[4]);
	output[13] =      (cast(limb) (cast(int) in2[6])) * (cast(int) in1[7]) +
		(cast(limb) (cast(int) in2[7])) * (cast(int) in1[6]) +
			(cast(limb) (cast(int) in2[5])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[5]) +
			(cast(limb) (cast(int) in2[4])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[4]);
	output[14] = 2 * ((cast(limb) (cast(int) in2[7])) * (cast(int) in1[7]) +
		(cast(limb) (cast(int) in2[5])) * (cast(int) in1[9]) +
		(cast(limb) (cast(int) in2[9])) * (cast(int) in1[5])) +
		(cast(limb) (cast(int) in2[6])) * (cast(int) in1[8]) +
			(cast(limb) (cast(int) in2[8])) * (cast(int) in1[6]);
	output[15] =      (cast(limb) (cast(int) in2[7])) * (cast(int) in1[8]) +
		(cast(limb) (cast(int) in2[8])) * (cast(int) in1[7]) +
			(cast(limb) (cast(int) in2[6])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[6]);
	output[16] =      (cast(limb) (cast(int) in2[8])) * (cast(int) in1[8]) +
		2 * ((cast(limb) (cast(int) in2[7])) * (cast(int) in1[9]) +
			(cast(limb) (cast(int) in2[9])) * (cast(int) in1[7]));
	output[17] =      (cast(limb) (cast(int) in2[8])) * (cast(int) in1[9]) +
		(cast(limb) (cast(int) in2[9])) * (cast(int) in1[8]);
	output[18] = 2 *  (cast(limb) (cast(int) in2[9])) * (cast(int) in1[9]);
}

/* Reduce a long form to a short form by taking the input mod 2^255 - 19.
 *
 * On entry: |output[i]| < 14*2^54
 * On exit: |output[0..8]| < 280*2^54 */
void freduce_degree(limb[] output) {
	/* Each of these shifts and adds ends up multiplying the value by 19.
	 *
	 * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
	 * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54. */
	output[8] += output[18] << 4;
	output[8] += output[18] << 1;
	output[8] += output[18];
	output[7] += output[17] << 4;
	output[7] += output[17] << 1;
	output[7] += output[17];
	output[6] += output[16] << 4;
	output[6] += output[16] << 1;
	output[6] += output[16];
	output[5] += output[15] << 4;
	output[5] += output[15] << 1;
	output[5] += output[15];
	output[4] += output[14] << 4;
	output[4] += output[14] << 1;
	output[4] += output[14];
	output[3] += output[13] << 4;
	output[3] += output[13] << 1;
	output[3] += output[13];
	output[2] += output[12] << 4;
	output[2] += output[12] << 1;
	output[2] += output[12];
	output[1] += output[11] << 4;
	output[1] += output[11] << 1;
	output[1] += output[11];
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];
}

static assert((-1 & 3) == 3, "This code only works on a two's complement system");

/* return v / 2^26, using only shifts and adds.
 *
 * On entry: v can take any value. */
limb div_by_2_26(in limb v)
{
	/* High word of v; no shift needed. */
	uint highword = cast(uint) (cast(ulong) v >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	int sign = (cast (int) highword) >> 31;
	/* Set to 0x3ffffff if v was negative; else set to 0. */
	int roundoff = (cast(uint) sign) >> 6;
	/* Should return v / (1<<26) */
	return (v + roundoff) >> 26;
}

/* return v / (2^25), using only shifts and adds.
 *
 * On entry: v can take any value. */
limb div_by_2_25(in limb v)
{
	/* High word of v; no shift needed*/
	uint highword = cast(uint) ((cast(ulong) v) >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	int sign = (cast(int) highword) >> 31;
	/* Set to 0x1ffffff if v was negative; else set to 0. */
	int roundoff = (cast(uint) sign) >> 7;
	/* Should return v / (1<<25) */
	return (v + roundoff) >> 25;
}

/* Reduce all coefficients of the short form input so that |x| < 2^26.
 *
 * On entry: |output[i]| < 280*2^54 */
void freduce_coefficients(ref limb[19] output)
{

	output[10] = 0;
	
	for (uint i = 0; i < 10; i += 2) {
		limb over = div_by_2_26(output[i]);
		/* The entry condition (that |output[i]| < 280*2^54) means that over is, at
		 * most, 280*2^28 in the first iteration of this loop. This is added to the
		 * next limb and we can approximate the resulting bound of that limb by
		 * 281*2^54. */
		output[i] -= over << 26;
		output[i+1] += over;
		
		/* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
		 * 281*2^29. When this is added to the next limb, the resulting bound can
		 * be approximated as 281*2^54.
		 *
		 * For subsequent iterations of the loop, 281*2^54 remains a conservative
		 * bound and no overflow occurs. */
		over = div_by_2_25(output[i+1]);
		output[i+1] -= over << 25;
		output[i+2] += over;
	}
	/* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];
	
	output[10] = 0;
	
	/* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
	 * So |over| will be no more than 2^16. */
	{
		limb over = div_by_2_26(output[0]);
		output[0] -= over << 26;
		output[1] += over;
	}
	
	/* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
	 * bound on |output[1]| is sufficient to meet our needs. */
}

/* A helpful wrapper around fproduct: output = in * in2.
 *
 * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
 *
 * output must be distinct to both inputs. The output is reduced degree
 * (indeed, one need only provide storage for 10 limbs) and |output[i]| < 2^26. */

void fmul(limb[] output, in limb[] in1, in limb[] in2)
in {
	// TODO check assertions
	assert(output.length >= 10);
	assert(in1.length >= 10);
	assert(in2.length >= 10);
}
body {
	limb[19] t;
	fproduct(t, in1, in2);
	/* |t[i]| < 14*2^54 */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	output[0..10] = t[0..10];
}

/* Square a number: output = in**2
 *
 * output must be distinct from the input. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
void fsquare_inner(limb[] output, in limb[] input) {
	output[0] =       (cast(limb) (cast(int) input[0])) * (cast(int) input[0]);
	output[1] =  2 *  (cast(limb) (cast(int) input[0])) * (cast(int) input[1]);
	output[2] =  2 * ((cast(limb) (cast(int) input[1])) * (cast(int) input[1]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[2]));
	output[3] =  2 * ((cast(limb) (cast(int) input[1])) * (cast(int) input[2]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[3]));
	output[4] =       (cast(limb) (cast(int) input[2])) * (cast(int) input[2]) +
		4 *  (cast(limb) (cast(int) input[1])) * (cast(int) input[3]) +
			2 *  (cast(limb) (cast(int) input[0])) * (cast(int) input[4]);
	output[5] =  2 * ((cast(limb) (cast(int) input[2])) * (cast(int) input[3]) +
		(cast(limb) (cast(int) input[1])) * (cast(int) input[4]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[5]));
	output[6] =  2 * ((cast(limb) (cast(int) input[3])) * (cast(int) input[3]) +
		(cast(limb) (cast(int) input[2])) * (cast(int) input[4]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[6]) +
		2 *  (cast(limb) (cast(int) input[1])) * (cast(int) input[5]));
	output[7] =  2 * ((cast(limb) (cast(int) input[3])) * (cast(int) input[4]) +
		(cast(limb) (cast(int) input[2])) * (cast(int) input[5]) +
		(cast(limb) (cast(int) input[1])) * (cast(int) input[6]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[7]));
	output[8] =       (cast(limb) (cast(int) input[4])) * (cast(int) input[4]) +
		2 * ((cast(limb) (cast(int) input[2])) * (cast(int) input[6]) +
			(cast(limb) (cast(int) input[0])) * (cast(int) input[8]) +
			2 * ((cast(limb) (cast(int) input[1])) * (cast(int) input[7]) +
				(cast(limb) (cast(int) input[3])) * (cast(int) input[5])));
	output[9] =  2 * ((cast(limb) (cast(int) input[4])) * (cast(int) input[5]) +
		(cast(limb) (cast(int) input[3])) * (cast(int) input[6]) +
		(cast(limb) (cast(int) input[2])) * (cast(int) input[7]) +
		(cast(limb) (cast(int) input[1])) * (cast(int) input[8]) +
		(cast(limb) (cast(int) input[0])) * (cast(int) input[9]));
	output[10] = 2 * ((cast(limb) (cast(int) input[5])) * (cast(int) input[5]) +
		(cast(limb) (cast(int) input[4])) * (cast(int) input[6]) +
		(cast(limb) (cast(int) input[2])) * (cast(int) input[8]) +
		2 * ((cast(limb) (cast(int) input[3])) * (cast(int) input[7]) +
			(cast(limb) (cast(int) input[1])) * (cast(int) input[9])));
	output[11] = 2 * ((cast(limb) (cast(int) input[5])) * (cast(int) input[6]) +
		(cast(limb) (cast(int) input[4])) * (cast(int) input[7]) +
		(cast(limb) (cast(int) input[3])) * (cast(int) input[8]) +
		(cast(limb) (cast(int) input[2])) * (cast(int) input[9]));
	output[12] =      (cast(limb) (cast(int) input[6])) * (cast(int) input[6]) +
		2 * ((cast(limb) (cast(int) input[4])) * (cast(int) input[8]) +
			2 * ((cast(limb) (cast(int) input[5])) * (cast(int) input[7]) +
				(cast(limb) (cast(int) input[3])) * (cast(int) input[9])));
	output[13] = 2 * ((cast(limb) (cast(int) input[6])) * (cast(int) input[7]) +
		(cast(limb) (cast(int) input[5])) * (cast(int) input[8]) +
		(cast(limb) (cast(int) input[4])) * (cast(int) input[9]));
	output[14] = 2 * ((cast(limb) (cast(int) input[7])) * (cast(int) input[7]) +
		(cast(limb) (cast(int) input[6])) * (cast(int) input[8]) +
		2 *  (cast(limb) (cast(int) input[5])) * (cast(int) input[9]));
	output[15] = 2 * ((cast(limb) (cast(int) input[7])) * (cast(int) input[8]) +
		(cast(limb) (cast(int) input[6])) * (cast(int) input[9]));
	output[16] =      (cast(limb) (cast(int) input[8])) * (cast(int) input[8]) +
		4 *  (cast(limb) (cast(int) input[7])) * (cast(int) input[9]);
	output[17] = 2 *  (cast(limb) (cast(int) input[8])) * (cast(int) input[9]);
	output[18] = 2 *  (cast(limb) (cast(int) input[9])) * (cast(int) input[9]);
}

/* fsquare sets output = in^2.
 *
 * On entry: The |in| argument is in reduced coefficients form and |in[i]| <
 * 2^27.
 *
 * On exit: The |output| argument is in reduced coefficients form (indeed, one
 * need only provide storage for 10 limbs) and |out[i]| < 2^26. */
void fsquare(limb[] output, in limb[] input) {
	limb[19] t;
	fsquare_inner(t, input);
	/* |t[i]| < 14*2^54 because the largest product of two limbs will be <
	 * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
	 * products. */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	output[0..10] = t[0..10];
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void fexpand(ref limb[10] output, in ref ubyte[32] input) 
{

	void F(uint n, uint start, uint shift, uint mask)(limb[] output, in ubyte[] input) {
		output[n] = ((input[start + 0] | 
				(input[start + 1]) << 8 | 
				(input[start + 2]) << 16 | 
				(input[start + 3]) << 24) >> shift) & mask;
	}

	F!(0, 0, 0, 0x3ffffff)(output, input);
	F!(1, 3, 2, 0x1ffffff)(output, input);
	F!(2, 6, 3, 0x3ffffff)(output, input);
	F!(3, 9, 5, 0x1ffffff)(output, input);
	F!(4, 12, 6, 0x3ffffff)(output, input);
	F!(5, 16, 0, 0x1ffffff)(output, input);
	F!(6, 19, 1, 0x3ffffff)(output, input);
	F!(7, 22, 3, 0x1ffffff)(output, input);
	F!(8, 25, 4, 0x3ffffff)(output, input);
	F!(9, 28, 6, 0x1ffffff)(output, input);

}

static assert((-32 >> 1) == -16, "This code only works when >> does sign-extension on negative numbers");

/* int_eq returns 0xffffffff iff a == b and zero otherwise. */
int int_eq(int a, int b) {
	a = ~(a ^ b);
	a &= a << 16;
	a &= a << 8;
	a &= a << 4;
	a &= a << 2;
	a &= a << 1;
	return a >> 31;
}

/* int_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
 * both non-negative. */
int int_gte(int a, int b) {
	a -= b;
	/* a >= 0 iff a >= b. */
	return ~(a >> 31);
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array.
 *
 * On entry: |input_limbs[i]| < 2^26 */
void fcontract(ubyte[] output, in limb[] input_limbs) 
in {
	assert(output.length == 32);
	assert(input_limbs.length == 10);
} body {
	int[10] input;
	int _mask;
	
	/* |input_limbs[i]| < 2^26, so it's valid to convert to an int. */
	for (uint i = 0; i < 10; i++) {
		input[i] = cast(uint) input_limbs[i];
	}

	for (uint j = 0; j < 2; ++j) {
		for (uint i = 0; i < 9; ++i) {
			if ((i & 1) == 1) {
				/* This calculation is a time-invariant way to make input[i]
				 * non-negative by borrowing from the next-larger limb. */
				immutable int mask = input[i] >> 31;
				immutable int carry = -((input[i] & mask) >> 25);
				input[i] = input[i] + (carry << 25);
				input[i+1] = input[i+1] - carry;
			} else {
				immutable int mask = input[i] >> 31;
				immutable int carry = -((input[i] & mask) >> 26);
				input[i] = input[i] + (carry << 26);
				input[i+1] = input[i+1] - carry;
			}
		}
		
		/* There's no greater limb for input[9] to borrow from, but we can multiply
		 * by 19 and borrow from input[0], which is valid mod 2^255-19. */
		{
			immutable int mask = input[9] >> 31;
			immutable int carry = -((input[9] & mask) >> 25);
			input[9] = input[9] + (carry << 25);
			input[0] = input[0] - (carry * 19);
		}
		
		/* After the first iteration, input[1..9] are non-negative and fit within
		 * 25 or 26 bits, depending on position. However, input[0] may be
		 * negative. */
	}
	
	/* The first borrow-propagation pass above ended with every limb
	 except (possibly) input[0] non-negative.

	 If input[0] was negative after the first pass, then it was because of a
	 carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
	 one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.

	 In the second pass, each limb is decreased by at most one. Thus the second
	 borrow-propagation pass could only have wrapped around to decrease
	 input[0] again if the first pass left input[0] negative *and* input[1]
	 through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
	 and this last borrow-propagation step will leave input[1] non-negative. */
	{
		immutable int mask = input[0] >> 31;
		immutable int carry = -((input[0] & mask) >> 26);
		input[0] = input[0] + (carry << 26);
		input[1] = input[1] - carry;
	}
	
	/* All input[i] are now non-negative. However, there might be values between
	 * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide. */
	for (uint j = 0; j < 2; j++) {
		for (uint i = 0; i < 9; i++) {
			if ((i & 1) == 1) {
				immutable int carry = input[i] >> 25;
				input[i] &= 0x1ffffff;
				input[i+1] += carry;
			} else {
				immutable int carry = input[i] >> 26;
				input[i] &= 0x3ffffff;
				input[i+1] += carry;
			}
		}
		
		{
			immutable int carry = input[9] >> 25;
			input[9] &= 0x1ffffff;
			input[0] += 19*carry;
		}
	}
	
	/* If the first carry-chain pass, just above, ended up with a carry from
	 * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
	 * < 2^26 + 2*19, because the carry was, at most, two.
	 *
	 * If the second pass carried from input[9] again then input[0] is < 2*19 and
	 * the input[9] -> input[0] carry didn't push input[0] out of bounds. */
	
	/* It still remains the case that input might be between 2^255-19 and 2^255.
	 * In this case, input[1..9] must take their maximum value and input[0] must
	 * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed. */
	_mask = int_gte(input[0], 0x3ffffed);
	for (uint i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			_mask &= int_eq(input[i], 0x1ffffff);
		} else {
			_mask &= int_eq(input[i], 0x3ffffff);
		}
	}
	
	/* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
	 * this conditionally subtracts 2^255-19. */
	input[0] -= _mask & 0x3ffffed;
	
	for (uint i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			input[i] -= _mask & 0x1ffffff;
		} else {
			input[i] -= _mask & 0x3ffffff;
		}
	}
	
	input[1] <<= 2;
	input[2] <<= 3;
	input[3] <<= 5;
	input[4] <<= 6;
	input[6] <<= 1;
	input[7] <<= 3;
	input[8] <<= 4;
	input[9] <<= 6;

	void F(uint i, uint s)() {
		output[s+0] |=  input[i] & 0xff; 
		output[s+1]  = (input[i] >> 8) & 0xff; 
		output[s+2]  = (input[i] >> 16) & 0xff; 
		output[s+3]  = (input[i] >> 24) & 0xff;
	}

	output[0] = 0;
	output[16] = 0;
	F!(0,0)();
	F!(1,3)();
	F!(2,6)();
	F!(3,9)();
	F!(4,12)();
	F!(5,16)();
	F!(6,19)();
	F!(7,22)();
	F!(8,25)();
	F!(9,28)();
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 *
 * On entry and exit, the absolute value of the limbs of all inputs and outputs
 * are < 2^26. */
void fmonty(ref limb[19] x2, ref limb[19] z2,  /* output 2Q */
	ref limb[19] x3, ref limb[19] z3,  /* output Q + Q' */
	ref limb[19] x, ref limb[19] z,    /* input Q */
	ref limb[19] xprime, ref limb[19] zprime,  /* input Q' */
	in ref limb[10] qmqp /* input Q - Q' */) 
{

	limb[10] origx, origxprime;
	limb[19] zzz, xx, zz, xxprime,
		zzprime, zzzprime, xxxprime;
	
	//memcpy(origx, x, 10 * sizeofcast(limb));
	origx[0..10] = x[0..10];

	fsum(x, z);
	/* |x[i]| < 2^27 */
	fdifference(z, origx);  /* does x - z */
	/* |z[i]| < 2^27 */
	
	//memcpy(origxprime, xprime, sizeofcast(limb) * 10);
	origxprime[0..10] = xprime[0..10];

	fsum(xprime, zprime);
	/* |xprime[i]| < 2^27 */
	fdifference(zprime, origxprime);
	/* |zprime[i]| < 2^27 */
	fproduct(xxprime, xprime, z);
	/* |xxprime[i]| < 14*2^54: the largest product of two limbs will be <
	 * 2^(27+27) and fproduct adds together, at most, 14 of those products.
	 * (Approximating that to 2^58 doesn't work out.) */
	fproduct(zzprime, x, zprime);
	/* |zzprime[i]| < 14*2^54 */
	freduce_degree(xxprime);
	freduce_coefficients(xxprime);
	/* |xxprime[i]| < 2^26 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	//memcpy(origxprime, xxprime, sizeofcast(limb) * 10);
	origxprime[0..10] = xxprime[0..10];
	fsum(xxprime, zzprime);
	/* |xxprime[i]| < 2^27 */
	fdifference(zzprime, origxprime);
	/* |zzprime[i]| < 2^27 */
	fsquare(xxxprime, xxprime);
	/* |xxxprime[i]| < 2^26 */
	fsquare(zzzprime, zzprime);
	/* |zzzprime[i]| < 2^26 */
	fproduct(zzprime, zzzprime, qmqp);
	/* |zzprime[i]| < 14*2^52 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	//memcpy(x3, xxxprime, sizeofcast(limb) * 10);
	x3[0..10] = xxxprime[0..10];
	//memcpy(z3, zzprime, sizeofcast(limb) * 10);
	z3[0..10] = zzprime[0..10];
	
	fsquare(xx, x);
	/* |xx[i]| < 2^26 */
	fsquare(zz, z);
	/* |zz[i]| < 2^26 */
	fproduct(x2, xx, zz);
	/* |x2[i]| < 14*2^52 */
	freduce_degree(x2);
	freduce_coefficients(x2);
	/* |x2[i]| < 2^26 */
	fdifference(zz, xx);  // does zz = xx - zz
	/* |zz[i]| < 2^27 */
	//memset(zzz + 10, 0, sizeofcast(limb) * 9);
	zzz[10..19] = 0;

	fscalar_product(zzz, zz, 121665);
	/* |zzz[i]| < 2^(27+17) */
	/* No need to call freduce_degree here:
	 fscalar_product doesn't increase the degree of its input. */
	freduce_coefficients(zzz);
	/* |zzz[i]| < 2^26 */
	fsum(zzz, xx);
	/* |zzz[i]| < 2^27 */
	fproduct(z2, zz, zzz);
	/* |z2[i]| < 14*2^(26+27) */
	freduce_degree(z2);
	freduce_coefficients(z2);
	/* |z2|i| < 2^26 */
}

/* Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
 * them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
 * side-channel attacks.
 *
 * NOTE that this function requires that 'iswap' be 1 or 0; other values give
 * wrong results.  Also, the two limb arrays must be in reduced-coefficient,
 * reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
 * and all all values in a[0..9],b[0..9] must have magnitude less than
 * INT32_MAX. */
void swap_conditional(ref limb[19] a, ref limb[19] b, in limb iswap) 
in {
	assert(iswap == 0 || iswap == 1, "requires 'iswap' to be 1 or 0");
}
body {
	immutable int swap = cast(int) -iswap;
	
	for (uint i = 0; i < 10; ++i) {
		immutable int x = swap & ( (cast(int)a[i]) ^ (cast(int)b[i]) );
		a[i] = (cast(int)a[i]) ^ x;
		b[i] = (cast(int)b[i]) ^ x;
	}
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form) */
void cmult(ref limb[10] resultx, ref limb[10] resultz, in ref ubyte[32] n, in ref limb[10] q) 
{
	limb[19] a, b, c, d;
	b[0] = 1;
	c[0] = 1;

	alias nqpqx = a, nqpqz = b, nqx = c, nqz = d;
	limb[] t;
	limb[19] e, f, g, h;
	f[0] = 1;
	h[0] = 1;
	alias nqpqx2 = e, nqpqz2 = f, nqx2 = g, nqz2 = h;

	nqpqx[0..10] = q[0..10];
	
	for (uint i = 0; i < 32; ++i) {
		ubyte byt = n[31 - i];
		for (uint j = 0; j < 8; ++j) {
			immutable limb bit = byt >> 7;
			
			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
				nqpqx2, nqpqz2,
				nqx, nqz,
				nqpqx, nqpqz,
				q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);
			
			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byt <<= 1;
		}
	}

	resultx[0..10] = nqx[0..10];
	resultz[0..10] = nqz[0..10];
}

// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code :-)
// -----------------------------------------------------------------------------
void crecip(limb[] output, in limb[] z) {
	limb[10] z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1;

	/* 2 */ fsquare(z2,z);
	/* 4 */ fsquare(t1,z2);
	/* 8 */ fsquare(t0,t1);
	/* 9 */ fmul(z9,t0,z);
	/* 11 */ fmul(z11,z9,z2);
	/* 22 */ fsquare(t0,z11);
	/* 2^5 - 2^0 = 31 */ fmul(z2_5_0,t0,z9);
	
	/* 2^6 - 2^1 */ fsquare(t0,z2_5_0);
	/* 2^7 - 2^2 */ fsquare(t1,t0);
	/* 2^8 - 2^3 */ fsquare(t0,t1);
	/* 2^9 - 2^4 */ fsquare(t1,t0);
	/* 2^10 - 2^5 */ fsquare(t0,t1);
	/* 2^10 - 2^0 */ fmul(z2_10_0,t0,z2_5_0);
	
	/* 2^11 - 2^1 */ fsquare(t0,z2_10_0);
	/* 2^12 - 2^2 */ fsquare(t1,t0);
	/* 2^20 - 2^10 */ for (uint i = 2;i < 10;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
	/* 2^20 - 2^0 */ fmul(z2_20_0,t1,z2_10_0);
	
	/* 2^21 - 2^1 */ fsquare(t0,z2_20_0);
	/* 2^22 - 2^2 */ fsquare(t1,t0);
	/* 2^40 - 2^20 */ for (uint i = 2;i < 20;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
	/* 2^40 - 2^0 */ fmul(t0,t1,z2_20_0);
	
	/* 2^41 - 2^1 */ fsquare(t1,t0);
	/* 2^42 - 2^2 */ fsquare(t0,t1);
	/* 2^50 - 2^10 */ for (uint i = 2;i < 10;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
	/* 2^50 - 2^0 */ fmul(z2_50_0,t0,z2_10_0);

	/* 2^51 - 2^1 */ fsquare(t0,z2_50_0);
	/* 2^52 - 2^2 */ fsquare(t1,t0);
	/* 2^100 - 2^50 */ for (uint i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
	/* 2^100 - 2^0 */ fmul(z2_100_0,t1,z2_50_0);
	
	/* 2^101 - 2^1 */ fsquare(t1,z2_100_0);
	/* 2^102 - 2^2 */ fsquare(t0,t1);
	/* 2^200 - 2^100 */ for (uint i = 2;i < 100;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
	/* 2^200 - 2^0 */ fmul(t1,t0,z2_100_0);
	
	/* 2^201 - 2^1 */ fsquare(t0,t1);
	/* 2^202 - 2^2 */ fsquare(t1,t0);
	/* 2^250 - 2^50 */ for (uint i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
	/* 2^250 - 2^0 */ fmul(t0,t1,z2_50_0);

	/* 2^251 - 2^1 */ fsquare(t1,t0);
	/* 2^252 - 2^2 */ fsquare(t0,t1);
	/* 2^253 - 2^3 */ fsquare(t1,t0);
	/* 2^254 - 2^4 */ fsquare(t0,t1);
	/* 2^255 - 2^5 */ fsquare(t1,t0);
	/* 2^255 - 21 */ fmul(output,t1,z11);
}
