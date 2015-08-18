module dcrypt.crypto.ecc.ed25519.fieldElement;

// from fe.h

//#ifndef FE_H
//#define FE_H
//
//#include "crypto_int32.h"

alias uint[10] fe;


/// fe means field element.
/// Here the field is \Z/(2^255-19).
/// An element t, entries t[0]...t[9], represents the integer
/// t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
/// Bounds on each t[i] vary depending on context.


//#define fe_frombytes crypto_sign_ed25519_ref10_fe_frombytes
//#define fe_tobytes crypto_sign_ed25519_ref10_fe_tobytes
//#define fe_copy crypto_sign_ed25519_ref10_fe_copy
//#define fe_isnonzero crypto_sign_ed25519_ref10_fe_isnonzero
//#define fe_isnegative crypto_sign_ed25519_ref10_fe_isnegative
//#define fe_0 crypto_sign_ed25519_ref10_fe_0
//#define fe_1 crypto_sign_ed25519_ref10_fe_1
//#define fe_cswap crypto_sign_ed25519_ref10_fe_cswap
//#define fe_cmov crypto_sign_ed25519_ref10_fe_cmov
//#define fe_add crypto_sign_ed25519_ref10_fe_add
//#define fe_sub crypto_sign_ed25519_ref10_fe_sub
//#define fe_neg crypto_sign_ed25519_ref10_fe_neg
//#define fe_mul crypto_sign_ed25519_ref10_fe_mul
//#define fe_sq crypto_sign_ed25519_ref10_fe_sq
//#define fe_sq2 crypto_sign_ed25519_ref10_fe_sq2
//#define fe_mul121666 crypto_sign_ed25519_ref10_fe_mul121666
//#define fe_invert crypto_sign_ed25519_ref10_fe_invert
//#define fe_pow22523 crypto_sign_ed25519_ref10_fe_pow22523
//
//extern void fe_frombytes(fe,const unsigned char *);
//extern void fe_tobytes(unsigned char *,const fe);
//
//extern void fe_copy(fe,const fe);
//extern int fe_isnonzero(const fe);
//extern int fe_isnegative(const fe);
//extern void fe_0(fe);
//extern void fe_1(fe);
//extern void fe_cswap(fe,fe,unsigned int);
//extern void fe_cmov(fe,const fe,unsigned int);
//
//extern void fe_add(fe,const fe,const fe);
//extern void fe_sub(fe,const fe,const fe);
//extern void fe_neg(fe,const fe);
//extern void fe_mul(fe,const fe,const fe);
//extern void fe_sq(fe,const fe);
//extern void fe_sq2(fe,const fe);
//extern void fe_mul121666(fe,const fe);
//extern void fe_invert(fe,const fe);
//extern void fe_pow22523(fe,const fe);
//
//#endif

/// h = 0
void fe_0(ref fe h)
{
	h[] = 0;
}

/// h = 1
void fe_1(ref fe h)
{
	h[0] = 1;
	h[1..10] = 0;
}

/// h = f + g
/// Can overlap h with f or g.
///
/// Preconditions:
///   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
///   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
///
/// Postconditions:
///  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
void fe_add(ref fe h, in ref fe f, in ref fe g)
{
	h[] = f[] + g[];
}

/*
 * Conditional move.
 Replace (f,g) with (g,g) if b == 1;
 replace (f,g) with (f,g) if b == 0.

 Preconditions: b in {0,1}.
 
 TODO change b to bool
 */
void fe_cmov(ref fe f, in ref fe g, in uint b)
in {
	assert(b == 0 || b == 1);
} body {
	immutable uint mask = -b;

	f[] ^= mask&g[];
	f[] ^= mask&f[];
}

// test conditional move
unittest {
	import std.algorithm: all;

	fe a, b;
	a[] = 13;
	b[] = 42;

	assert(all!"a == 13"(a[]));
	assert(all!"a == 42"(b[]));

	fe_cmov(a, b, 0);

	assert(all!"a == 13"(a[]));
	assert(all!"a == 42"(b[]));

	fe_cmov(a, b, 0);

	assert(all!"a == 42"(b[]));
	assert(all!"a == 42"(b[]));
}