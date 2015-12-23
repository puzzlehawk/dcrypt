module dcrypt.pqc.sphincs.common;

/// Functions used in different SPHINCS components.

import std.traits: ReturnType;

import dcrypt.crypto.digests.blake;
import dcrypt.bitmanip;

package:

package template is_hash_n_n(alias func, H = ReturnType!func)
{
	enum bool is_hash_n_n =
		is(typeof(
				{
					H h1;
					h1 = func(h1);
				}));
}


package template is_hash_2n_n(alias func, H = ReturnType!func)
{
	enum bool is_hash_2n_n =
		is(typeof(
				{
					H h1, h2;
					h1 = func(h1, h2);
				}));
}

package template is_prg(alias prg, uint seed_bytes)
{
	enum bool is_prg =
		is(typeof(
				{
					ubyte[] buf;
					ubyte[seed_bytes] seed;
					prg(buf, seed);
				}));
}

/// Create the parent node of two sibling nodes in a binary hash tree.
/// Equals hash_2n_n_mask in ref.
/// Params:
/// left	=	Hash of left node.
/// right	=	Hash of right node.
/// bitmask	=	A bitmask for both nodes.
@safe @nogc pure nothrow
H hash_2n_n_mask(alias hash_2n_n, H, M)(in ref H left, in ref H right, in ref M bitmask)
	if(2*H.length == M.length && is_hash_2n_n!(hash_2n_n, H))
{
	return hash_2n_n_mask!(hash_2n_n, H)(left, right, bitmask[0..$/2], bitmask[$/2..$]);
}

/// Create the parent node of two sibling nodes in a binary hash tree.
/// Equals hash_2n_n_mask in ref.
/// 
/// Params:
/// left	=	Hash of left node.
/// right	=	Hash of right node.
/// bitmask_left	=	Bitmask for left hash.
/// bitmask_right	=	Bitmask for left right.
@safe @nogc pure nothrow 
H hash_2n_n_mask(alias hash_2n_n, H)(in ref H left, in ref H right, in ref H bitmask_left, in ref H bitmask_right)
	if(is_hash_2n_n!(hash_2n_n, H))
{
	H m1 = left;
	H m2 = right;
	m1[] ^= bitmask_left[];
	m2[] ^= bitmask_right[];
	return hash_2n_n(m1, m2);
}

/// Wrapper for hash!Blake256.
template varlen_hash(T...) {
	@safe @nogc
	auto varlen_hash(T...)(in T data) nothrow {
		return hash!Blake256(data);
	}
}


// Sanity test for varlen_hash.
private unittest {
	ubyte[] a = [1,2,3];
	ubyte[] b = [4,5,6];

	assert(varlen_hash(a) != varlen_hash(b));
	assert(varlen_hash(a,b) == varlen_hash(a~b));
}

/// Calclulate the number of digits of x in base 'base' representation.
@nogc @safe pure nothrow
package uint num_digits(ulong x, uint base) {
	uint log = 0;
	while(x > 0) {
		++log;
		x /= base;
	}
	return log;
}

private unittest {
	assert(num_digits(255, 2) == 8);
	assert(num_digits(256, 2) == 9);

	assert(num_digits(1, 10) == 1);
	assert(num_digits(9, 10) == 1);
	assert(num_digits(10, 10) == 2);
	assert(num_digits(99, 10) == 2);
	assert(num_digits(100, 10) == 3);
}