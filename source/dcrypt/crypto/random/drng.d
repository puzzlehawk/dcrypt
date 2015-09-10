module dcrypt.crypto.random.drng;

/// The DRNG module contains a collection of deterministic random number generators.

import dcrypt.crypto.random.prng;
import dcrypt.crypto.digest;
import dcrypt.crypto.digests.sha2: SHA256;
import dcrypt.util.pack;
import std.algorithm: min;

///
/// Test if T is a deterministic random number generator.
/// Returns: Returns $(D true) if T can be used as a DRNG.
/// 
@safe @nogc nothrow
template isDRNG(T)
{
	enum bool isDRNG = 
		is(T == struct) && isRNG!T && // isInputRange!T &&
			is(typeof(
					{
						ubyte[] buf;
						T rng = T.init;
						bool d = T.isDeterministic;
						rng.setSeed(cast(const ubyte[]) buf); // Can set the generator to well known state.
						rng.setSeed(cast(ubyte) 0);					// variadic template
						rng.setSeed(cast(ubyte) 0, cast(ubyte) 0);
					}));
}

/// Generate a pseudo random but deterministic sequence of bytes.
unittest {
	import dcrypt.crypto.digests.sha2;
	import std.stdio;

	HashDRNG!SHA256 drng;

	ubyte[64] buf;

	drng.setSeed(0);
	drng.addSeed(1, 2, 3);
	drng.nextBytes(buf);
}

static assert(isDRNG!(HashDRNG!SHA256), HashDRNG.name~" is no DRNG.");

/// Standard: NIST SP 800-90A
@safe
struct HashDRNG(D) if(isDigest!D) {

	public {
		enum isDeterministic = true;
		enum name = "HashDRNG-" ~ D.name;
	}

	private {
		enum seedlen = D.digestLength;
		ubyte[seedlen] V, C;
		ulong reseedCounter;
	}

	nothrow @nogc:

	/// Initialize the generator with given seed.
	void setSeed(in ubyte[] seed...) {
		D hash;
		hash.put(seed);
		V = hash.finish();

		hash.put(cast(ubyte) 0x00);
		hash.put(V);
		C = hash.finish();

		reseedCounter = 1;
	}

	
	/// Add entropy to the generators internal state.
	void addSeed(in ubyte[] seed...) {
		D hash;
		hash.put(0x01);
		hash.put(V);
		hash.put(seed);

		hash.put(cast(ubyte) 0x00);
		hash.put(V);
		C = hash.finish();
		
		reseedCounter = 1;
	}

	/// Generate pseudo random bytes.
	/// Params:
	/// buf = Fill this buffer with random data.
	/// additionalInput = Can provide more entropy. Similar but not equal to callin addSeed() before.
	void nextBytes(ubyte[] buf, in ubyte[] additionalInput...) {
		D hash;

		if(additionalInput.length > 0) {
			hash.put(0x02);
			hash.put(V);
			hash.put(additionalInput);
			ubyte[seedlen] w = hash.finish();
			add(V, w);
		}

		hashGen(buf);

		hash.put(0x03);
		hash.put(V);
		immutable ubyte[seedlen] H = hash.finish();

		add(V, H);
		add(V, reseedCounter);

		++reseedCounter;
	}

	private void hashGen(ubyte[] buf) {
		ubyte[seedlen] data = V;
		D hash;
		while(buf.length > 0) {
			size_t len = min(seedlen, buf.length);
			hash.put(data);
			buf[0..len] = hash.finish()[0..len];
			buf = buf[len..$];
			increment(data);
		}
	}

}

/// NIST SP800-90A, Section 10.4.1
private void hashDF(D)(ubyte[] buf, in ubyte[] seed...) if(isDigest!D) {
	ubyte counter = 1;
	ubyte[4] outputLen; /// output length in bits

	toBigEndian!uint(cast(uint) buf.length*8, outputLen);	// BC compatible
	//toLittleEndian!uint(cast(uint) buf.length*8, outputLen);

	D digest;

	while(buf.length > 0) {
		digest.put(counter);
		digest.put(outputLen);
		digest.put(seed);

		size_t len = min(buf.length, D.digestLength);
		buf[0..len] = digest.finish()[0..len];
		buf = buf[len..$];

		++ counter;
	}
}

// test hashDF
private unittest {
	ubyte[70] buf;
	hashDF!SHA256(buf, cast(const ubyte[]) "seed");
	import std.stdio;
	writefln("%(%.2x%)", buf);

	assert(buf == x"ae678a8fcbcfaf3bcf57395b6fa3c614516d21182992780fb155bc75ded4369ac44ebfc392d9990553d59f6beffa1fb56d3962be000d1a7d009674240f02855b7a8fd125dd19");
}


/// Little endian increment.
private void increment(ubyte[] v) nothrow @safe @nogc {
	
	for(uint i = 0; i < v.length; ++i) {
		
		if(++v[i] != 0) {
			break;
		}
		
	}
}


/// Add number to little endian byte string.
/// a += b;
private void add(ubyte[] a, ulong b) nothrow @safe @nogc {
	ubyte carry = 0;
	for(uint i = 0; i < a.length; ++i) {
		uint t = cast(uint) a[i] + (b & 0xFF) + carry;
		a[i] = cast(ubyte) t;
		carry = cast(ubyte) (t >> 8);
		b >>= 8;
	}
}


/// a += b;
private void add(ubyte[] a, in ubyte[] b) nothrow @safe @nogc
in {
	assert(a.length >= b.length);
} body {
	ubyte carry = 0;

	for(uint i = 0; i < a.length; ++i) {
		uint t = cast(uint) a[i] + carry;
		if(i < b.length) {
			t += b[i];
		}
		a[i] = cast(ubyte) t;
		carry = cast(ubyte) (t >> 8);
	}

}

// testing add()
private unittest {
	ubyte[32] a, b;
	add(a, 0xFF);
	assert(a[0..4] == x"FF000000");
	add(b, 0xFF00);
	assert(b[0..4] == x"00FF0000");
	add(a, b);
	assert(a[0..4] == x"FFFF0000");
	add(a, 1);
	assert(a[0..4] == x"00000100");
}