module dcrypt.crypto.random.drng;

/// The DRNG module contains a collection of deterministic random number generators.

public import dcrypt.crypto.random.prng;
import dcrypt.crypto.digest;
import dcrypt.crypto.digests.sha1;
import dcrypt.crypto.digests.sha2;
import dcrypt.util.pack;
import dcrypt.util.util: wipe;
import std.algorithm: min;
import std.traits: isIntegral;

///
/// Test if T is a deterministic random number generator.
/// Returns: Returns $(D true) if T can be used as a DRNG.
/// 
@safe @nogc nothrow
template isDRNG(T)
{
	enum bool isDRNG = isRNG!T &&
			T.isDeterministic &&
			is(typeof(
					{
						ubyte[] buf;
						T rng = T.init;
						rng.setSeed(cast(const ubyte[]) buf); // Can set the generator to well known state.
						rng.setSeed(cast(ubyte) 0);					// variadic template
						rng.setSeed(cast(ubyte) 0, cast(ubyte) 0);
					}));
}

@safe @nogc nothrow
template isDRNGWithInput(T)
{
	enum bool isDRNGWithInput = isDRNG!T && isRNGWithInput!T;
}

/// Generate a pseudo random but deterministic sequence of bytes.
unittest {
	import dcrypt.crypto.digests.sha2;
	//import std.stdio;

	HashDRNG_SHA256 drng;

	ubyte[70] buf;

	drng.nextBytes(buf);

	//writefln("%(%.2x%)", buf);
}

alias HashDRNG!(SHA1, 440) HashDRNG_SHA1;
alias HashDRNG!(SHA256, 440) HashDRNG_SHA256;
alias HashDRNG!(SHA384, 888) HashDRNG_SHA384;
alias HashDRNG!(SHA512, 888) HashDRNG_SHA512;

static assert(isDRNG!HashDRNG_SHA256 && isRNGWithInput!HashDRNG_SHA256 , HashDRNG.name~" is no DRNG.");

/// Standard: NIST SP800-90A, HashDRBG
/// 
/// Params:
/// D = The underlying digest.
/// seedlen = Length of internal state in bits. See NIST SP800-90A, Section 10.1.
@safe
struct HashDRNG(D, uint seedlen) if(isStdDigest!D && seedlen % 8 == 0) {

	public {
		enum isDeterministic = true;
		enum name = "HashDRNG-" ~ D.name;
	}

	private {
		ubyte[seedlen/8] V, C;
		ulong reseedCounter;
	}
	nothrow @nogc:

	~this() {
		wipe(V);
		wipe(C);
	}

	/// Initialize the generator with given seed.
	void setSeed(in ubyte[] seed...) {

		hashDF!D(V, seed);

		hashDF!D(V, cast(ubyte) 0x00, V);

		reseedCounter = 1;
	}
	
	/// Add entropy to the generators internal state.
	void addSeed(in ubyte[] seed...) {

		hashDF!D(V, cast(ubyte) 0x01, V, seed);

		hashDF!D(C, cast(ubyte) 0x00, V);
		
		reseedCounter = 1;
	}

	/// Generate pseudo random bytes.
	/// Params:
	/// buf = Fill this buffer with random data.
	/// additionalInput = Can provide more entropy. Similar but not equal to callin addSeed() before.
	void nextBytes(ubyte[] buf, in ubyte[] additionalInput...) {
		D hash;

		if(additionalInput.length > 0) {
			hash.putAll(cast(ubyte) 0x02, V, additionalInput);
			ubyte[D.digestLength] w = hash.finish();
			add(V, w);
		}

		hashGen(buf);

		hash.putAll(cast(ubyte) 0x03, V);
		immutable ubyte[D.digestLength] H = hash.finish();

		add(V, H);
		add(V, reseedCounter);

		++reseedCounter;
	}

	private void hashGen(ubyte[] buf) {
		ubyte[V.length] data = V;
		D hash;
		while(buf.length > 0) {
			size_t len = min(D.digestLength, buf.length);
			hash.put(data);
			buf[0..len] = hash.finish()[0..len];
			buf = buf[len..$];
			increment(data);
		}
		wipe(data);
	}

}

/// Hash derivation function.
/// Standard: NIST SP800-90A, Section 10.4.1
/// Note: Number of output bits is implicitly defined by buf.length*8.
private void hashDF(D, T...)(ubyte[] buf, in T seed) if(isDigest!D) {
	ubyte counter = 1;
	ubyte[4] outputLen; /// output length in bits

	outputLen = toEndian!uint(cast(uint) buf.length*8);	// BC compatible
	//outputLen = toLittleEndian!uint(cast(uint) buf.length*8, outputLen);

	D digest;

	while(buf.length > 0) {

		digest.putAll(counter, outputLen, seed);

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

	assert(buf == x"ae678a8fcbcfaf3bcf57395b6fa3c614516d21182992780fb155bc75ded4369ac44ebfc392d9990553d59f6beffa1fb56d3962be000d1a7d009674240f02855b7a8fd125dd19");
}


/// Little endian increment.
private void increment(ubyte[] v) nothrow @safe @nogc {
	ubyte[1] one = 1;
	add(v, one);
}


private alias toBigEndian toEndian; /// easily switch between LE and BE

/// Add number to little endian byte string.
/// a += b;
private void add(T)(ubyte[] a, T b) nothrow @safe @nogc 
if(isIntegral!T) {
	add(a, toEndian!T(b));
}


/// a += b;
private void add(ubyte[] a, in ubyte[] b) nothrow @safe @nogc
in {
	assert(a.length >= b.length);
} body {
	ubyte carry = 0;

	for(uint i = 0; i < a.length; ++i) {
		uint t = cast(uint) a[$-1-i] + carry;
		if(i < b.length) {
			t += b[$-1-i];
		}
		a[$-1-i] = cast(ubyte) t;
		carry = cast(ubyte) (t >> 8);
	}

}

// testing add()
private unittest {
	ubyte[4] a, b;

	add(a, 0xFF);
	assert(a[0..4] == toEndian(0xFF));
	add(b, 0xFF00);
	assert(b[0..4] == toEndian(0xFF00));
	add(a, b);
	assert(a[0..4] == toEndian(0xFFFF));
	add(a, 1);
	assert(a[0..4] == toEndian(0x10000));
}