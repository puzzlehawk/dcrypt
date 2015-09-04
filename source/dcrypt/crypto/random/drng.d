module dcrypt.crypto.random.drng;

import dcrypt.crypto.digest;
import std.algorithm: min;

unittest {
	import dcrypt.crypto.digests.sha2;
	import std.stdio;

	HashDRNG!SHA256 drng;

	ubyte[64] buf;

	drng.nextBytes(buf);

	writefln("%(%0.2x%)", buf);
}

/// Standard: NIST SP 800-90A
@safe
struct HashDRNG(D) if(isDigest!D) {

	public {
		enum isDeterministic = true;
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

	/// Little endian increment.
	private void increment(ref ubyte[seedlen] v) {

		for(uint i = 0; i < v.length; ++i) {

			if(++v[i] != 0) {
				break;
			}

		}
	}

	/// a += b;
	private static void add(uint seedlen)(ref ubyte[seedlen] a, in ref ubyte[seedlen] b) {
		ubyte carry = 0;
		for(uint i = 0; i < seedlen; ++i) {
			uint t = cast(uint) a[i] + b[i] + carry;
			a[i] = cast(ubyte) t;
			carry = cast(ubyte) (t >> 8);
		}
	}

	/// a += b;
	private static void add(uint seedlen)(ref ubyte[seedlen] a, ulong b) {
		ubyte carry = 0;
		for(uint i = 0; i < seedlen; ++i) {
			uint t = cast(uint) a[i] + (b & 0xFF) + carry;
			a[i] = cast(ubyte) t;
			carry = cast(ubyte) (t >> 8);
			b >>= 8;
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
}
