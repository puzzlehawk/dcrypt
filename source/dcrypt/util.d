﻿module dcrypt.util;

import core.vararg;
import std.traits;
import std.algorithm;

/// TODO: neat variadic implementation of `wipe()`

/// Clears data in memory.
@safe @nogc nothrow
void wipe(T)(ref T t) {
	static if(is(typeof(cast (ubyte[]) t))) {
		ubyte[] bytes = cast(ubyte[]) t;

		bytes[] = 0;

		if(!all!"a == 0"(bytes[])) {
			// This should not get optimized away.
			assert(false, "Wiping failed.");
		}
	} else static if ( is(typeof( {T a = T.init;} ))) {
		t = T.init;

		if(t != T.init) {
			// This should not get optimized away.
			assert(false, "Wiping failed.");
		}
	} else {
		static assert(false, "Type not supported for wiping: " ~ T.stringof);
	}
}


@safe @nogc nothrow
void wipe(T...)(ref T ts) {
	foreach(ref t; ts) {
		wipe(t);
	}
}

// test static arrays
unittest {
	ubyte[4] buf1 = [1,2,3,4];
	uint[4] buf2 = [1,2,3,4];
	size_t[4] buf3 = [1,2,3,4];

	wipe(buf1);
	wipe(buf2);
	wipe(buf3);

	assert(all!"a == 0"(buf1[]), "Failed to wipe ubyte[].");
	assert(all!"a == 0"(buf2[]), "Failed to wipe ubyte[].");
	assert(all!"a == 0"(buf3[]), "Failed to wipe ubyte[].");
}

// test dynamic arrays
unittest {
	ubyte[] buf1 = [1,2,3,4];
	uint[] buf2 = [1,2,3,4];
	size_t[] buf3 = [1,2,3,4];

	wipe(buf1, buf2, buf3);
	
	assert(all!"a == 0"(buf1), "Failed to wipe ubyte[].");
	assert(all!"a == 0"(buf2), "Failed to wipe ubyte[].");
	assert(all!"a == 0"(buf3), "Failed to wipe ubyte[].");
}

unittest {
	int a = 42;
	int b = 84;
	ubyte c = 1;

	wipe(a, b, c);

	assert(a == 0 && b == 0 && c == 0, "Wiping integer failed!");
}

/// Compares a and b in constant time.
/// 
/// Returns: 0 if a == b, some other value if a != b.
bool crypto_equals(T)(in T[] a, in T[] b) pure nothrow @safe @nogc
in {
	assert(a.length == b.length, "Unequal length.");
} body  {
	T result = 0;
	size_t i = 0;

	while(i < a.length) {
		result |= a[i] ^ b[i];
		++i;
	}

	if(i != a.length) {
		// Just to be sure that the compiler optimization does not destroy const time.
		assert(false);
	}

	return result == 0;
}

// test crypto_equals
unittest {
	ubyte[32] f = 0;
	immutable ubyte[32] zero = 0;
	assert(crypto_equals(f[], zero[]));
	f[8] = 1;
	assert(!crypto_equals(f[], zero[]));
}