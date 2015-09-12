module dcrypt.util.pack;
import std.traits;

/// 
/// This module contains several methods to convert integer types into byte arrays
/// and vice versa.
/// 

// TODO Replace with std.bitmanip?

public pure nothrow @safe:

/**
 Converts big endian bytes to integral of type T
 Params:	bs = the big endian bytes
 Returns: integral of type T
 */
@safe @nogc
T fromBigEndian(T)(in ubyte[] bs) if (isIntegral!T)
in {
	assert(bs.length >= T.sizeof, "input buffer too short");
}
body {
	version(BigEndian) {
		// data is already in memory as we want
		return (cast(const T[])bs)[0];
	}else {
		Unqual!T n = 0;
		static if (T.sizeof >= short.sizeof) {
			n |= bs[0];
			n <<= 8;
			n |= bs[1];
		}
		static if (T.sizeof >= int.sizeof) {
			n <<= 8;
			n |= bs[2];
			n <<= 8;
			n |= bs[3];
		}
		static if (T.sizeof == long.sizeof) {
			n <<= 8;
			n |= bs[4];
			n <<= 8;
			n |= bs[5];
			n <<= 8;
			n |= bs[6];
			n <<= 8;
			n |= bs[7];
		}
		
		return n;
	}
}

/**
 Converts little endian bytes to integral of type T
 Params:	bs = the little endian bytes
 Returns: integral of type T
 */
@safe @nogc
T fromLittleEndian(T)(in ubyte[] bs) if (isIntegral!T)
in {
	assert(bs.length >= T.sizeof, "input buffer too short");
}
body {
	version(LittleEndian) {
		// data is already in memory as we want
		return (cast(const T[])bs)[0];
	}else {
		Unqual!T n = 0;
		static if (T.sizeof >= short.sizeof) {
			n |= bs[0];
			n |= cast(T)bs[1] << 8;
		}
		static if (T.sizeof >= int.sizeof) {
			n |= cast(T)bs[2] << 16;
			n |= cast(T)bs[3] << 24;
		}
		static if (T.sizeof == long.sizeof) {
			n |= cast(T)bs[4] << 32;
			n |= cast(T)bs[5] << 40;
			n |= cast(T)bs[6] << 48;
			n |= cast(T)bs[7] << 56;
		}
		
		return n;
	}
}

/**
 Converts big endian bytes to integrals of type T
 size of bs has to match the size in bytes of output
 Params:
 bs = the big endian bytes
 output = where the T's get written to
 */
@safe @nogc
void fromBigEndian(T)(in ubyte[] bs, T[] output) if (isIntegral!T) 
in {
	assert(bs.length == output.length * T.sizeof, "size of input array does not match size of output array");
}
body {
	version(BigEndian) {
		// short cut on big endian systems
		const T[] casted = cast(const T[]) bs;
		output[] = casted[];
	} else {
		// for little endian systems
		foreach (i; 0 .. output.length)
		{
			output[i] = fromBigEndian!T(bs[4*i .. 4*i+4]);
		}
	}
}

/**
 Converts little endian bytes to integrals of type T
 size of bs has to match the size in bytes of output
 Params:
 bs = the little endian bytes
 output = where the T's get written to
 */
@safe @nogc
void fromLittleEndian(T)(in ubyte[] bs, T[] output) if (isIntegral!T) 
in {
	assert(bs.length == output.length * T.sizeof, "size of input array does not match size of output array");
}
body {
	version(LittleEndian) {
		// short cut on little endian systems
		const T[] casted = cast(const T[]) bs;
		output[] = casted[];
	} else {
		// for big endian systems
		foreach (i; 0 .. output.length)
		{
			output[i] = fromLittleEndian!T(bs[4*i .. 4*i+4]);
		}
	}
}

/**
 convert a integral type T into an array of bytes.
 Params:
 n = the number
 output = the buffer to write the bytes to
 */
@safe @nogc
void toBigEndian(T)(in T val, ubyte[] output) if(isIntegral!T) 
in {
	assert(output.length >= T.sizeof, "output buffer too small");
}
body {
	Unqual!T n = val;
	uint off = 0;
	
	static if(T.sizeof == long.sizeof) {
		output[off] = cast (ubyte) (n >>> 56);
		++off;
		output[off] = cast (ubyte) (n >>> 48);
		++off;
		output[off] = cast (ubyte) (n >>> 40);
		++off;
		output[off] = cast (ubyte) (n >>> 32);
		++off;
	}
	static if(T.sizeof >= int.sizeof) {
		output[off] = cast (ubyte) (n >>> 24);
		++off;
		output[off] = cast (ubyte) (n >>> 16);
		++off;
	}
	static if(T.sizeof >= short.sizeof) {
		output[off] = cast (ubyte) (n >>> 8);
		++off;
	}
	output[off] = cast (ubyte) (n);
}

/**
 convert a integral type T into an array of bytes.
 Params:
 n = the number
 output = the buffer to write the bytes to
 */
@safe @nogc
void toLittleEndian(T)(in T val, ubyte[] output) if(isIntegral!T) 
in {
	assert(output.length >= T.sizeof, "output buffer too small");
}
body {
	Unqual!T n = val;
	output[0] = cast (ubyte) (n);
	n >>>= 8;
	static if(T.sizeof >= short.sizeof) {
		output[1] = cast (ubyte) (n);
		n >>>= 8;
	}
	static if(T.sizeof >= int.sizeof) {
		output[2] = cast (ubyte) (n);
		n >>>= 8;
		output[3] = cast (ubyte) (n);
		n >>>= 8;
	}
	static if(T.sizeof == long.sizeof) {
		output[4] = cast (ubyte) (n);
		n >>>= 8;
		output[5] = cast (ubyte) (n);
		n >>>= 8;
		output[6] = cast (ubyte) (n);
		n >>>= 8;
		output[7] = cast (ubyte) (n);
	}
}

/**
 convert a integral type T[] into an array of bytes.
 Params:
 ns = the numbers
 output = the buffer to write the bytes to
 */
@safe @nogc
void toBigEndian(T)(in T[] ns, ubyte[] output) if(isIntegral!T) 
in {
	assert(output.length >= T.sizeof*ns.length, "output buffer too small");
}
body {
	version(BigEndian) {
		// shortcut on BigEndian systems
		const ubyte[] casted = cast(const ubyte []) ns;
		output[] = casted[];
	}else{
		foreach(i, const T n; ns) {
			toBigEndian!T(n, output[T.sizeof * i .. $]);
		}
	}
}

/**
 convert a integral type T[] into an array of bytes.
 Params:
 ns	the numbers
 output	the buffer to write the bytes to
 */
@safe @nogc
void toLittleEndian(T)(in T[] ns, ubyte[] output) if(isIntegral!T) 
in {
	assert(output.length >= T.sizeof*ns.length, "output buffer too small");
}
body {
	version(LittleEndian) {
		// shortcut on LittleEndian systems
		const ubyte[] casted = cast(const ubyte []) ns;
		output[] = casted[];
	}else{
		foreach(i, const T n; ns) {
			toLittleEndian!T(n, output[T.sizeof * i .. $]);
		}
	}
}

ubyte[T.sizeof] toBigEndian(T)(in T n) pure nothrow @nogc
	if(isIntegral!T)
{
	ubyte[T.sizeof] bs;
	toBigEndian!T(n, bs);
	return bs;
}

ubyte[] toBigEndian(T)(in T[] ns) if(isIntegral!T)
{
	ubyte[] bs = new ubyte[T.sizeof * ns.length];
	toBigEndian!T(ns, bs);
	return bs;
}


ubyte[T.sizeof] toLittleEndian(T)(in T n) pure nothrow @nogc
	if(isIntegral!T)
{
	ubyte[T.sizeof] bs;
	toLittleEndian!T(n, bs);
	return bs;
}


ubyte[] toLittleEndian(T)(in T[] ns) if(isIntegral!T)
{
	ubyte[] bs = new ubyte[T.sizeof * ns.length];
	toLittleEndian!T(ns, bs);
	return bs;
}

unittest {
	
	// int
	assert(toBigEndian(0x01020304) == [0x01,0x02,0x03,0x04], "intToBigEndian failed");
	assert(toLittleEndian(0x01020304) == [0x04,0x03,0x02,0x01], "intToLittleEndian failed");
	
	
	// long
	assert(toBigEndian(0x0102030405060708L) == [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08], "longToBigEndian failed");
	assert(toLittleEndian(0x0807060504030201L) == [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08], "longToLittleEndian failed");
	
	// bigEndian to short, int, long
	assert(fromBigEndian!ushort([0x01,0x02]) == 0x0102u);
	assert(fromBigEndian!uint([0x01,0x02,0x03,0x04]) == 0x01020304u);
	assert(fromBigEndian!ulong([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]) == 0x0102030405060708UL);
	
	// littleEndian to short, int, long
	assert(fromLittleEndian!ushort([0x02,0x01]) == 0x0102u);
	assert(fromLittleEndian!uint([0x04,0x03,0x02,0x01]) == 0x01020304u);
	assert(fromLittleEndian!ulong([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]) == 0x0807060504030201UL);
	
	// bigEndian: convert multiple ints
	uint[] output = new uint[2];
	immutable ubyte[] input = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
	fromBigEndian(input, output);
	assert(output == [0x01020304u, 0x05060708u], "fromBigEndian(ubyte[] input, int[] output) failed");
	
	// littleEndian: convert multiple ints
	output = new uint[2];
	fromLittleEndian(input, output);
	assert(output == [0x04030201u, 0x08070605u], "fromLittleEndian(ubyte[] input, int[] output) failed");
	
	
	immutable int i = 0xf1f2f3f4;
	int iResult;
	ubyte[] buf;
	
	// int to bigEndian
	buf = new ubyte[4];
	toBigEndian!int(i, buf);
	iResult = fromBigEndian!int(buf);
	assert(i == iResult);
	
	// int to littleEndian
	buf = new ubyte[4];
	toLittleEndian!int(i, buf);
	iResult = fromLittleEndian!int(buf);
	assert(i == iResult);
	
	
	
	immutable long l = 0xf1f2f3f4f5f6f7f8;
	long lResult;
	
	// long to bigEndian
	buf = new ubyte[8];
	toBigEndian!long(l, buf);
	lResult = fromBigEndian!long(buf);
	assert(l == lResult);
	
	// int to littleEndian
	buf = new ubyte[8];
	toLittleEndian!long(l, buf);
	lResult = fromLittleEndian!long(buf);
	assert(l == lResult);
}
