module dcrypt.crypto.ecc.curved25519.fieldElement;

import dcrypt.bitmanip;

@safe nothrow @nogc:

/// fe means field element.
/// Here the field is \Z/(2^255-19).
/// An element t, entries t[0]...t[9], represents the integer
/// t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
/// Bounds on each t[i] vary depending on context.

@safe
struct fe {

	enum fe zero = 0;
	enum fe one = [1,0,0,0,0,0,0,0,0,0];

	private uint[10] value;
	private alias value this;

	//	this(in ref uint[10] v) {
	//		value = v;
	//	}
	nothrow @nogc:

	/// Create fe from 32 bytes.
	static fe fromBytes(in ubyte[] bytes)
	in {
		assert(bytes.length == 32, "bytes.length must be 32.");
	} body {
		return fe_frombytes(bytes);
	}

	this(in uint[] v) 
	in {
		assert(v.length == 10, "v.length must be 10.");
	} body {
		value = v;
	}

	// TODO remove
	this(in uint v) 
	{
		value[] = v;
	}

	fe opAssign(in ref uint[10] v) {
		value = v;
		return this;
	}

	/// Comparing in constant time.
	bool opEquals()(auto ref const fe rhs) const {
		return crypto_equals(this.value, rhs.value);
	}

	fe opBinary(string op)(auto ref const fe rhs) const pure
		if (op == "+" || op == "-" || op == "*")
	{
		static if(op == "+") {
			fe tmp;
			tmp.value[] = this.value[] + rhs.value[];
			return tmp;
		} else static if(op == "-") {
			fe tmp;
			tmp.value[] = this.value[] - rhs.value[];
			return tmp;
		} else static if(op == "*") {
			return fe_mul(this, rhs);
		}
	}

	fe opUnary(string op)() const
		if(op == "-")
	{
		static if(op == "-") {
			fe tmp;
			tmp.value[] = -this.value[];
			return tmp;
		}
	}

	ref fe opOpAssign(string op)(auto ref const fe rhs) pure
		if (op == "+" || op == "-" || op == "*")
	{
		static if(op == "+") {
			value[] += rhs.value[];
		} else static if(op == "-") {
			value[] -= rhs.value[];
		} else static if(op == "*") {
			this = this * rhs;
		}

		return this;
	}

	/*
	 return 1 if f == 0
	 return 0 if f != 0

	 Preconditions:
	 |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	 */
	@property
	bool isNonzero() const
	{
		immutable ubyte[32] zero = 0;
		return !crypto_equals(fe_tobytes(this), zero);
	}

	/**
	 return 1 if f is in {1,3,5,...,q-2}
	 return 0 if f is in {0,2,4,...,q-1}

	 Preconditions:
	 |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	 */ 
	@property
	bool isNegative() const
	{
		return (toBytes[0] & 1) == 1;
	}

	@property
	fe inverse() const {
		return fe_invert(this);
	}

	/// Changes the sign.
	void negate() {
		value[] = -value[];
	}

	@property
	ubyte[32] toBytes() const {
		return fe_tobytes(this);
	}

	/// Params:
	/// repeat = Repeat squaring n times.
	/// Returns: f^2 or f^(2^repeat).
	@property
	fe sq(uint repeat = 1)() const pure 
		if(repeat > 0) 
	{
		fe f = fe_sq(this);

		static if(repeat > 1) {
			foreach(i; 1..repeat) {
				f = f.sq!1;
			}
		}

		return f;
	}

	/// Returns: 2*f*f
	@property
	fe sq2() const pure {
		return fe_sq2(this);
	}

	/// Power by squaring in constant time.
	/// Returns f^power
	@property
	fe cpow(uint power)() const {
		fe r = fe.one;
		fe sq = this;
		for(uint p = power; p > 0; p >>= 1) {
			if((p & 1) == 1) {
				r *= sq;
			}
			sq = sq.sq;
		}

		return r;
	}
}

/// Compares a and b in constant time.
/// 
/// Returns: 0 if a == b, some other value if a != b.
/// 
// TODO move to dcrypt.util
bool crypto_equals(T)(in T[] a, in T[] b) pure
in {
	assert(a.length == b.length, "Unequal length.");
} body  {
	T result = 0;
	foreach(i; 0..a.length) {
		result |= a[i] ^ b[i];
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


///// h = f + g
///// Can overlap h with f or g.
/////
///// Preconditions:
/////   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
/////   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
/////
///// Postconditions:
/////  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
//void fe_add(ref fe h, in ref fe f, in ref fe g)
//{
//	//h[] = f[] + g[];
//	foreach(i; 0..10) {
//		h[i] = f[i] + g[i];
//	}
//}


/// Conditional move.
/// Replace (f,g) with (g,g) if b == 1;
/// replace (f,g) with (f,g) if b == 0.
/// 
/// Params:
/// dest = Destination.
/// src = Source.
/// condition = Condition.
void fe_cmov(ref fe dest, in ref fe src, in bool condition)
in {
	assert(condition == 0 || condition == 1);
} out {
	if(condition == 1) {
		assert(dest == src);
	}
} body {
	immutable uint mask = -(cast(int)condition);

	assert((condition == 0 && mask == 0) || (condition == 1 && mask == 0xFFFFFFFF));

	dest[] ^= mask & dest[];
	dest[] ^= mask & src[];
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

	fe_cmov(a, b, 1);

	assert(all!"a == 42"(a[]));
}

ulong load_3(in ubyte[] inp) pure
in {
	assert(inp.length == 3);
} body {
	ulong result;
	result = cast(ulong) inp[0];
	result |= (cast(ulong) inp[1]) << 8;
	result |= (cast(ulong) inp[2]) << 16;
	return result;
}

ulong load_4(in ubyte[] inp) pure
in {
	assert(inp.length == 4);
}  body {
	ulong result;
	result = cast(ulong) inp[0];
	result |= (cast(ulong) inp[1]) << 8;
	result |= (cast(ulong) inp[2]) << 16;
	result |= (cast(ulong) inp[3]) << 24;
	return result;
}

/*
 Ignores top bit of h.
 */
private fe fe_frombytes(in ubyte[] s) pure
in {
	assert(s.length == 32);
} body {
	long h0 = load_4(s[0..4]);
	long h1 = load_3(s[4..7]) << 6;
	long h2 = load_3(s[7..10]) << 5;
	long h3 = load_3(s[10..13]) << 3;
	long h4 = load_3(s[13..16]) << 2;
	long h5 = load_4(s[16..20]);
	long h6 = load_3(s[20..23]) << 7;
	long h7 = load_3(s[23..26]) << 5;
	long h8 = load_3(s[26..29]) << 4;
	long h9 = (load_3(s[29..32]) & 8388607) << 2;

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
	
	carry9 = (h9 + cast(long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= SHL64(carry9,25);
	carry1 = (h1 + cast(long) (1<<24)) >> 25; h2 += carry1; h1 -= SHL64(carry1,25);
	carry3 = (h3 + cast(long) (1<<24)) >> 25; h4 += carry3; h3 -= SHL64(carry3,25);
	carry5 = (h5 + cast(long) (1<<24)) >> 25; h6 += carry5; h5 -= SHL64(carry5,25);
	carry7 = (h7 + cast(long) (1<<24)) >> 25; h8 += carry7; h7 -= SHL64(carry7,25);
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);
	carry2 = (h2 + cast(long) (1<<25)) >> 26; h3 += carry2; h2 -= SHL64(carry2,26);
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	carry6 = (h6 + cast(long) (1<<25)) >> 26; h7 += carry6; h6 -= SHL64(carry6,26);
	carry8 = (h8 + cast(long) (1<<25)) >> 26; h9 += carry8; h8 -= SHL64(carry8,26);

	fe h;
	h[0] = cast(int) h0;
	h[1] = cast(int) h1;
	h[2] = cast(int) h2;
	h[3] = cast(int) h3;
	h[4] = cast(int) h4;
	h[5] = cast(int) h5;
	h[6] = cast(int) h6;
	h[7] = cast(int) h7;
	h[8] = cast(int) h8;
	h[9] = cast(int) h9;
	return h;
}

// TODO replace all SHL* with <<
long SHL64(in long val, in uint shift) pure nothrow @nogc {
	return cast(long)(cast(ulong) val << shift);
}

int SHL32(in int val, in uint shift) pure nothrow @nogc  {
	return cast(int)(cast(uint) val << shift);
}

int SHL8(in byte val, in uint shift) pure nothrow @nogc  {
	return cast(byte)(cast(ubyte) val << shift);
}

unittest {
	assert(0xFFFFFFFF << 7 == SHL32(0xFFFFFFFF, 7));
}

private fe fe_invert(in ref fe z)
{
	fe t0;
	fe t1;
	fe t2;
	fe t3;
	// pow225521
	t0 = z.sq; 
	t1 = t0.sq.sq; 

	t1 *= z;
	t0 *= t1;
	t2 = t0.sq;
	t1 *= t2;

	t2 = t1.sq!5;

	t1 *= t2;
	t2 = t1.sq!10; 

	t2 *= t1;

	t3 = t2.sq!20;

	t2 *= t3;
	t2 = t2.sq!10;

	t1 *= t2;

	t2 = t1.sq!50;

	t2 *= t1;
	t3 = t2.sq!100;

	t2 *= t3;
	t2 = t2.sq!50;

	t1 *= t2;

	t1 = t1.sq!5;

	return t1 * t0;
}





/**
 Returns: h = f * g
 Can overlap h with f or g.

 Preconditions:
 |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

 Postconditions:
 |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.

 Note:
 Notes on implementation strategy:

 Using schoolbook multiplication.
 Karatsuba would save a little in some cost models.

 Most multiplications by 2 and 19 are 32-bit precomputations;
 cheaper than 64-bit postcomputations.

 There is one remaining multiplication by 19 in the carry chain;
 one *19 precomputation can be merged into this,
 but the resulting data flow is considerably less clean.

 There are 12 carries below.
 10 of them are 2-way parallelizable and vectorizable.
 Can get away with 11 carries, but then data flow is much deeper.

 With tighter constraints on inputs can squeeze carries into int32.
 */
private fe fe_mul(in ref fe f, in ref fe g) pure
{
	int f0 = f[0];
	int f1 = f[1];
	int f2 = f[2];
	int f3 = f[3];
	int f4 = f[4];
	int f5 = f[5];
	int f6 = f[6];
	int f7 = f[7];
	int f8 = f[8];
	int f9 = f[9];
	int g0 = g[0];
	int g1 = g[1];
	int g2 = g[2];
	int g3 = g[3];
	int g4 = g[4];
	int g5 = g[5];
	int g6 = g[6];
	int g7 = g[7];
	int g8 = g[8];
	int g9 = g[9];
	int g1_19 = 19 * g1; /* 1.959375*2^29 */
	int g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
	int g3_19 = 19 * g3;
	int g4_19 = 19 * g4;
	int g5_19 = 19 * g5;
	int g6_19 = 19 * g6;
	int g7_19 = 19 * g7;
	int g8_19 = 19 * g8;
	int g9_19 = 19 * g9;
	int f1_2 = 2 * f1;
	int f3_2 = 2 * f3;
	int f5_2 = 2 * f5;
	int f7_2 = 2 * f7;
	int f9_2 = 2 * f9;
	long f0g0    = f0   * cast(long) g0;
	long f0g1    = f0   * cast(long) g1;
	long f0g2    = f0   * cast(long) g2;
	long f0g3    = f0   * cast(long) g3;
	long f0g4    = f0   * cast(long) g4;
	long f0g5    = f0   * cast(long) g5;
	long f0g6    = f0   * cast(long) g6;
	long f0g7    = f0   * cast(long) g7;
	long f0g8    = f0   * cast(long) g8;
	long f0g9    = f0   * cast(long) g9;
	long f1g0    = f1   * cast(long) g0;
	long f1g1_2  = f1_2 * cast(long) g1;
	long f1g2    = f1   * cast(long) g2;
	long f1g3_2  = f1_2 * cast(long) g3;
	long f1g4    = f1   * cast(long) g4;
	long f1g5_2  = f1_2 * cast(long) g5;
	long f1g6    = f1   * cast(long) g6;
	long f1g7_2  = f1_2 * cast(long) g7;
	long f1g8    = f1   * cast(long) g8;
	long f1g9_38 = f1_2 * cast(long) g9_19;
	long f2g0    = f2   * cast(long) g0;
	long f2g1    = f2   * cast(long) g1;
	long f2g2    = f2   * cast(long) g2;
	long f2g3    = f2   * cast(long) g3;
	long f2g4    = f2   * cast(long) g4;
	long f2g5    = f2   * cast(long) g5;
	long f2g6    = f2   * cast(long) g6;
	long f2g7    = f2   * cast(long) g7;
	long f2g8_19 = f2   * cast(long) g8_19;
	long f2g9_19 = f2   * cast(long) g9_19;
	long f3g0    = f3   * cast(long) g0;
	long f3g1_2  = f3_2 * cast(long) g1;
	long f3g2    = f3   * cast(long) g2;
	long f3g3_2  = f3_2 * cast(long) g3;
	long f3g4    = f3   * cast(long) g4;
	long f3g5_2  = f3_2 * cast(long) g5;
	long f3g6    = f3   * cast(long) g6;
	long f3g7_38 = f3_2 * cast(long) g7_19;
	long f3g8_19 = f3   * cast(long) g8_19;
	long f3g9_38 = f3_2 * cast(long) g9_19;
	long f4g0    = f4   * cast(long) g0;
	long f4g1    = f4   * cast(long) g1;
	long f4g2    = f4   * cast(long) g2;
	long f4g3    = f4   * cast(long) g3;
	long f4g4    = f4   * cast(long) g4;
	long f4g5    = f4   * cast(long) g5;
	long f4g6_19 = f4   * cast(long) g6_19;
	long f4g7_19 = f4   * cast(long) g7_19;
	long f4g8_19 = f4   * cast(long) g8_19;
	long f4g9_19 = f4   * cast(long) g9_19;
	long f5g0    = f5   * cast(long) g0;
	long f5g1_2  = f5_2 * cast(long) g1;
	long f5g2    = f5   * cast(long) g2;
	long f5g3_2  = f5_2 * cast(long) g3;
	long f5g4    = f5   * cast(long) g4;
	long f5g5_38 = f5_2 * cast(long) g5_19;
	long f5g6_19 = f5   * cast(long) g6_19;
	long f5g7_38 = f5_2 * cast(long) g7_19;
	long f5g8_19 = f5   * cast(long) g8_19;
	long f5g9_38 = f5_2 * cast(long) g9_19;
	long f6g0    = f6   * cast(long) g0;
	long f6g1    = f6   * cast(long) g1;
	long f6g2    = f6   * cast(long) g2;
	long f6g3    = f6   * cast(long) g3;
	long f6g4_19 = f6   * cast(long) g4_19;
	long f6g5_19 = f6   * cast(long) g5_19;
	long f6g6_19 = f6   * cast(long) g6_19;
	long f6g7_19 = f6   * cast(long) g7_19;
	long f6g8_19 = f6   * cast(long) g8_19;
	long f6g9_19 = f6   * cast(long) g9_19;
	long f7g0    = f7   * cast(long) g0;
	long f7g1_2  = f7_2 * cast(long) g1;
	long f7g2    = f7   * cast(long) g2;
	long f7g3_38 = f7_2 * cast(long) g3_19;
	long f7g4_19 = f7   * cast(long) g4_19;
	long f7g5_38 = f7_2 * cast(long) g5_19;
	long f7g6_19 = f7   * cast(long) g6_19;
	long f7g7_38 = f7_2 * cast(long) g7_19;
	long f7g8_19 = f7   * cast(long) g8_19;
	long f7g9_38 = f7_2 * cast(long) g9_19;
	long f8g0    = f8   * cast(long) g0;
	long f8g1    = f8   * cast(long) g1;
	long f8g2_19 = f8   * cast(long) g2_19;
	long f8g3_19 = f8   * cast(long) g3_19;
	long f8g4_19 = f8   * cast(long) g4_19;
	long f8g5_19 = f8   * cast(long) g5_19;
	long f8g6_19 = f8   * cast(long) g6_19;
	long f8g7_19 = f8   * cast(long) g7_19;
	long f8g8_19 = f8   * cast(long) g8_19;
	long f8g9_19 = f8   * cast(long) g9_19;
	long f9g0    = f9   * cast(long) g0;
	long f9g1_38 = f9_2 * cast(long) g1_19;
	long f9g2_19 = f9   * cast(long) g2_19;
	long f9g3_38 = f9_2 * cast(long) g3_19;
	long f9g4_19 = f9   * cast(long) g4_19;
	long f9g5_38 = f9_2 * cast(long) g5_19;
	long f9g6_19 = f9   * cast(long) g6_19;
	long f9g7_38 = f9_2 * cast(long) g7_19;
	long f9g8_19 = f9   * cast(long) g8_19;
	long f9g9_38 = f9_2 * cast(long) g9_19;
	long h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
	long h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
	long h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
	long h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
	long h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
	long h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
	long h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
	long h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
	long h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
	long h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
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
	
	/*
	 |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
	 i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
	 |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
	 i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
	 */
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	/* |h0| <= 2^25 */
	/* |h4| <= 2^25 */
	/* |h1| <= 1.71*2^59 */
	/* |h5| <= 1.71*2^59 */
	
	carry1 = (h1 + cast(long) (1<<24)) >> 25; h2 += carry1; h1 -= SHL64(carry1,25);
	carry5 = (h5 + cast(long) (1<<24)) >> 25; h6 += carry5; h5 -= SHL64(carry5,25);
	/* |h1| <= 2^24; from now on fits into int32 */
	/* |h5| <= 2^24; from now on fits into int32 */
	/* |h2| <= 1.41*2^60 */
	/* |h6| <= 1.41*2^60 */
	
	carry2 = (h2 + cast(long) (1<<25)) >> 26; h3 += carry2; h2 -= SHL64(carry2,26);
	carry6 = (h6 + cast(long) (1<<25)) >> 26; h7 += carry6; h6 -= SHL64(carry6,26);
	/* |h2| <= 2^25; from now on fits into int32 unchanged */
	/* |h6| <= 2^25; from now on fits into int32 unchanged */
	/* |h3| <= 1.71*2^59 */
	/* |h7| <= 1.71*2^59 */
	
	carry3 = (h3 + cast(long) (1<<24)) >> 25; h4 += carry3; h3 -= SHL64(carry3,25);
	carry7 = (h7 + cast(long) (1<<24)) >> 25; h8 += carry7; h7 -= SHL64(carry7,25);
	/* |h3| <= 2^24; from now on fits into int32 unchanged */
	/* |h7| <= 2^24; from now on fits into int32 unchanged */
	/* |h4| <= 1.72*2^34 */
	/* |h8| <= 1.41*2^60 */
	
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	carry8 = (h8 + cast(long) (1<<25)) >> 26; h9 += carry8; h8 -= SHL64(carry8,26);
	/* |h4| <= 2^25; from now on fits into int32 unchanged */
	/* |h8| <= 2^25; from now on fits into int32 unchanged */
	/* |h5| <= 1.01*2^24 */
	/* |h9| <= 1.71*2^59 */
	
	carry9 = (h9 + cast(long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= SHL64(carry9,25);
	/* |h9| <= 2^24; from now on fits into int32 unchanged */
	/* |h0| <= 1.1*2^39 */
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);
	/* |h0| <= 2^25; from now on fits into int32 unchanged */
	/* |h1| <= 1.01*2^24 */
	fe h;
	h[0] = cast(int) h0;
	h[1] = cast(int) h1;
	h[2] = cast(int) h2;
	h[3] = cast(int) h3;
	h[4] = cast(int) h4;
	h[5] = cast(int) h5;
	h[6] = cast(int) h6;
	h[7] = cast(int) h7;
	h[8] = cast(int) h8;
	h[9] = cast(int) h9;

	return h;
}


/// Returns f * 121666
///
/// Preconditions:
/// |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
///
/// Postconditions:
/// |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
public fe fe_mul121666(in ref fe f) pure
{
	int f0 = f[0];
	int f1 = f[1];
	int f2 = f[2];
	int f3 = f[3];
	int f4 = f[4];
	int f5 = f[5];
	int f6 = f[6];
	int f7 = f[7];
	int f8 = f[8];
	int f9 = f[9];
	long h0 = f0 * cast(long) 121666;
	long h1 = f1 * cast(long) 121666;
	long h2 = f2 * cast(long) 121666;
	long h3 = f3 * cast(long) 121666;
	long h4 = f4 * cast(long) 121666;
	long h5 = f5 * cast(long) 121666;
	long h6 = f6 * cast(long) 121666;
	long h7 = f7 * cast(long) 121666;
	long h8 = f8 * cast(long) 121666;
	long h9 = f9 * cast(long) 121666;
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
	
	carry9 = (h9 + cast(long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
	carry1 = (h1 + cast(long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry3 = (h3 + cast(long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry5 = (h5 + cast(long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry7 = (h7 + cast(long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry2 = (h2 + cast(long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry6 = (h6 + cast(long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry8 = (h8 + cast(long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
	
	fe h;
	h[0] = cast(uint) h0;
	h[1] = cast(uint) h1;
	h[2] = cast(uint) h2;
	h[3] = cast(uint) h3;
	h[4] = cast(uint) h4;
	h[5] = cast(uint) h5;
	h[6] = cast(uint) h6;
	h[7] = cast(uint) h7;
	h[8] = cast(uint) h8;
	h[9] = cast(uint) h9;

	return h;
}

/// Returns: z^(2^(225-23))
package fe fe_pow22523(in ref fe z) pure
{
	fe t0;
	fe t1;
	fe t2;
	t0 = z.sq;
	t1 = t0.sq.sq;

	t1 *= z;
	t0 *= t1;
	t0 = t0.sq;
	t0 *= t1;

	//		t1 = z.cpow!9;
	//		t0 = z.cpow!31;

	t1 = t0.sq!5;

	t0 *= t1;

	t1 = t0.sq!10;

	t1 *= t0;

	t2 = t1.sq!20;

	t1 *= t2;

	t1 = t1.sq!10;

	t0 *= t1;

	t1 = t0.sq!50;

	t1 *= t0;

	t2 = t1.sq!100;

	t1 *= t2;

	t1 = t1.sq!50;

	t0 *= t1;
	t0 = t0.sq.sq;

	return t0 * z;
}


/**
 Returns: h = f * f
 Can overlap h with f.

 Preconditions:
 |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

 Postconditions:
 |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.

 Note:
 See fe_mul.c for discussion of implementation strategy.
 */
private fe fe_sq(in ref fe f) pure
{
	int f0 = f[0];
	int f1 = f[1];
	int f2 = f[2];
	int f3 = f[3];
	int f4 = f[4];
	int f5 = f[5];
	int f6 = f[6];
	int f7 = f[7];
	int f8 = f[8];
	int f9 = f[9];
	int f0_2 = 2 * f0;
	int f1_2 = 2 * f1;
	int f2_2 = 2 * f2;
	int f3_2 = 2 * f3;
	int f4_2 = 2 * f4;
	int f5_2 = 2 * f5;
	int f6_2 = 2 * f6;
	int f7_2 = 2 * f7;
	int f5_38 = 38 * f5; /* 1.959375*2^30 */
	int f6_19 = 19 * f6; /* 1.959375*2^30 */
	int f7_38 = 38 * f7; /* 1.959375*2^30 */
	int f8_19 = 19 * f8; /* 1.959375*2^30 */
	int f9_38 = 38 * f9; /* 1.959375*2^30 */
	long f0f0    = f0   * cast(long) f0;
	long f0f1_2  = f0_2 * cast(long) f1;
	long f0f2_2  = f0_2 * cast(long) f2;
	long f0f3_2  = f0_2 * cast(long) f3;
	long f0f4_2  = f0_2 * cast(long) f4;
	long f0f5_2  = f0_2 * cast(long) f5;
	long f0f6_2  = f0_2 * cast(long) f6;
	long f0f7_2  = f0_2 * cast(long) f7;
	long f0f8_2  = f0_2 * cast(long) f8;
	long f0f9_2  = f0_2 * cast(long) f9;
	long f1f1_2  = f1_2 * cast(long) f1;
	long f1f2_2  = f1_2 * cast(long) f2;
	long f1f3_4  = f1_2 * cast(long) f3_2;
	long f1f4_2  = f1_2 * cast(long) f4;
	long f1f5_4  = f1_2 * cast(long) f5_2;
	long f1f6_2  = f1_2 * cast(long) f6;
	long f1f7_4  = f1_2 * cast(long) f7_2;
	long f1f8_2  = f1_2 * cast(long) f8;
	long f1f9_76 = f1_2 * cast(long) f9_38;
	long f2f2    = f2   * cast(long) f2;
	long f2f3_2  = f2_2 * cast(long) f3;
	long f2f4_2  = f2_2 * cast(long) f4;
	long f2f5_2  = f2_2 * cast(long) f5;
	long f2f6_2  = f2_2 * cast(long) f6;
	long f2f7_2  = f2_2 * cast(long) f7;
	long f2f8_38 = f2_2 * cast(long) f8_19;
	long f2f9_38 = f2   * cast(long) f9_38;
	long f3f3_2  = f3_2 * cast(long) f3;
	long f3f4_2  = f3_2 * cast(long) f4;
	long f3f5_4  = f3_2 * cast(long) f5_2;
	long f3f6_2  = f3_2 * cast(long) f6;
	long f3f7_76 = f3_2 * cast(long) f7_38;
	long f3f8_38 = f3_2 * cast(long) f8_19;
	long f3f9_76 = f3_2 * cast(long) f9_38;
	long f4f4    = f4   * cast(long) f4;
	long f4f5_2  = f4_2 * cast(long) f5;
	long f4f6_38 = f4_2 * cast(long) f6_19;
	long f4f7_38 = f4   * cast(long) f7_38;
	long f4f8_38 = f4_2 * cast(long) f8_19;
	long f4f9_38 = f4   * cast(long) f9_38;
	long f5f5_38 = f5   * cast(long) f5_38;
	long f5f6_38 = f5_2 * cast(long) f6_19;
	long f5f7_76 = f5_2 * cast(long) f7_38;
	long f5f8_38 = f5_2 * cast(long) f8_19;
	long f5f9_76 = f5_2 * cast(long) f9_38;
	long f6f6_19 = f6   * cast(long) f6_19;
	long f6f7_38 = f6   * cast(long) f7_38;
	long f6f8_38 = f6_2 * cast(long) f8_19;
	long f6f9_38 = f6   * cast(long) f9_38;
	long f7f7_38 = f7   * cast(long) f7_38;
	long f7f8_38 = f7_2 * cast(long) f8_19;
	long f7f9_76 = f7_2 * cast(long) f9_38;
	long f8f8_19 = f8   * cast(long) f8_19;
	long f8f9_38 = f8   * cast(long) f9_38;
	long f9f9_38 = f9   * cast(long) f9_38;
	long h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
	long h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
	long h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
	long h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
	long h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
	long h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
	long h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
	long h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
	long h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
	long h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
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
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	
	carry1 = (h1 + cast(long) (1<<24)) >> 25; h2 += carry1; h1 -= SHL64(carry1,25);
	carry5 = (h5 + cast(long) (1<<24)) >> 25; h6 += carry5; h5 -= SHL64(carry5,25);
	
	carry2 = (h2 + cast(long) (1<<25)) >> 26; h3 += carry2; h2 -= SHL64(carry2,26);
	carry6 = (h6 + cast(long) (1<<25)) >> 26; h7 += carry6; h6 -= SHL64(carry6,26);
	
	carry3 = (h3 + cast(long) (1<<24)) >> 25; h4 += carry3; h3 -= SHL64(carry3,25);
	carry7 = (h7 + cast(long) (1<<24)) >> 25; h8 += carry7; h7 -= SHL64(carry7,25);
	
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	carry8 = (h8 + cast(long) (1<<25)) >> 26; h9 += carry8; h8 -= SHL64(carry8,26);
	
	carry9 = (h9 + cast(long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= SHL64(carry9,25);
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);

	fe h;
	h[0] = cast(int) h0;
	h[1] = cast(int) h1;
	h[2] = cast(int) h2;
	h[3] = cast(int) h3;
	h[4] = cast(int) h4;
	h[5] = cast(int) h5;
	h[6] = cast(int) h6;
	h[7] = cast(int) h7;
	h[8] = cast(int) h8;
	h[9] = cast(int) h9;
	return h;
}

/**
 Returns: h = 2 * f * f
 Can overlap h with f.

 Preconditions:
 |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

 Postconditions:
 |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.

 Note:
 See fe_mul.c for discussion of implementation strategy.
 */
private fe fe_sq2(in ref fe f) pure
{
	int f0 = f[0];
	int f1 = f[1];
	int f2 = f[2];
	int f3 = f[3];
	int f4 = f[4];
	int f5 = f[5];
	int f6 = f[6];
	int f7 = f[7];
	int f8 = f[8];
	int f9 = f[9];
	int f0_2 = 2 * f0;
	int f1_2 = 2 * f1;
	int f2_2 = 2 * f2;
	int f3_2 = 2 * f3;
	int f4_2 = 2 * f4;
	int f5_2 = 2 * f5;
	int f6_2 = 2 * f6;
	int f7_2 = 2 * f7;
	int f5_38 = 38 * f5; /* 1.959375*2^30 */
	int f6_19 = 19 * f6; /* 1.959375*2^30 */
	int f7_38 = 38 * f7; /* 1.959375*2^30 */
	int f8_19 = 19 * f8; /* 1.959375*2^30 */
	int f9_38 = 38 * f9; /* 1.959375*2^30 */
	long f0f0    = f0   * cast(long) f0;
	long f0f1_2  = f0_2 * cast(long) f1;
	long f0f2_2  = f0_2 * cast(long) f2;
	long f0f3_2  = f0_2 * cast(long) f3;
	long f0f4_2  = f0_2 * cast(long) f4;
	long f0f5_2  = f0_2 * cast(long) f5;
	long f0f6_2  = f0_2 * cast(long) f6;
	long f0f7_2  = f0_2 * cast(long) f7;
	long f0f8_2  = f0_2 * cast(long) f8;
	long f0f9_2  = f0_2 * cast(long) f9;
	long f1f1_2  = f1_2 * cast(long) f1;
	long f1f2_2  = f1_2 * cast(long) f2;
	long f1f3_4  = f1_2 * cast(long) f3_2;
	long f1f4_2  = f1_2 * cast(long) f4;
	long f1f5_4  = f1_2 * cast(long) f5_2;
	long f1f6_2  = f1_2 * cast(long) f6;
	long f1f7_4  = f1_2 * cast(long) f7_2;
	long f1f8_2  = f1_2 * cast(long) f8;
	long f1f9_76 = f1_2 * cast(long) f9_38;
	long f2f2    = f2   * cast(long) f2;
	long f2f3_2  = f2_2 * cast(long) f3;
	long f2f4_2  = f2_2 * cast(long) f4;
	long f2f5_2  = f2_2 * cast(long) f5;
	long f2f6_2  = f2_2 * cast(long) f6;
	long f2f7_2  = f2_2 * cast(long) f7;
	long f2f8_38 = f2_2 * cast(long) f8_19;
	long f2f9_38 = f2   * cast(long) f9_38;
	long f3f3_2  = f3_2 * cast(long) f3;
	long f3f4_2  = f3_2 * cast(long) f4;
	long f3f5_4  = f3_2 * cast(long) f5_2;
	long f3f6_2  = f3_2 * cast(long) f6;
	long f3f7_76 = f3_2 * cast(long) f7_38;
	long f3f8_38 = f3_2 * cast(long) f8_19;
	long f3f9_76 = f3_2 * cast(long) f9_38;
	long f4f4    = f4   * cast(long) f4;
	long f4f5_2  = f4_2 * cast(long) f5;
	long f4f6_38 = f4_2 * cast(long) f6_19;
	long f4f7_38 = f4   * cast(long) f7_38;
	long f4f8_38 = f4_2 * cast(long) f8_19;
	long f4f9_38 = f4   * cast(long) f9_38;
	long f5f5_38 = f5   * cast(long) f5_38;
	long f5f6_38 = f5_2 * cast(long) f6_19;
	long f5f7_76 = f5_2 * cast(long) f7_38;
	long f5f8_38 = f5_2 * cast(long) f8_19;
	long f5f9_76 = f5_2 * cast(long) f9_38;
	long f6f6_19 = f6   * cast(long) f6_19;
	long f6f7_38 = f6   * cast(long) f7_38;
	long f6f8_38 = f6_2 * cast(long) f8_19;
	long f6f9_38 = f6   * cast(long) f9_38;
	long f7f7_38 = f7   * cast(long) f7_38;
	long f7f8_38 = f7_2 * cast(long) f8_19;
	long f7f9_76 = f7_2 * cast(long) f9_38;
	long f8f8_19 = f8   * cast(long) f8_19;
	long f8f9_38 = f8   * cast(long) f9_38;
	long f9f9_38 = f9   * cast(long) f9_38;
	long h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
	long h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
	long h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
	long h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
	long h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
	long h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
	long h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
	long h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
	long h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
	long h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
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
	
	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	
	carry1 = (h1 + cast(long) (1<<24)) >> 25; h2 += carry1; h1 -= SHL64(carry1,25);
	carry5 = (h5 + cast(long) (1<<24)) >> 25; h6 += carry5; h5 -= SHL64(carry5,25);
	
	carry2 = (h2 + cast(long) (1<<25)) >> 26; h3 += carry2; h2 -= SHL64(carry2,26);
	carry6 = (h6 + cast(long) (1<<25)) >> 26; h7 += carry6; h6 -= SHL64(carry6,26);
	
	carry3 = (h3 + cast(long) (1<<24)) >> 25; h4 += carry3; h3 -= SHL64(carry3,25);
	carry7 = (h7 + cast(long) (1<<24)) >> 25; h8 += carry7; h7 -= SHL64(carry7,25);
	
	carry4 = (h4 + cast(long) (1<<25)) >> 26; h5 += carry4; h4 -= SHL64(carry4,26);
	carry8 = (h8 + cast(long) (1<<25)) >> 26; h9 += carry8; h8 -= SHL64(carry8,26);
	
	carry9 = (h9 + cast(long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= SHL64(carry9,25);
	
	carry0 = (h0 + cast(long) (1<<25)) >> 26; h1 += carry0; h0 -= SHL64(carry0,26);

	fe h;
	h[0] = cast(int) h0;
	h[1] = cast(int) h1;
	h[2] = cast(int) h2;
	h[3] = cast(int) h3;
	h[4] = cast(int) h4;
	h[5] = cast(int) h5;
	h[6] = cast(int) h6;
	h[7] = cast(int) h7;
	h[8] = cast(int) h8;
	h[9] = cast(int) h9;
	return h;
}

///**
// Returns: h = f - g
// Can overlap h with f or g.
//
// Preconditions:
// |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
// |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
//
// Postconditions:
// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
// */
//void fe_sub(ref fe h, in ref fe f, in ref fe g)
//{
//	h[] = f[] - g[];
//}


/**
 * 
 * Params:
 * s = 32 byte buffer
 * 
 Preconditions:
 |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

 Write p=2^255-19; q=floor(h/p).
 Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

 Proof:
 Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
 Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

 Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
 Then 0<y<1.

 Write r=h-pq.
 Have 0<=r<=p-1=2^255-20.
 Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

 Write x=r+19(2^-255)r+y.
 Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

 Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
 so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
 */
private ubyte[32] fe_tobytes(in ref fe h) pure
{
	int h0 = h[0];
	int h1 = h[1];
	int h2 = h[2];
	int h3 = h[3];
	int h4 = h[4];
	int h5 = h[5];
	int h6 = h[6];
	int h7 = h[7];
	int h8 = h[8];
	int h9 = h[9];
	int q;
	int carry0;
	int carry1;
	int carry2;
	int carry3;
	int carry4;
	int carry5;
	int carry6;
	int carry7;
	int carry8;
	int carry9;

	q = (19 * h9 + ((cast(int) 1) << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;

	/* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
	h0 += 19 * q;
	/* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
	
	carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
	carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
	carry9 = h9 >> 25;               h9 -= carry9 << 25;
	/* h10 = carry9 */
	
	/*
	 Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
	 Have h0+...+2^230 h9 between 0 and 2^255-1;
	 evidently 2^255 h10-2^255 q = 0.
	 Goal: Output h0+...+2^230 h9.
	 */

	ubyte[32] s;
	s[0] = cast(ubyte) (h0 >> 0);
	s[1] = cast(ubyte) (h0 >> 8);
	s[2] = cast(ubyte) (h0 >> 16);
	s[3] = cast(ubyte) (((h0 >> 24) | (h1 << 2)));
	s[4] = cast(ubyte) (h1 >> 6);
	s[5] = cast(ubyte) (h1 >> 14);
	s[6] = cast(ubyte) (((h1 >> 22) | (h2 << 3)));
	s[7] = cast(ubyte) (h2 >> 5);
	s[8] = cast(ubyte) (h2 >> 13);
	s[9] = cast(ubyte) (((h2 >> 21) | (h3 << 5)));
	s[10] = cast(ubyte) (h3 >> 3);
	s[11] = cast(ubyte) (h3 >> 11);
	s[12] = cast(ubyte) (((h3 >> 19) | (h4 << 6)));
	s[13] = cast(ubyte) (h4 >> 2);
	s[14] = cast(ubyte) (h4 >> 10);
	s[15] = cast(ubyte) (h4 >> 18);
	s[16] = cast(ubyte) (h5 >> 0);
	s[17] = cast(ubyte) (h5 >> 8);
	s[18] = cast(ubyte) (h5 >> 16);
	s[19] = cast(ubyte) (((h5 >> 24) | (h6 << 1)));
	s[20] = cast(ubyte) (h6 >> 7);
	s[21] = cast(ubyte) (h6 >> 15);
	s[22] = cast(ubyte) (((h6 >> 23) | (h7 << 3)));
	s[23] = cast(ubyte) (h7 >> 5);
	s[24] = cast(ubyte) (h7 >> 13);
	s[25] = cast(ubyte) (((h7 >> 21) | (h8 << 4)));
	s[26] = cast(ubyte) (h8 >> 4);
	s[27] = cast(ubyte) (h8 >> 12);
	s[28] = cast(ubyte) (((h8 >> 20) | (h9 << 6)));
	s[29] = cast(ubyte) (h9 >> 2);
	s[30] = cast(ubyte) (h9 >> 10);
	s[31] = cast(ubyte) (h9 >> 18);

	return s;
}

/// Conditional swap.
/// Replace (f,g) with (g,f) if b == 1;
/// replace (f,g) with (f,g) if b == 0.
/// Params:
/// b = 0 or 1
void fe_cswap(ref fe f, ref fe g, in uint b)
in {
	assert(b == 0 || b == 1);
} body
{
	// TODO refactor
	immutable uint mask = -b;

	assert(mask == 0 || mask == 0xFFFFFFFF);

	f[] ^= mask & g[];
	g[] ^= mask & f[];
	f[] ^= mask & g[];
}

unittest {
	fe a;
	fe b;
	a[] = 1;
	b[] = 2;
	fe A = 1;
	fe B = 2;

	fe_cswap(A, B, 0);
	assert(A == a);
	assert(B == b);
	fe_cswap(A, B, 1);
	assert(A == b);
	assert(B == a);
}