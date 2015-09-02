module dcrypt.crypto.ecc.ed25519.groupElement;

public import dcrypt.crypto.ecc.ed25519.fieldElement;
import dcrypt.crypto.ecc.ed25519.base;

@safe nothrow @nogc:

/**
 ge means group element.

 Here the group is the set of pairs (x,y) of field elements (see fe.h)
 satisfying -x^2 + y^2 = 1 + d x^2y^2
 where d = -121665/121666.

 Representations:
 ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 ge_precomp (Duif): (y+x,y-x,2dxy)
 */

// #include "fe.h"

/// ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
struct ge_p2 {
	@safe nothrow @nogc:
	enum ge_p2 zero = ge_p2(fe.zero, fe.one, fe.one);
	
	fe X = fe.zero;
	fe Y = fe.zero;
	fe Z = fe.one;

	this(fe x, fe y, fe z) {
		X = x;
		Y = y;
		Z = z;
	}

	@property
	ubyte[32] toBytes() const {
		ubyte[32] s;
		fe recip = Z.inverse;
		fe x = X * recip;
		fe y = Y * recip;
		
		s[0..32] = y.toBytes;
		s[31] ^= x.isNegative << 7;
		return s;
	}

}

/// ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
struct ge_p3 {
	@safe nothrow @nogc:
	enum ge_p3 zero = ge_p3(fe.zero, fe.one, fe.one, fe.zero);

	fe X = fe.zero;
	fe Y = fe.one;
	fe Z = fe.one;
	fe T = fe.zero;

	this(fe x, fe y, fe z, fe t) {
		X = x;
		Y = y;
		Z = z;
		T = t;
	}

	ge_p2 opCast(G: ge_p2)() const {
		return ge_p2(X, Y, Z);
	}

	ge_cached opCast(G: ge_cached)() const {
		return ge_cached(X+Y, Y-X, Z, T*d2);
	}

	@property
	ubyte[32] toBytes() const {
		ubyte[32] s;
		fe recip = Z.inverse;
		fe x = X * recip;
		fe y = Y * recip;
		
		s[0..32] = y.toBytes;
		s[31] ^= x.isNegative << 7;
		return s;
	}
}

/// ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
struct ge_p1p1 {
	@safe nothrow @nogc:
	fe X;
	fe Y;
	fe Z;
	fe T;

	this(fe x, fe y, fe z, fe t) {
		X = x;
		Y = y;
		Z = z;
		T = t;
	}

	ge_p2 opCast(G: ge_p2)() const {
		return ge_p2(X*T, Y*Z, Z*T);
	}

	ge_p3 opCast(G: ge_p3)() const {
		return ge_p3(X*T, Y*Z, Z*T, X*Y);
	}
}

/// ge_precomp (Duif): (y+x,y-x,2dxy)
struct ge_precomp {
	@safe nothrow @nogc:
	enum ge_precomp zero = ge_precomp(fe.one, fe.one, fe.zero);

	fe yplusx = fe.one;
	fe yminusx = fe.one;
	fe xy2d = fe.zero;

	this(fe yplusx, fe yminusx, fe xy2d) {
		this.yplusx = yplusx;
		this.yminusx = yminusx;
		this.xy2d = xy2d;
	}

	this(in uint[] yplusx, in uint[] yminusx, in uint[] xy2d)
	in {
		assert(yplusx.length == 10);
		assert(yminusx.length == 10);
		assert(xy2d.length == 10);
	} body {
		this.yplusx = yplusx;
		this.yminusx = yminusx;
		this.xy2d = xy2d;
	}
}

struct ge_cached {
	@safe nothrow @nogc:
	fe YplusX;
	fe YminusX;
	fe Z;
	fe T2d;

	this(fe yplusx, fe yminusx, fe z, fe t2d) {
		YplusX = yplusx;
		YminusX = yminusx;
		Z = z;
		T2d = t2d;
	}
};


/**
 r = p + q
 */
void ge_add(ref ge_p1p1 r, in ref ge_p3 p, in ref ge_cached q)
{
	fe t0;
	r.X = p.Y + p.X;
	r.Y = p.Y - p.X;
	r.Z = r.X * q.YplusX;
	r.Y *= q.YminusX;
	r.T = q.T2d * p.T;
	r.X = p.Z * q.Z;
	t0 = r.X + r.X;
	r.X = r.Z - r.Y;
	r.Y += r.Z;
	r.Z = t0 + r.T;
	r.T = t0 - r.T;
}


/**
 r = p + q
 */
void ge_madd(ref ge_p1p1 r, in ref ge_p3 p, in ref ge_precomp q)
{
	fe t0;
	r.X = p.Y + p.X;
	r.Y = p.Y - p.X;
	r.Z = r.X * q.yplusx;
	r.Y *= q.yminusx;
	r.T = q.xy2d * p.T;
	t0 = p.Z + p.Z;
	r.X = r.Z - r.Y;
	r.Y += r.Z;
	r.Z = t0 + r.T;
	r.T = t0 - r.T;
}


/**
 r = p - q
 */
void ge_msub(ref ge_p1p1 r, in ref ge_p3 p, in ref ge_precomp q)
{
	fe t0;
	r.X = p.Y + p.X;
	r.Y = p.Y - p.X;
	r.Z = r.X * q.yminusx;
	r.Y *= q.yplusx;
	r.T = q.xy2d * p.T;
	t0 = p.Z + p.Z;
	r.X = r.Z - r.Y;
	r.Y += r.Z;
	r.Z = t0 - r.T;
	r.T += t0;
}

// TODO pre conditions
void slide(byte[] r, in ubyte[] a)
{	
	for (uint i = 0; i < 256; ++i) {
		r[i] = 1 & (a[i >> 3] >> (i & 7));
	}
	
	for (uint i = 0; i < 256; ++i) {
		if (r[i]) {
			for (uint b = 1; b <= 6 && i + b < 256; ++b) {
				if (r[i + b]) {
					if (r[i] + (r[i + b] << b) <= 15) {
						r[i] += r[i + b] << b; r[i + b] = 0;
					} else if (r[i] - (r[i + b] << b) >= -15) {
						r[i] -= r[i + b] << b;
						for (uint k = i + b; k < 256; ++k) {
							if (!r[k]) {
								r[k] = 1;
								break;
							}
							r[k] = 0;
						}
					} else
						break;
				}
			}
		}
	}
	
}


/// calculates a * A + b * B
/// B is the Ed25519 base point (x,4/5) with x positive.
/// Params:
/// a = a[0]+256*a[1]+...+256^31 a[31].
/// b = b[0]+256*b[1]+...+256^31 b[31].
/// Returns: r = a * A + b * B

void ge_double_scalarmult_vartime(ref ge_p2 r, in ubyte[] a, in ref ge_p3 A, in ubyte[] b)
{
	byte[256] aslide, bslide;

	ge_cached[8] Ai; /* A,3A,5A,7A,9A,11A,13A,15A */
	ge_p1p1 t;
	ge_p3 u;
	ge_p3 A2;
	
	slide(aslide,a);
	slide(bslide, b);
	
	Ai[0] = cast(ge_cached) A;
	ge_p3_dbl(t, A); A2 = cast(ge_p3) t;
	foreach(i; 0..7) {
		ge_add(t, A2, Ai[i]); u = cast(ge_p3) t; Ai[i+1] = cast(ge_cached) u;
	}
	
	r = ge_p2.zero;
	
	int i;
	for (i = 255; i >= 0; --i) {
		if (aslide[i] || bslide[i]) break;
	}
	
	for (; i >= 0; --i) {
		ge_p2_dbl(t, r);
		
		if (aslide[i] > 0) {
			u = cast(ge_p3) t;
			ge_add(t, u, Ai[aslide[i]/2]);
		} else if (aslide[i] < 0) {
			u = cast(ge_p3) t;
			ge_sub(t, u, Ai[(-aslide[i])/2]);
		}
		
		if (bslide[i] > 0) {
			u = cast(ge_p3) t;
			ge_madd(t, u, Bi[bslide[i]/2]);
		} else if (bslide[i] < 0) {
			u = cast(ge_p3) t;
			ge_msub(t, u, Bi[(-bslide[i])/2]);
		}

		r = cast(ge_p2) t;
	}
}



bool ge_frombytes_negate_vartime(ref ge_p3 h, in ubyte[] s)
in {
	assert(s.length == 32);
} body {
	fe u;
	fe v;
	fe v3;
	fe vxx;
	fe check;
	
	fe_frombytes(h.Y,s);
	h.Z = fe.one;
	fe_sq(u, h.Y);
	v = u * d;
	u -= h.Z;      /* u = y^2-1 */
	v += h.Z;       /* v = dy^2+1 */
	
	fe_sq(v3,v);
	v3 *= v;		/* v3 = v^3 */
	fe_sq(h.X,v3);
	h.X *= v; // TODO h.X *= v*u;
	h.X *= u;   /* x = uv^7 */
	
	fe_pow22523(h.X, h.X); /* x = (uv^7)^((q-5)/8) */
	h.X *= v3;
	h.X *= u;    /* x = uv^3(uv^7)^((q-5)/8) */
	
	fe_sq(vxx, h.X);
	vxx *= v;
	check = vxx - u;    /* vx^2-u */
	if (check.isNonzero) {
		check = vxx + u;  /* vx^2+u */
		if (check.isNonzero) return false;
		h.X *= sqrtm1;
	}
	
	if (h.X.isNegative == (s[31] >> 7)) {
		h.X.negate();
	}

	h.T = h.X * h.Y;
	return true;
}


/**
 r = 2 * p
 */
void ge_p2_dbl(ref ge_p1p1 r, in ref ge_p2 p)
{
	fe t0;

	fe_sq(r.X, p.X);
	fe_sq(r.Z, p.Y);
	fe_sq2(r.T, p.Z);
	r.Y = p.X + p.Y;
	fe_sq(t0, r.Y);
	r.Y = r.Z + r.X;
	r.Z -= r.X;
	r.X = t0 - r.Y;
	r.T -= r.Z;
}


/**
 r = 2 * p
 */
void ge_p3_dbl(ref ge_p1p1 r, in ref ge_p3 p)
{
	ge_p2 q;
	q = cast(ge_p2) p;
	ge_p2_dbl(r, q);
}


bool equal(in byte b, in byte c) pure
{
	ubyte x = b ^ c; /* 0: yes; 1..255: no */
	uint y = x; /* 0: yes; 1..255: no */
	y -= 1; /* 4294967295: yes; 0..254: no */
	y >>= 31; /* 1: yes; 0: no */
	return y != 0;
}

unittest {
	assert(equal(0, 1) == 0);
	assert(equal(1, 1) == 1);
	assert(equal(127, 126) == 0);
	assert(equal(127, 127) == 1);
}

/// Returns: true if b is negative
/// TODO replace with <
bool negative(in byte b) pure
{
	return b < 0;
}

/// Conditional move: t = u, if and only if b != 0.
void cmov(ref ge_precomp t, in ref ge_precomp u, in bool b)
in {
	assert(b == 0 || b == 1);
} body {
	fe_cmov(t.yplusx, u.yplusx, b);
	fe_cmov(t.yminusx, u.yminusx, b);
	fe_cmov(t.xy2d, u.xy2d, b);
}

/* Rename this so as not to interfere with select() which torint.h apparently
 * grabs. :p */
//#define select ed25519_ref10_select

/// Select ge_precomp from base table in constant time.
/// Params:
/// b = 
ge_precomp select(in int pos, in byte b)
{
	ge_precomp minust;
	immutable bool bnegative = negative(b);
	immutable ubyte babs = cast(ubyte) (b - (cast(byte)((-cast(int)(bnegative)) & cast(ubyte)b) << 1)); // abs(b)

	assert((b >= 0 && babs == b) || (b < 0 && babs == -b));
	
	ge_precomp t;
	cmov(t, base[pos][0], babs == 1);
	cmov(t, base[pos][1], babs == 2);
	cmov(t, base[pos][2], babs == 3);
	cmov(t, base[pos][3], babs == 4);
	cmov(t, base[pos][4], babs == 5);
	cmov(t, base[pos][5], babs == 6);
	cmov(t, base[pos][6], babs == 7);
	cmov(t, base[pos][7], babs == 8);
	minust.yplusx = t.yminusx;
	minust.yminusx = t.yplusx;
	minust.xy2d = -t.xy2d;
	cmov(t, minust, bnegative);
	return t;
}

/**
 h = a * B
 where a = a[0]+256*a[1]+...+256^31 a[31]
 B is the Ed25519 base point (x,4/5) with x positive.

 Preconditions:
 a[31] <= 127
 */
ge_p3 ge_scalarmult_base(in ubyte[] a)
in {
	assert(a.length == 32);
	assert(a[31] <= 127);
} body {
	byte[64] e;
	byte carry;
	ge_p1p1 r;
	ge_p2 s;
	ge_precomp t;
	ge_p3 h;
	
	for (uint i = 0; i < 32; ++i) {
		e[2 * i + 0] = (a[i] >> 0) & 0x0F;
		e[2 * i + 1] = (a[i] >> 4) & 0x0F;
	}
	/* each e[i] is between 0 and 15 */
	/* e[63] is between 0 and 7 */
	
	carry = 0;
	for (uint i = 0; i < 63; ++i) {
		e[i] += carry;
		carry = cast(byte) (e[i] + 8);
		carry >>= 4;
		e[i] -= SHL8(carry,4);
	}
	e[63] += carry;
	/* each e[i] is between -8 and 8 */
	
	h = ge_p3.zero;
	for (uint i = 1; i < 64; i += 2) {
		t = select(i / 2, e[i]);
		ge_madd(r, h, t);
		h = cast(ge_p3) r;
	}

	ge_p3_dbl(r, h); s = cast(ge_p2) r;
	ge_p2_dbl(r, s); s = cast(ge_p2) r;
	ge_p2_dbl(r, s); s = cast(ge_p2) r;
	ge_p2_dbl(r, s); h = cast(ge_p3) r;
	
	for (uint i = 0; i < 64; i += 2) {
		t = select(i / 2, e[i]);
		ge_madd(r, h, t);
		h = cast(ge_p3) r;
	}

	return h;
}

/**
 r = p - q
 */
void ge_sub(ref ge_p1p1 r, in ref ge_p3 p, in ref ge_cached q)
{
	fe t0;
	r.X = p.Y + p.X;
	r.Y = p.Y - p.X;
	r.Z = r.X * q.YminusX;
	r.Y *= q.YplusX;
	r.T = q.T2d * p.T;
	r.X = p.Z * q.Z;
	t0 = r.X + r.X;
	r.X = r.Z - r.Y;
	r.Y += r.Z;
	r.Z = t0 - r.T;
	r.T += t0;
}

// constants

immutable fe d = [-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116];
immutable fe d2 = [-21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199];
immutable fe sqrtm1 = [-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482];

immutable ge_precomp[8] Bi = [
	ge_precomp(
		[ 25967493,-14356035,29566456,3660896,-12694345,4014787,27544626,-11754271,-6079156,2047605 ],
		[ -12545711,934262,-2722910,3049990,-727428,9406986,12720692,5043384,19500929,-15469378 ],
		[ -8738181,4489570,9688441,-14785194,10184609,-12363380,29287919,11864899,-24514362,-4438546 ],
		),
	ge_precomp(
		[ 15636291,-9688557,24204773,-7912398,616977,-16685262,27787600,-14772189,28944400,-1550024 ],
		[ 16568933,4717097,-11556148,-1102322,15682896,-11807043,16354577,-11775962,7689662,11199574 ],
		[ 30464156,-5976125,-11779434,-15670865,23220365,15915852,7512774,10017326,-17749093,-9920357 ],
		),
	ge_precomp(
		[ 10861363,11473154,27284546,1981175,-30064349,12577861,32867885,14515107,-15438304,10819380 ],
		[ 4708026,6336745,20377586,9066809,-11272109,6594696,-25653668,12483688,-12668491,5581306 ],
		[ 19563160,16186464,-29386857,4097519,10237984,-4348115,28542350,13850243,-23678021,-15815942 ],
		),
	ge_precomp(
		[ 5153746,9909285,1723747,-2777874,30523605,5516873,19480852,5230134,-23952439,-15175766 ],
		[ -30269007,-3463509,7665486,10083793,28475525,1649722,20654025,16520125,30598449,7715701 ],
		[ 28881845,14381568,9657904,3680757,-20181635,7843316,-31400660,1370708,29794553,-1409300 ],
		),
	ge_precomp(
		[ -22518993,-6692182,14201702,-8745502,-23510406,8844726,18474211,-1361450,-13062696,13821877 ],
		[ -6455177,-7839871,3374702,-4740862,-27098617,-10571707,31655028,-7212327,18853322,-14220951 ],
		[ 4566830,-12963868,-28974889,-12240689,-7602672,-2830569,-8514358,-10431137,2207753,-3209784 ],
		),
	ge_precomp(
		[ -25154831,-4185821,29681144,7868801,-6854661,-9423865,-12437364,-663000,-31111463,-16132436 ],
		[ 25576264,-2703214,7349804,-11814844,16472782,9300885,3844789,15725684,171356,6466918 ],
		[ 23103977,13316479,9739013,-16149481,817875,-15038942,8965339,-14088058,-30714912,16193877 ],
		),
	ge_precomp(
		[ -33521811,3180713,-2394130,14003687,-16903474,-16270840,17238398,4729455,-18074513,9256800 ],
		[ -25182317,-4174131,32336398,5036987,-21236817,11360617,22616405,9761698,-19827198,630305 ],
		[ -13720693,2639453,-24237460,-7406481,9494427,-5774029,-6554551,-15960994,-2449256,-14291300 ],
		),
	ge_precomp(
		[ -3151181,-5046075,9282714,6866145,-31907062,-863023,-18940575,15033784,25105118,-7894876 ],
		[ -24326370,15950226,-31801215,-14592823,-11662737,-5090925,1573892,-2625887,2198790,-15804619 ],
		[ -3099351,10324967,-2241613,7453183,-5446979,-2735503,-13812022,-16236442,-32461234,-12290683 ],
		)
];