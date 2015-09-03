module dcrypt.crypto.ecc.ed25519.curve25519;

import dcrypt.crypto.ecc.ed25519.fieldElement;


int crypto_scalarmult(out ubyte[32] q,
	in ref ubyte[32] n,
	in ref ubyte[32] p)
{
	ubyte[32] e;
	uint i;
	fe x1;
	fe x2;
	fe z2;
	fe x3;
	fe z3;
	fe tmp0;
	fe tmp1;
	int pos;
	uint swap, b;
	
	for (i = 0;i < 32;++i) e[i] = n[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	x1 = fe.fromBytes(p);
	x2 = fe.one;
	z2 = fe.zero;
	x3 = x1;
	z3 = fe.one;
	
	swap = 0;
	for (pos = 254;pos >= 0;--pos) {
		b = e[pos / 8] >> (pos & 7);
		b &= 1;
		swap ^= b;
		fe_cswap(x2,x3,swap);
		fe_cswap(z2,z3,swap);
		swap = b;

		tmp0 = x3 - z3;

		tmp1 = x2 - z2;
		x2 += z2;
		z2 = x3 + z3;

		z3 = tmp0 + x2;

		z2 += tmp1;
		tmp0 = tmp1.sq;
		tmp1 = x2.sq;
		x3 += z2;

		z2 += z3;
		x2 = tmp0 * tmp1;

		tmp1 -= tmp0;
		
		z2 = z2.sq;

		z3 = fe_mul121666(tmp1);

		x3 = x3.sq;

		tmp0 += z3;
		z3 = x1 * z2;

		z2 = tmp0 * tmp1;
	}
	fe_cswap(x2,x3,swap);
	fe_cswap(z2,z3,swap);

	z2 = z2.inverse;
	x2 *= z2;
	q = x2.toBytes;
	return 0;
}

