module dcrypt.blockcipher.modes.gcm.galoisfield;

import std.traits: isIntegral;

package:
@safe
struct GF128
{

	alias ubyte	T;
	alias T[BLOCKLEN/(T.sizeof*8)]	block;

	enum BLOCKLEN = 128;

	enum T R = 0xE1<<(T.sizeof*8-8);

	enum T ONE = 0x80<<(T.sizeof*8-8);

	/**
	 * raises x to the power 'pow' by squaring
	 * x <- x^pow
	 * 
	 * Params:
	 * x = this value gets raised to the power pow
	 * pow = the power
	 */
	static void power(T)(T[] x, ulong pow) nothrow @nogc
		if(isIntegral!T)
		in {
			assert(x.length*T.sizeof*8 == BLOCKLEN, "invalid length. expected 16 bytes.");
		}
	body {
		block squared;
		squared[] = x[];

		block exp;
		exp[0] = ONE; // little endian 1

		block one;
		one[0] = ONE; // little endian 1

		while(pow > 0) {

			if(pow & 0x1) {
				multiply(exp, squared);
			} else {
				multiply(exp, one);	// dummy multiplication to avoid timing attacks
			}

			multiply(squared, squared);

			pow = pow >> 1;
		}
		
		x[] = exp[];
	}

	// test power
	unittest {
		immutable ubyte[] x = cast(immutable ubyte[]) x"66e94bd4ef8a2c3b884cfa59ca342b2e";

		ubyte[16] naivePow;
		naivePow[0] = 0x80; // little endian 1

		immutable uint pow = 13;

		for(uint i = 0; i < pow; ++i) {
			multiply(naivePow, x);
		}

		ubyte[16] powBySquare;
		powBySquare[] = x[];

		power(powBySquare, pow);

		assert(naivePow == powBySquare, "power() failed");
	}

	/// Multiplies x by y using schoolbook multiplication. Result stored in x.
	static void multiply(T[] x, in T[] y) nothrow @nogc
	in {
		assert(x.length*T.sizeof*8 == BLOCKLEN, "x: invalid length.");
	}
	body {

		block v = x;
		block z;

		for(uint i = 0; i < y.length; ++i) {
			T currWord = y[i];

			for(int j = T.sizeof*8-1; j >= 0; --j) {

				//				if((currWord >> j) & 0x01) {
				//					z[] ^= v[];
				//				}
				// avoid branching:
				z[] ^= v[]&(-(cast(T)((currWord >> j) & 1))); // less prone to timing attacks than if statement

				T lsb = v[$-1] & 1;
				shiftRight(v);

				//				if(lsb) {
				//					v[0] ^= R;
				//				}
				// Avoid branching by using conditional XOR:
				v[0] ^= R&(-lsb); // -lsb is either 0x00, or 0xFF
			}
		}

		x[] = z[];
	}

	/// test multiplication by one
	unittest {
		immutable block x0 = cast(immutable block) x"66e94bd4ef8a2c3b884cfa59ca342b2e";
		block x1 = x0;

		block one;
		one[0] = ONE;
		
		multiply(x1, one);
		
		assert(x1 == x0, "GCM multiplication by ONE failed!");
	}

	/// test multiplication
	unittest {

		immutable block H = cast(immutable block)x"66e94bd4ef8a2c3b884cfa59ca342b2e";

		block x1 = cast(immutable block) x"0388dace60b6a392f328c2b971b2fe78";

		multiply(x1, H);
		
		assert(x1 == x"5e2ec746917062882c85b0685353deb7", "GCM multiplication failed!");
	}

	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	unittest {

		immutable block H = cast(immutable block) x"73A23D80121DE2D5A850253FCF43120E";
		block X1 = cast(immutable block) x"D609B1F056637A0D46DF998D88E5222A";
		
		multiply(X1, H);

		assert(X1 == x"6B0BE68D67C6EE03EF7998E399C01CA4", "GCM multiplication failed!");
	}

	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	unittest {
		
		immutable block H = cast(immutable block) x"286D73994EA0BA3CFD1F52BF06A8ACF2";
		block X1 = cast(immutable block) x"D609B1F056637A0D46DF998D88E5222A";
		
		multiply(X1, H);
		
		assert(X1 == x"BA7C26F578254853CF321281A48317CA", "GCM multiplication failed!");
	}

	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	unittest {
		
		immutable block H = cast(immutable block) x"E4E01725D724C1215C7309AD34539257";
		block X1 = cast(immutable block) x"E20106D7CD0DF0761E8DCD3D88E54000";
		
		multiply(X1, H);

		assert(X1 == x"8DAD4981E33493018BB8482F69E4478C", "GCM multiplication failed!");
	}

	/**
	 * multiplication by P (only bit 1 = 1)
	 */
	static void multiplyP(T[] x) nothrow @nogc
	in {
		assert(x.length == 16, "x: invalid length. must be 16.");
	}
	body {
		T lsb = x[$-1] & 0x01;
		shiftRight(x);
		x[0] ^= R * lsb;
	}

	// test multiplyP()
	unittest {

		block X = cast(immutable block) x"E20106D7CD0DF0761E8DCD3D88E54000";
		immutable block P = cast(immutable block) x"40000000000000000000000000000000";

		block XmultP;
		XmultP = X;

		multiplyP(XmultP);

		multiply(X, P);

		assert(X == XmultP, "multiplyP() failed");
	}

	/**
	 * multiplication by P^8
	 */
	static void multiplyP8(T)(T[] x)
	{
		T lsw = x[$-1];
		shiftRight8(x);
		for (int i = 7; i >= 0; --i)
		{
			//			if (lsw & (1 << i))
			//			{
			//				x[0] ^= ((R<<(T.sizeof*8-8)) >> (7 - i));
			//			}
			//			avoid branching:
			x[0] ^= (((R<<(T.sizeof*8-8)) >> (7 - i))) * (lsw & (1 << i));
		}
	}

	// test multiplyP8()
	unittest {
		
		block X = cast(immutable block) x"E20106D7CD0DF0761E8DCD3D88E54000";
		immutable block P = cast(immutable block) x"40000000000000000000000000000000";

		block XmultP8;
		XmultP8 = X;
		
		multiplyP8(XmultP8);

		foreach(i;0..8){
			multiply(X, P);
		}
		
		assert(X == XmultP8, "multiplyP8() failed");
	}
	
	/**
	 * Shift big endian number a 1 bit to the right.
	 */
	static void shiftRight(T)(T[] a) nothrow @nogc 
		if(isIntegral!T)
	{
		T carryBit = 0;
		for(size_t i = 0; i < a.length; ++i) {
			T b = a[i];
			a[i] >>= 1;
			a[i] |= carryBit;
			carryBit = cast(T)(b << (T.sizeof * 8 - 1));
		}
	}

	// test right shift with bytes
	unittest {
		ubyte[] a = [0xf1,0x83,0x01];
		shiftRight(a);
		assert(a == [0x78,0xc1,0x80], "right shift failed");
	}

	// test shiftRight
	unittest {
		
		ubyte[16] a = cast(immutable ubyte[16]) x"59ed3f2bb1a0aaa07c9f56c6a504647b";
		foreach(i;0..8) {
			shiftRight(a);
		}
		
		assert(a == x"0059ed3f2bb1a0aaa07c9f56c6a50464", "right shift failed");
	}

	// with ints
	unittest {
		uint[] a = [0xfedcba98,0x76543210];
		foreach(i;0..8) {
			shiftRight(a);
		}
		assert(a == [0x00fedcba,0x98765432], "right shift failed");
	}

	// with longs
	unittest {
		ulong[] a = [0x59ed3f2bb1a0aaa0,0x7c9f56c6a504647b];
		foreach(i;0..8) {
			shiftRight(a);
		}
		assert(a == [0x0059ed3f2bb1a0aa,0xa07c9f56c6a50464], "right shift failed");
	}

	/**
	 * Shift big endian number a 8 bits to the right.
	 */
	static void shiftRight8(T)(T[] a) nothrow @nogc {
		T carryBit = 0;
		for(size_t i = 0; i < a.length; ++i) {
			T b = a[i];
			a[i] >>= 8;
			a[i] |= carryBit;
			carryBit = cast(T)(b << (T.sizeof * 8 - 8));
		}
	}

	//	static void shiftRight(T)(T[] a, ubyte n) nothrow @nogc {
	//		T carryBit = 0;
	//		for(size_t i = 0; i < a.length; ++i) {
	//			T b = a[i];
	//			a[i] >>= n;
	//			a[i] |= carryBit;
	//			carryBit = cast(T)(b << (T.sizeof * 8 - n));
	//		}
	//	}

	
	//	static void shiftRight(ubyte[] a, ubyte n) nothrow @nogc {
	//		shiftRight(cast(uint[])a, n);
	//	}

	// test shiftRight8()
	unittest {
		ubyte[16] a = cast(immutable ubyte[16])x"59ed3f2bb1a0aaa07c9f56c6a504647b";
		ubyte[16] b = a;
		foreach(i;0..8) {
			shiftRight(a);
		}

		shiftRight8(b);
		
		assert(a == b, "right shift by 8 bits failed");
	}

}