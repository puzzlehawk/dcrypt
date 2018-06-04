module dcrypt.aead.gcm.multiplier;

package:

import dcrypt.aead.gcm.galoisfield;

// TODO Dynamically make use of intel pclmulqdq instruction for fast multiplication.

/// test if T is a GCM multiplier
@safe
template isGCMMultiplier(T)
{
	enum bool isGCMMultiplier =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[16] block;
						T m = void;
						m.init(block);
						m.multiply(block);
					}));
}

/// This struct provides schoolbook multiplication in GF(2^128).
@safe
struct GCMBasicMultiplier
{
	
	private {
		ubyte[16] H;
	}
	
	this(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		init(H);
	}
	
	nothrow @nogc {
		/**
		 * initialize the multiplicator
		 */
		void init(in ubyte[] H) 
		in {
			assert(H.length == 16, "H: invalid length");
		}
		body {
			this.H[] = H[];
		}
		
		/// Multiply x by H and store result in x.
		/// 
		/// Params:
		/// x = 16 byte block
		void multiply(ubyte[] x)
		in {
			assert(x.length == 16, "x: invalid length.");
		}
		body {
			GF128.multiply(x, H);
		}
	}
	
	/// test multiplication using schoolbook multiplication
	unittest {
		
		immutable ubyte[16] H = cast(immutable ubyte[16]) x"66e94bd4ef8a2c3b884cfa59ca342b2e";
		ubyte[16] X1 = cast(immutable ubyte[16]) x"0388dace60b6a392f328c2b971b2fe78";
		
		GCMBasicMultiplier mult = GCMBasicMultiplier(H);
		
		mult.multiply(X1);
		
		assert(X1 == x"5e2ec746917062882c85b0685353deb7", "GF128 multiplication with 8k table failed!");
	}
	
}

/// This struct provides table driven multiplication in GF(2^128).
@safe
struct GCMMultiplier8kTable
{
	
	private {
		ubyte[16][16][32] M;
	}
	
	this(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		init(H);
	}
	
	nothrow @nogc {
		/**
		 * initialize the multiplicator
		 */
		void init(in ubyte[] H) {
			tableSetup(H);
		}
		
		/// Multiply x by H and store result in x.
		/// 
		/// Params:
		/// x = 16 byte block
		void multiply(ubyte[] x)
		in {
			assert(x.length == 16, "x: invalid length.");
		}
		body {
			
			ubyte[16] z;
			
			for(uint i = 0; i < 16; ++i) {
				z[] ^= M[2*i][x[i]>>4][];
				z[] ^= M[2*i+1][x[i]&0xF][];
			}
			
			x[] = z[];
		}
	}
	
	/// test multiplication using 8k table
	unittest {
		
		immutable ubyte[16] H = cast(immutable ubyte[16]) x"66e94bd4ef8a2c3b884cfa59ca342b2e";
		ubyte[16] X1 = cast(immutable ubyte[16]) x"0388dace60b6a392f328c2b971b2fe78";
		
		GCMMultiplier8kTable mult = GCMMultiplier8kTable(H);
		
		mult.multiply(X1);
		
		assert(X1 == x"5e2ec746917062882c85b0685353deb7", "GF128 multiplication with 8k table failed!");
	}
	
	private void tableSetup(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		ubyte[16] Pi;
		Pi[0] = 0x80;
		ubyte[1] oneByte;
		for(int i = 0; i < 32; ++i) {
			for(uint j = 0; j < 16; ++j) {
				M[i][j] = H;
				oneByte[0] = cast(ubyte) (j<<4);
				GF128.multiply(M[i][j], oneByte);
				GF128.multiply(M[i][j], Pi);
			}
			multiplyP4(Pi);
		}
	}
	
	private void multiplyP4(ubyte[] x) nothrow @nogc {
		foreach(i;0..4){
			GF128.multiplyP(x);
		}
	}
	
}

/// This class provides table driven multiplication in GF(2^128).
/// The 64k table is rather large and probably won't fit into the cache.
/// Use the 8k table to avoid timing based leaks.
@safe
struct GCMMultiplier64kTable
{
	
	private {
		ubyte[16][256][16] M;
	}
	
	this(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		init(H);
	}
	
	nothrow @nogc {

		/// initialize the multiplicator
		void init(in ubyte[] H) {
			tableSetup(H);
		}
		
		/// Multiply x by H and store result in x.
		/// 
		/// Params:
		/// x = 16 byte block
		void multiply(ubyte[] x)
		in {
			assert(x.length == 16, "x: invalid length.");
		}
		body {
			
			ubyte[16] z;
			
			for(uint i = 0; i < 16; ++i) {
				z[] ^= M[i][x[i]][];
			}
			
			x[] = z[];
		}
	}
	
	/// test multiplication using 64k table
	unittest {
		immutable ubyte[16] H = cast(immutable ubyte[16]) x"66e94bd4ef8a2c3b884cfa59ca342b2e";
		ubyte[16] X1 = cast(immutable ubyte[16]) x"0388dace60b6a392f328c2b971b2fe78";
		
		GCMMultiplier64kTable mult = GCMMultiplier64kTable(H);
		
		mult.multiply(X1);
		
		assert(X1 == x"5e2ec746917062882c85b0685353deb7", "GF128 multiplication with 64k table failed!");
	}
	
	private void tableSetup(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		ubyte[16] P;
		P[0] = 0x80;
		ubyte[1] oneByte;
		for(int i = 0; i < 16; ++i) {
			for(uint j = 0; j <= 255; ++j) {
				M[i][j] = H;
				oneByte[0] = cast(ubyte) j;
				GF128.multiply(M[i][j], oneByte);
				GF128.multiply(M[i][j], P);
			}
			GF128.multiplyP8(P);
		}
	}
	
}


/// This struct provides hardware accelerated multiplication in GF(2^128)
/// using the Intel PCLMULQDQ instruction.
/// 
/// See: https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
@safe
struct GCMPCLMULQDQMultiplier
{
	
	private {
		ubyte[16] H;
	}
	
	this(in ubyte[] H) nothrow @nogc
	in {
		assert(H.length == 16, "H: invalid length");
	}
	body {
		init(H);
	}
	
	nothrow @nogc {
		/**
		 * initialize the multiplicator
		 */
		void init(in ubyte[] H) 
		in {
			assert(H.length == 16, "H: invalid length");
		}
		body {
			this.H[] = H[];
		}
		
		/// Multiply x by H and store result in x.
		/// 
		/// Params:
		/// x = 16 byte block
		void multiply(ubyte[] x)
		in {
			assert(x.length == 16, "x: invalid length.");
		}
		body {
			//GF128.multiply(x, H);
			gfmul(x, H);
		}
	}
	
	/// Multiplies a with b, result is stored in a.
	@trusted
	private void gfmul(ubyte[] a, in ubyte[] b) nothrow @nogc
	in {
		assert(a.length == 16, "Invalid length of input. Must be 16 bytes.");
		assert(b.length == 16, "Invalid length of input. Must be 16 bytes.");
	}
	body {

		import std.algorithm: reverse;
		ubyte[16] revB;

		reverse(a);

		revB[] = b[];
		reverse(revB[]);

		asm @nogc nothrow {
			//xmm0 holds operand a (128 bits)
			//xmm1 holds operand b (128 bits)
			//rdi holds the pointer to output (128 bits)

			// Note: since pclmulqdq instruction is not supported as of this writing binary opcodes are used.
			// TODO Replace binary opcodes by pclmulqdq as soon as this instruction is supported by dmd's inline assembler.

			// load pointer to a
			mov	RSI, a+8;
			mov RDI, RSI; // store destination address
			// load input into registers XMM0 and XMM1
			movdqu	XMM0, [RSI];
			//mov	RSI, b+8;
			//movdqu	XMM1, [RSI];

			movdqu	XMM1, revB[RBP];

			movdqa     XMM3, XMM0;
			db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x00;	// pclmulqdq  XMM3, XMM1, 0x00;    // XMM3 holds a0*b0
			movdqa     XMM4, XMM0;
			db 0x66, 0x0f, 0x3a, 0x44, 0xe1, 0x10;	// pclmulqdq  XMM4, XMM1, 0x10;    //XMM4 holds a0*b1
			movdqa     XMM5, XMM0;
			db 0x66, 0x0f, 0x3a, 0x44, 0xe9, 0x01; // pclmulqdq  XMM5, XMM1, 0x01;     // XMM5 holds a1*b0
			movdqa     XMM6, XMM0;
			db 0x66, 0x0f, 0x3a, 0x44, 0xf1, 0x11;	// pclmulqdq  XMM6, XMM1, 0x11;    // XMM6 holds a1*b1
			pxor       XMM4, XMM5;         // XMM4 holds a0*b1 + a1*b0
			movdqa     XMM5, XMM4;
			psrldq     XMM4, 8;
			pslldq     XMM5, 8;
			pxor       XMM3, XMM5;
			pxor       XMM6, XMM4;         // <XMM6:XMM3> holds the result of 
			// the carry-less multiplication of XMM0 by XMM1
			// shift the result by one bit position to the left cope for the fact
			// that bits are reversed
			movdqa   XMM7, XMM3;
			movdqa   XMM8, XMM6;
			pslld    XMM3, 1;
			pslld    XMM6, 1;
			psrld    XMM7, 31;
			psrld    XMM8, 31;
			movdqa   XMM9, XMM7;
			pslldq   XMM8, 4;
			pslldq   XMM7, 4;
			psrldq   XMM9, 12;
			por      XMM3, XMM7;
			por      XMM6, XMM8;
			por      XMM6, XMM9;
			//first phase of the reduction
			movdqa   XMM7, XMM3;
			movdqa   XMM8, XMM3;
			movdqa   XMM9, XMM3;     
			pslld    XMM7, 31;            // packed right shifting << 31  
			pslld    XMM8, 30;            // packed right shifting shift << 30
			pslld    XMM9, 25;            // packed right shifting shift << 25  
			pxor     XMM7, XMM8;          // xor the shifted versions
			pxor     XMM7, XMM9;    
			movdqa   XMM8, XMM7;

			
			pslldq   XMM7, 12;
			psrldq   XMM8, 4;
			pxor     XMM3, XMM7;          // first phase of the reduction complete 
			movdqa   XMM2, XMM3;           // second phase of the reduction
			movdqa   XMM4, XMM3;
			movdqa   XMM5, XMM3;  
			psrld    XMM2, 1;             // packed left shifting >> 1
			psrld    XMM4, 2;             // packed left shifting >> 2
			psrld    XMM5, 7;             // packed left shifting >> 7   

			pxor     XMM2, XMM4;          // xor the shifted versions
			pxor     XMM2, XMM5;
			pxor     XMM2, XMM8;
			pxor     XMM3, XMM2; 
			pxor     XMM6, XMM3;          // the result is in xmm6 
			movdqu   [RDI], XMM6;         // store the result
		}

		reverse(a);

	}

	// test pclmulqdq instruction with multiplication by 1
	@trusted
	unittest {
		import core.cpuid;
		version(D_InlineAsm_X86_64) {
			if(aes) {
				
				ubyte[16] a = cast(const ubyte[16]) x"12345678000000000000000000000000"; 
				ubyte[16] b = cast(const ubyte[16]) x"01000000000000000000000000000000"; 
				ubyte[16] c;
				
				asm {
					movdqu XMM1, a[RBP];
					movdqu XMM3, b[EBP];
					
					db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x00;	// pclmulqdq  XMM3, XMM1, 0x00;    // XMM3 holds a0*b0
					
					movdqu c[EBP], XMM3;
				}
				
				assert(c == x"12345678000000000000000000000000");
			}
		}
	}
	
	/// test pclmulqdq instruction with test vectors from
	/// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
	@trusted
	unittest {
		import core.cpuid;

		version(D_InlineAsm_X86_64) {
			if(aes) {

				/// Python code to convert test vectors into little endian format. 
				/// Reverses the string by bytes (not by hexits):
				/// 
				/// import binascii
				/// def conv(xmmstr):
				///		bytearr=bytearray.fromhex(xmmstr)[::-1]
				///		return binascii.hexlify(bytearr)
				///
				/// conv('7b5b54657374566563746f725d53475d')
				/// conv('48692853686179295b477565726f6e5d')
				/// conv('1d4d84c85c3440c0929633d5d36f0451')
				/// 

				ubyte[16] a = cast(const ubyte[16]) x"5d47535d726f74636556747365545b7b"; // xxm1 high: 7b5b546573745665 low: 63746f725d53475d
				ubyte[16] b = cast(const ubyte[16]) x"5d6e6f726575475b2979616853286948"; // 4869285368617929 5b477565726f6e5d
				ubyte[16] c;

				asm {
					movdqu XMM1, a[RBP];
					movdqu XMM3, b[EBP];

					db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x00;	// pclmulqdq  XMM3, XMM1, 0x00;    // XMM3 holds a0*b0

					movdqu c[EBP], XMM3;
				}
				assert(c == x"51046fd3d5339692c040345cc8844d1d");

				asm {
					movdqu XMM1, a[RBP];
					movdqu XMM3, b[EBP];
					
					db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x01;
					
					movdqu c[EBP], XMM3;
				}
				assert(c == x"1513282aac40a57fa1b56a558d7cd11b");

				asm {
					movdqu XMM1, a[RBP];
					movdqu XMM3, b[EBP];
					
					db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x10;
					
					movdqu c[EBP], XMM3;
				}
				assert(c == x"c9d5b7f42d26bfba2f86303adbf62b1a");

				asm {
					movdqu XMM1, a[RBP];
					movdqu XMM3, b[EBP];
					
					db 0x66, 0x0f, 0x3a, 0x44, 0xd9, 0x11;
					
					movdqu c[EBP], XMM3;
				}
				assert(c == x"edd40f413ee06ed6457c2e592c1f1e1d");
			}
		}
	}

	
//	/// test hardware accelerated multiplication (pclmulqdq)
//	unittest {
//		
//		immutable ubyte[16] H = cast(immutable ubyte[16]) x"00000000000000000000000000000080"; // neutral element
//		ubyte[16] X1 = cast(immutable ubyte[16]) x"0388dace60b6a392f328c2b971b2fe78";
//		
//		GCMPCLMULQDQMultiplier mult = GCMPCLMULQDQMultiplier(H);
//		
//		mult.multiply(X1);
//		
//		assert(X1 == x"0388dace60b6a392f328c2b971b2fe78", "GF128 multiplication with pclmulqdq failed!");
//	}
	
	/// test hardware accelerated multiplication (pclmulqdq)
	unittest {

		import std.algorithm: reverse;
		
		ubyte[16] H = cast(immutable ubyte[16]) x"952b2a56a5604ac0b32b6656a05b40b6";
		ubyte[16] X1 = cast(immutable ubyte[16]) x"dfa6bf4ded81db03ffcaff95f830f061";

		ubyte[16] expected = cast(immutable ubyte[16]) x"da53eb0ad2c55bb64fc4802cc3feda60";

//		reverse(H[]);
//		reverse(X1[]);
//		reverse(expected[]);

		//GCMMultiplier8kTable mult = GCMMultiplier8kTable(H);
		GCMPCLMULQDQMultiplier mult = GCMPCLMULQDQMultiplier(H);
		
		mult.multiply(X1);
		
		assert(X1 == expected, "GF128 multiplication with pclmulqdq failed!");
	}

//	/// test hardware accelerated multiplication (pclmulqdq)
//	unittest {
//		
//		ulong[2] H = [0xb32b6656a05b40b6, 0x952b2a56a5604ac0];
//		ulong[2] X1 = [0xffcaff95f830f061, 0xdfa6bf4ded81db03];
//		
//		ulong[2] expected = [0x4fc4802cc3feda60, 0xda53eb0ad2c55bb6];
//
//		//GCMMultiplier8kTable mult = GCMMultiplier8kTable(H);
//		GCMPCLMULQDQMultiplier mult = GCMPCLMULQDQMultiplier(cast(ubyte[16])H);
//		
//		mult.multiply(cast(ubyte[16])X1);
//		
//		assert(X1 == expected, "GF128 multiplication with pclmulqdq failed!");
//	}
	
}