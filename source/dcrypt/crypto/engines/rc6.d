module dcrypt.crypto.engines.rc6;

import dcrypt.crypto.blockcipher;
import dcrypt.util.bitmanip;
import dcrypt.util.pack;

/// test the RC6 block cipher engine
unittest {

	// 160, 224 bit keys commented out
	string[] test_keys = [
		x"01010101010101010101010101010101",
		//x"0101010101010101010101010101010101010101",
		x"010101010101010101010101010101010101010101010101",
		//x"01010101010101010101010101010101010101010101010101010101",
		x"0101010101010101010101010101010101010101010101010101010101010101",
	];
	string[] test_plaintexts = [
		x"01010101010101010101010101010101",
		//x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
		//x"01010101010101010101010101010101",
		x"01010101010101010101010101010101",
	];
	string[] test_ciphertexts = [
		x"efb2c7dd69614683dab0bc607036c425",
		//x"ff59d24608b42833e9292f4be0a239a5",
		x"142aa9f25dd64a8a6444304735aa6641",
		//x"26e64b9c2bb63e93494d0d803994bdfd",
		x"41ecee06dda0946c816f528a767c0ef6",
	];
	
	RC6Engine t = new RC6Engine();
	blockCipherTest(t, test_keys, test_plaintexts, test_ciphertexts);
}

alias BlockCipherWrapper!RC6 RC6Engine;

/**
 * An RC6 engine.
 */
@safe
public struct RC6
{
	public {

		enum name = "RC6";
		enum blockSize = 4*bytesPerWord;

		
		/// Params:
		/// forEncryption = `false`: decrypt, `true`: encrypt
		/// userKey = Secret key.
		/// iv = Not used.
		/// Throws: Error if key has unsupported size.	
		void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc
		{
			this.forEncryption = forEncryption;
			setKey(userKey);
		}

		uint processBlock(in ubyte[]  input, ubyte[]  output) nothrow @nogc
		in {
			assert(initialized, "RC6 engine not initialized");
			assert(blockSize <= input.length, "input buffer too short");
			assert(blockSize <= output.length, "output buffer too short");
		}
		body {
			return forEncryption ? encryptBlock(input, output) : decryptBlock(input, output);
		}

		void reset() nothrow @nogc
		{
		}

		
		private nothrow @nogc:

		private {
			enum wordSize = 32;
			enum bytesPerWord = wordSize / 8;

			/*
			 * the number of rounds to perform
			 */
			enum _noRounds = 20;

			/*
			 * our "magic constants" for wordSize 32
			 *
			 * Pw = Odd((e-2) * 2^wordsize)
			 * Qw = Odd((o-2) * 2^wordsize)
			 *
			 * where e is the base of natural logarithms (2.718281828...)
			 * and o is the golden ratio (1.61803398...)
			 */
			enum uint    P32 = 0xb7e15163;
			enum uint    Q32 = 0x9e3779b9;

			enum    LGW = 5;        // log2(32)

			/*
			 * the expanded key array of size 2*(rounds + 1)
			 */
			uint[2+2*_noRounds+2] _S;
			bool forEncryption;
			bool initialized = false; // set to true in setKey()

		}
		/**
		 * Re-key the cipher.
		 * Params:  key  the key to be used
		 */
		private void setKey(in ubyte[] key) nothrow @nogc
		in {
			size_t len = key.length;
			assert(len == 16 || len == 24 || len == 32, "RC6: Unsupported key length. Should be 128, 192, or 256 bits."); 
		}
		body {
			
			enum maxKeyLength = 32;
			
			//
			// KEY EXPANSION:
			//
			// There are 3 phases to the key expansion.
			//
			// Phase 1:
			//   Copy the secret key K[0...b-1] into an array L[0..c-1] of
			//   c = ceil(b/u), where u = wordSize/8 in little-endian order.
			//   In other words, we fill up L using u consecutive key bytes
			//   of K. Any unfilled byte positions in L are zeroed. In the
			//   case that b = c = 0, set c = 1 and L[0] = 0.
			//
			// compute number of dwords
			size_t c = (key.length + (bytesPerWord - 1)) / bytesPerWord;
			if (c == 0)
			{
				c = 1;
			}
			
			uint[(maxKeyLength + bytesPerWord - 1) / bytesPerWord] L;	///	Static length is hight enough to support 256 bit keys.
			immutable size_t Llength = (key.length + bytesPerWord - 1) / bytesPerWord;	/// Holds the actual length of L.
			
			// load all key bytes into array of key dwords
			
			foreach(size_t i; 0..key.length) {
				L[i / bytesPerWord] += key[i] << (8*i);
			}
			
			//
			// Phase 2:
			//   Key schedule is placed in a array of 2+2*ROUNDS+2 = 44 dwords.
			//   Initialize S to a particular fixed pseudo-random bit pattern
			//   using an arithmetic progression modulo 2^wordsize determined
			//   by the magic numbers, Pw & Qw.
			//
			//        _S            = new uint[2+2*_noRounds+2];
			
			_S[0] = P32;
			foreach (size_t i; 1.._S.length)
			{
				_S[i] = (_S[i-1] + Q32);
			}
			
			//
			// Phase 3:
			//   Mix in the user's secret key in 3 passes over the arrays S & L.
			//   The max of the arrays sizes is used as the loop control
			//
			size_t iter;
			
			if (Llength > _S.length)
			{
				iter = 3 * Llength;
			}
			else
			{
				iter = 3 * _S.length;
			}
			
			uint A = 0;
			uint B = 0;
			uint i = 0, j = 0;
			
			foreach (k; 0..iter)
			{
				A = _S[i] = rotateLeft(_S[i] + A + B, 3);
				B =  L[j] = rotateLeft(L[j] + A + B, A+B);
				i = (i+1) % _S.length;
				j = (j+1) %  Llength;
			}
			
			initialized = true;
		}
	}

	@nogc
	private uint encryptBlock(in ubyte[]  input, ubyte[]  output) nothrow
	{
		// load A,B,C and D registers from in.
		uint A = fromLittleEndian!uint(input);
		uint B = fromLittleEndian!uint(input[bytesPerWord..$]);
		uint C = fromLittleEndian!uint(input[bytesPerWord*2..$]);
		uint D = fromLittleEndian!uint(input[bytesPerWord*3..$]);

		// Do pseudo-round #0: pre-whitening of B and D
		B += _S[0];
		D += _S[1];

		// perform round #1,#2 ... #ROUNDS of encryption
		foreach (uint i; 1.._noRounds+1)
		{
			uint t = 0,u = 0;

			t = B*(2*B+1);
			t = rotateLeft(t,5);

			u = D*(2*D+1);
			u = rotateLeft(u,5);

			A ^= t;
			A = rotateLeft(A,u);
			A += _S[2*i];

			C ^= u;
			C = rotateLeft(C,t);
			C += _S[2*i+1];

			uint temp = A;
			A = B;
			B = C;
			C = D;
			D = temp;
		}
		// do pseudo-round #(ROUNDS+1) : post-whitening of A and C
		A += _S[2*_noRounds+2];
		C += _S[2*_noRounds+3];

		// store A, B, C and D registers to out
		toLittleEndian(A, output);
		toLittleEndian(B, output[bytesPerWord..$]);
		toLittleEndian(C, output[bytesPerWord*2..$]);
		toLittleEndian(D, output[bytesPerWord*3..$]);

		return 4 * bytesPerWord;
	}

	@nogc
	private uint decryptBlock(in ubyte[]  input, ubyte[]  output) nothrow
	{
		// load A,B,C and D registers from out.
		uint A = fromLittleEndian!uint(input);
		uint B = fromLittleEndian!uint(input[bytesPerWord..$]);
		uint C = fromLittleEndian!uint(input[bytesPerWord*2..$]);
		uint D = fromLittleEndian!uint(input[bytesPerWord*3..$]);

		// Undo pseudo-round #(ROUNDS+1) : post whitening of A and C
		C -= _S[2*_noRounds+3];
		A -= _S[2*_noRounds+2];

		// Undo round #ROUNDS, .., #2,#1 of encryption
		for (uint i = _noRounds; i >= 1; i--)
		{
			uint t=0,u = 0;

			uint temp = D;
			D = C;
			C = B;
			B = A;
			A = temp;

			t = B*(2*B+1);
			t = rotateLeft(t, LGW);

			u = D*(2*D+1);
			u = rotateLeft(u, LGW);

			C -= _S[2*i+1];
			C = rotateRight(C,t);
			C ^= u;

			A -= _S[2*i];
			A = rotateRight(A,u);
			A ^= t;

		}
		// Undo pseudo-round #0: pre-whitening of B and D
		D -= _S[1];
		B -= _S[0];

		toLittleEndian(A, output);
		toLittleEndian(B, output[bytesPerWord..$]);
		toLittleEndian(C, output[bytesPerWord*2..$]);
		toLittleEndian(D, output[bytesPerWord*3..$]);

		return 4 * bytesPerWord;
	}
}