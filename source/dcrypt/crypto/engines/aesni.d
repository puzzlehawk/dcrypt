module dcrypt.crypto.engines.aesni;

/// 
/// This module provides a hardware accelerated implementation of AES using the Intel AES instructionset.
/// Aside from being faster than software AES this implementation is presumably less prone to cache timing attacks such as FLUSH+RELOAD.
/// 
/// The assembler instructions for key setup are more or less copied from linux kernel crypto (arch/x86/crypto/aesni-intel_asm.S).
/// 
/// This code relies on intel AES and SSE2 instruction sets. If the CPU does not support all of these, an error will be thrown.
/// Consider using checkHardwareAES() to check if aesni is supported.
/// 

import core.cpuid;
import dcrypt.crypto.blockcipher;

/// OOP API wrapper for AESNI
alias BlockCipherWrapper!AESNI AESNIEngine;

version (D_InlineAsm_X86_64) {
	// enable AESNI
	version = AESNI;
}

// TODO what if AESNI is not supported?
version(AESNI) {} else {
	// fall back to software aes implementation
	import dcrypt.crypto.engines.aes;
	alias AESNI = AES; // use software AES on non x86_64 platforms
	
}

/// Check if CPU supports aes instructions.
/// 
/// Returns: true if and only if CPU supports AES acceleration.
public static bool checkHardwareAES() nothrow @nogc {
	version(AESNI) {
		return aes & sse2;
	} else {
		return false;
	}
}

version (AESNI) {

	///
	///	hardware accelerated aes implementation
	/// makes use of intel AESNI
	/// 
	/// This code relies on intel AES and SSE2 instruction sets. If the CPU does not support all of these, an error will be thrown.
	/// Consider using checkHardwareAES() to check if aesni is supported.
	///
	@safe
	public struct AESNI
	{

		public enum blockSize = 16;
		public enum name = "AES-NI";
		
		public {

			/// Params:
			/// forEncryption = `false`: decrypt, `true`: encrypt
			/// userKey = Secret key.
			/// iv = Not used.
			/// 
			/// Throws: Error if aes instruction set is not supported by CPU.
			/// Use checkHardwareAES() to avoid running into this error.
			void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc
			{
				assertHardwareSupport();
				
				this.forEncryption = forEncryption;

				switch(userKey.length) {
					case 16: rounds = 11;
						break;
					case 24: rounds = 13;
						break;
					case 32: rounds = 15;
						break;
					default: assert(false, "Invalid user key size. (16, 24 or 32 bytes allowed)");
				}
				
				AES_KEY_EXPANSION(userKey, workingKey[0..rounds*16], forEncryption);
				
				initialized = true;
			}

			uint processBlock(in ubyte[] input, ubyte[] output) nothrow @nogc
			in {
				assert(initialized, "AESNI engine not initialized");
				assert(blockSize<=input.length, "input buffer too short");
				assert(blockSize<=output.length, "output buffer too short");
			}
			body {

				if (forEncryption)
				{
					AES_ENCRYPT(workingKey[0..rounds*16], input, output);
				}
				else
				{
					AES_DECRYPT(workingKey[0..rounds*16], input, output);
				}

				return blockSize;
			}

			void reset() nothrow @nogc
			{
			}
		}

		
		// begin of private section
	private:

		
		/// AES encryption (1 block)
		/// Params:
		/// key = rounds*16 byte encryption key schedule
		/// input = 16 bytes plaintext
		/// output = at least 16 bytes output buffer
		@trusted
		void AES_ENCRYPT(in ubyte[] key, in ubyte[] input, ubyte[] output) nothrow @nogc
		in {
			assert(key.length == 16*rounds, "invalid key size");
			assert(input.length == 16, "invalid input block size");
			assert(output.length >= 16, "output buffer too small");
		}
		body {

			ubyte rounds = this.rounds;
			
			asm @nogc nothrow {

				// XMM0:	round key
				// XMM1:	data block

				// load plaintext into XMM1
				mov RSI, input+8;	// pointer to plaintext
				movdqu XMM1, [RSI];	// read plaintext block

				
				mov RSI, key+8;	// pointer to key schedule

				// AES-128 encryption sequence.
				// The data block is in XMM1
				// Register XMM0 holds the round keys(from 0 to 10 in this order).
				// In the end, XMM1 holds the encryption result.
				movdqu XMM0, [RSI+0x00];
				pxor XMM1, XMM0; // Whitening step (Round 0)
				add RSI, 0x10;

				xor RCX, RCX;
				mov CL, rounds;
				sub RCX, 2;

				// encryption rounds 1..N-1
			_encLoop:
				movdqu XMM0, [RSI];	// load round key
				aesenc XMM1, XMM0;	// encrypt
				add RSI, 0x10;		// increment round key pointer
				loop _encLoop;

				movdqu XMM0, [RSI];	// load last round key
				aesenclast XMM1, XMM0; // last round

				// store encrypted data to buffer
				mov RDI, output+8;		// pointer to output buffer
				movdqu [RDI], XMM1;		// write processed data to buffer

				// wipe data
				pxor XMM0, XMM0;
				pxor XMM1, XMM1;
			}
		}
		
		/// AES128 11 round decryption
		/// Params:
		/// key = rounds*16 byte decryption key schedule
		/// input = 16 bytes ciphertext
		/// output = at least 16 bytes output buffer
		@trusted
		void AES_DECRYPT(in ubyte[] key, in ubyte[] input, ubyte[] output) nothrow @nogc
		in {
			assert(key.length == 16*rounds, "invalid key size");
			assert(input.length == 16, "invalid input block size");
			assert(output.length >= 16, "output buffer too small");
		}
		body {

			ubyte rounds = rounds;

			asm @nogc nothrow {

				// XMM0:	round key
				// XMM1:	data block

				
				
				// load ciphertext block into XMM1
				mov RSI, input + 8;		// get to first block of data
				movdqu XMM1, [RSI];		// get first block of data

				mov RSI, key + 8;		// get pointer to key schedule

				// RCX: round counter
				xor RCX, RCX;
				mov CL, rounds;	// load number of rounds
				dec RCX;		// set index: rounds-1
				shl	RCX, 4;		// multiply by 0x10
				add RSI, RCX;	// set pointer to last round key
				shr RCX, 4;		// restore RCX to number of rounds

				movdqu XMM0, [RSI];		// load first round key
				sub RSI, 0x10;			// adjust round key pointer
				pxor XMM1, XMM0;		// Whitening step (Round 0)
				dec RCX;				// first round done

				// decryption rounds 1..N-1
			_decLoop:
				movdqu XMM0, [RSI];		// load round key
				aesdec XMM1, XMM0;		// decrypt
				sub RSI, 0x10;			// adjust round key pointer
				loop _decLoop;

				movdqu XMM0, [RSI];
				aesdeclast XMM1, XMM0; // last round

				// store decrypted data to buffer
				mov RSI, output + 8;	// get pointer to output buffer
				movdqu [RSI], XMM1;	// write block to output buffer

				// wipe data
				pxor XMM0, XMM0;
				pxor XMM1, XMM1;
			}
		}
		
		///
		/// Expand a 128,192,256 bit user key into N round keys for AES with 128 bit blocks.
		/// 
		/// source: linux source code, arch/x86/crypto/aesni-intel_asm.S
		/// Params:
		/// 
		/// userKey = the AES key as given by the user
		/// keySchedule = enough space for N round keys
		/// forEncryption = true: generate encryption key, false: generate decryption key
		///
		///
		@trusted
		private static void AES_KEY_EXPANSION(in ubyte[] userKey, ubyte[] keySchedule, bool forEncryption) nothrow @nogc
		in {
			assertHardwareSupport();
		}
		body {

			size_t rounds;
			switch(userKey.length) {
				case 16: rounds = 11;
					break;
				case 24: rounds = 13;
					break;
				case 32: rounds = 15;
					break;
				default: assert(false, "Invalid user key size. (16, 24 or 32 bytes allowed)");
			}

			if(keySchedule.length != rounds*16) {
				// Never omit this check, so use assert(false).
				assert(false, "Invalid key schedule size. Should be 'rounds*16' .");
			}

			asm @nogc nothrow {
				
				// pointer to key schedule: RDI
				// user key length: RDX
				// pointer to user key:	RSI

				mov RDI, keySchedule+8;	// pointer to key schedule
				mov RDX, userKey+0;	// length of user key
				mov RSI, userKey+8; // pointer to user key
				
				
				movdqu XMM0, [RSI];		// user key (first 16 bytes)
				movdqu [RDI], XMM0;
				add	RDI, 0x10;			// key addr
				//	movl %edx, 480(KEYP)
				pxor XMM4, XMM4;		// xmm4 is assumed 0 in _key_expansion_x
				
				// branch depending on user key length
				cmp DL, 24;				// len == 192 bits
				jb _enc_key128;
				je _enc_key192;
				
				// 256 bit
				movdqu XMM2, [RSI+0x10];		// second part of user key (bytes 16...31)
				movdqu [RDI], XMM2;
				add RDI, 0x10;
				aeskeygenassist XMM1, XMM2, 0x1;	// round 1
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x1;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x2;	// round 2
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x2;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x4;	// round 3
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x4;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x8;	// round 4
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x8;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x10;	// round 5
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x10;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x20;	// round 6
				call _key_expansion_256a;
				aeskeygenassist XMM1, XMM0, 0x20;
				call _key_expansion_256b;
				aeskeygenassist XMM1, XMM2, 0x40;	// round 7
				call _key_expansion_256a;
				jmp _end;
				
				// 192 bit
			_enc_key192:
				movq XMM2, [RSI+0x10];				// second part of user key (bytes 16...23)
				aeskeygenassist XMM1, XMM2, 0x1;	// round 1
				call _key_expansion_192a;
				aeskeygenassist XMM1, XMM2, 0x2;	// round 2
				call _key_expansion_192b;
				aeskeygenassist XMM1, XMM2, 0x4;	// round 3
				call _key_expansion_192a;
				aeskeygenassist XMM1, XMM2, 0x8;	// round 4
				call _key_expansion_192b;
				aeskeygenassist XMM1, XMM2, 0x10;	// round 5
				call _key_expansion_192a;
				aeskeygenassist XMM1, XMM2, 0x20;	// round 6
				call _key_expansion_192b;
				aeskeygenassist XMM1, XMM2, 0x40;	// round 7
				call _key_expansion_192a;
				aeskeygenassist XMM1, XMM2, 0x80;	// round 8
				call _key_expansion_192b;
				jmp _end;

				// 128 bit
			_enc_key128:
				aeskeygenassist XMM1, XMM0, 0x1;	// round 1
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x2;	// round 2
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x4;	// round 3
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x8;	// round 4
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x10;	// round 5
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x20;	// round 6
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x40;	// round 7
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x80;	// round 8
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x1b;	// round 9
				call _key_expansion_128;
				aeskeygenassist XMM1, XMM0, 0x36;	// round 10
				call _key_expansion_128;
				jmp _end;
				
				align 4;
			_key_expansion_128:;
			_key_expansion_256a:
				pshufd XMM1, XMM1, 0b11111111;
				shufps XMM4, XMM0, 0b00010000;
				pxor XMM0, XMM4;
				shufps XMM4, XMM0, 0b10001100;
				pxor XMM0, XMM4;
				pxor XMM0, XMM1;
				movdqu [RDI], XMM0;
				add RDI, 0x10;
				ret;
				
				align 4;
			_key_expansion_192a:
				pshufd XMM1, XMM1, 0b01010101;
				shufps XMM4, XMM0, 0b00010000;
				pxor XMM0, XMM4;
				shufps XMM4, XMM0, 0b10001100;
				pxor XMM0, XMM4;
				pxor XMM0, XMM1;
				
				movdqu XMM5, XMM2;
				movdqu XMM6, XMM2;
				pslldq XMM5, 4;
				pshufd XMM3, XMM0, 0b11111111;
				pxor XMM2, XMM3;
				pxor XMM2, XMM5;
				
				movdqu XMM1, XMM0;
				shufps XMM6, XMM0, 0b01000100;
				movdqu [RDI], XMM6;
				shufps XMM1, XMM2, 0b01001110;
				movdqu [RDI+0x10], XMM1;
				add RDI, 0x20;
				ret;
				
				
				align 4;
			_key_expansion_192b:
				pshufd XMM1, XMM1, 0b01010101;
				shufps XMM4, XMM0, 0b00010000;
				pxor XMM0, XMM4;
				shufps XMM4, XMM0, 0b10001100;
				pxor XMM0, XMM4;
				pxor XMM0, XMM1;
				
				movdqu XMM5, XMM2;
				pslldq XMM5, 4;
				pshufd XMM3, XMM0, 0b11111111;
				pxor XMM2, XMM3;
				pxor XMM2, XMM5;
				
				movdqu [RDI], XMM0;
				add RDI, 0x10;
				ret;
				
				align 4;
			_key_expansion_256b:
				pshufd XMM1, XMM1, 0b10101010;
				shufps XMM4, XMM2, 0b00010000;
				pxor XMM2, XMM4;
				shufps XMM4, XMM2, 0b10001100;
				pxor XMM2, XMM4;
				pxor XMM2, XMM1;
				movdqu [RDI], XMM2;
				add RDI, 0x10;
				ret;
				
			_end:;
				
			}
			
			if(!forEncryption) {
				asm @nogc nothrow {
					
					// This section generates the decryption key schedule by
					// calling AESIMC on all except the first and the last round key.
					// Note that this way, round keys will be reverse ordered in memory.
					// TODO: Reorder round keys such that they are in order. Requires adaption of decryption function too.
					
					mov RCX, rounds;		// set counter to number of rounds - 2
					sub RCX, 2;
					
					mov RDI, keySchedule+8;			// pointer to key output buffer
					add RDI, 0x10;			// dont modify first key
					
				_loopDecKey:
					movdqu XMM0, [RDI];		// load
					aesimc XMM0, XMM0;		// invert
					movdqu [RDI], XMM0;		// store
					
					add RDI, 0x10;			// increment pointer
					
					loop _loopDecKey;		// loop rounds-2 times
				}
			}
			
			
			asm @nogc nothrow {
				// clear registers to ensure that no key data is at unexpected locations
				pxor XMM0, XMM0;
				pxor XMM1, XMM1;
				pxor XMM2, XMM2;
				pxor XMM3, XMM3;
				pxor XMM4, XMM4;
				pxor XMM5, XMM5;
				pxor XMM6, XMM6;
			}
		}

		private {
			ubyte[16*15] workingKey; // space for 15 round keys
			ubyte rounds;
			bool forEncryption;
			bool initialized;
		}

		/// Asserts that SSE2 and AES instructions are supported.
		/// Throws: an AssertionException if CPU does not support required instructions.
		private static void assertHardwareSupport() nothrow @nogc {
			assert(aes, "AES not supported by CPU!");
			assert(sse2, "SSE2 not supported by CPU!");
		};

		
		//		~this() {
		//			// wipe working key
		//			workingKey[] = 0;
		//		}

		
		//
		// unittests
		//

		
		/// Test AES128-128 encryption key schedule with test vectors from FIPS 197
		unittest {
			immutable ubyte[] key = cast(immutable ubyte[])x"000102030405060708090a0b0c0d0e0f";
			
			string expectedKeySchedule = x"
					000102030405060708090a0b0c0d0e0f
					d6aa74fdd2af72fadaa678f1d6ab76fe
					b692cf0b643dbdf1be9bc5006830b3fe
					b6ff744ed2c2c9bf6c590cbf0469bf41
					47f7f7bc95353e03f96c32bcfd058dfd
					3caaa3e8a99f9deb50f3af57adf622aa
					5e390f7df7a69296a7553dc10aa31f6b
					14f9701ae35fe28c440adf4d4ea9c026
					47438735a41c65b9e016baf4aebf7ad2
					549932d1f08557681093ed9cbe2c974e
					13111d7fe3944a17f307a78b4d2b30c5
					";
			
			ubyte[11*16] keySchedule;
			AES_KEY_EXPANSION(key, keySchedule, true);
			assert(keySchedule == expectedKeySchedule, "128 bit AES_KEY_EXPANSION failed");
		}
		
		/// Test AES128-128 decryption key schedule with test vectors from FIPS 197
		unittest {
			immutable ubyte[] key = cast(immutable ubyte[])x"000102030405060708090a0b0c0d0e0f";
			
			// Reverse order compared to FIPS 197 test vectors.
			string expectedKeySchedule = x"
							000102030405060708090a0b0c0d0e0f
							8c56dff0825dd3f9805ad3fc8659d7fd
							a0db02992286d160a2dc029c2485d561
							c7c6e391e54032f1479c306d6319e50c
							a8a2f5044de2c7f50a7ef79869671294
							2ec410276326d7d26958204a003f32de
							72e3098d11c5de5f789dfe1578a2cccb
							8d82fc749c47222be4dadc3e9c7810f5
							1362a4638f2586486bff5a76f7874a83
							13aa29be9c8faff6f770f58000f7bf03
							13111d7fe3944a17f307a78b4d2b30c5
							";
			
			ubyte[11*16] keySchedule;
			AES_KEY_EXPANSION(key, keySchedule, false);
			
			assert(keySchedule == expectedKeySchedule, "128 bit AES_KEY_EXPANSION (decryption) failed");
		}
		
		
		/// Test AES128-192 encryption key schedule with test vectors from FIPS 197
		unittest {
			immutable ubyte[] key = cast(immutable ubyte[])x"000102030405060708090a0b0c0d0e0f1011121314151617";
			assert(key.length == 24);
			string expectedKeySchedule = x"
							000102030405060708090a0b0c0d0e0f
							10111213141516175846f2f95c43f4fe
							544afef55847f0fa4856e2e95c43f4fe
							40f949b31cbabd4d48f043b810b7b342

                            58e151ab04a2a5557effb5416245080c
							2ab54bb43a02f8f662e3a95d66410c08
							f501857297448d7ebdf1c6ca87f33e3c
							e510976183519b6934157c9ea351f1e0

							1ea0372a995309167c439e77ff12051e
							dd7e0e887e2fff68608fc842f9dcc154
							859f5f237a8d5a3dc0c02952beefd63a
							de601e7827bcdf2ca223800fd8aeda32

							a4970a331a78dc09c418c271e3a41d5d
							";
			
			ubyte[13*16] keySchedule;
			AES_KEY_EXPANSION(key, keySchedule, true);
			
			assert(keySchedule == expectedKeySchedule, "192 bit AES_KEY_EXPANSION failed");
		}
		
		/// Test AES128-256 encryption key schedule with test vectors from FIPS 197
		unittest {
			immutable ubyte[] key = cast(immutable ubyte[])x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
			
			string expectedKeySchedule = x"
							000102030405060708090a0b0c0d0e0f
							101112131415161718191a1b1c1d1e1f
							a573c29fa176c498a97fce93a572c09c
							1651a8cd0244beda1a5da4c10640bade

							ae87dff00ff11b68a68ed5fb03fc1567
							6de1f1486fa54f9275f8eb5373b8518d
							c656827fc9a799176f294cec6cd5598b
							3de23a75524775e727bf9eb45407cf39

							0bdc905fc27b0948ad5245a4c1871c2f
							45f5a66017b2d387300d4d33640a820a
							7ccff71cbeb4fe5413e6bbf0d261a7df
							f01afafee7a82979d7a5644ab3afe640

							2541fe719bf500258813bbd55a721c0a
							4e5a6699a9f24fe07e572baacdf8cdea
							24fc79ccbf0979e9371ac23c6d68de36
							";
			
			ubyte[15*16] keySchedule;
			AES_KEY_EXPANSION(key, keySchedule, true);
			
			assert(keySchedule[] == expectedKeySchedule[], "256 bit AES_KEY_EXPANSION failed");
		}
	}

	/// Test AES encryption and decryption with different key sizes.
	@safe
	unittest {
		// test vectors from http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
		
		static string[] test_keys = [
			x"2b7e151628aed2a6abf7158809cf4f3c",
			x"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
		];
		
		static string[] test_plaintexts = [
			x"6bc1bee22e409f96e93d7e117393172a",
			x"6bc1bee22e409f96e93d7e117393172a",
			x"6bc1bee22e409f96e93d7e117393172a"
		];
		
		static string[] test_ciphertexts = [
			x"3ad77bb40d7a3660a89ecaf32466ef97",
			x"bd334f1d6e45f25ff712a214571fa5cc",
			x"f3eed1bdb5d2a03c064b5a7e3db181f8"
			
		];
		
		AESNIEngine t = new AESNIEngine();
		
		blockCipherTest(t, test_keys, test_plaintexts, test_ciphertexts);
		
	}
}