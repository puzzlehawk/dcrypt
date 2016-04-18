module dcrypt.main;

import std.stdio;
import std.conv;
import dcrypt.streamcipher.streamcipher;
import dcrypt.encoders.hex;
import dcrypt.digest;
import dcrypt.digests.sha1;
import dcrypt.digests.sha2;
import dcrypt.digests.sha3;
import dcrypt.digests.blake;

import dcrypt.crypto.pbe.pbkdf2;

import dcrypt.blockcipher.blockcipher;
import dcrypt.blockcipher.aes;
import dcrypt.blockcipher.aesni;
import dcrypt.blockcipher.aesopenssl;
import dcrypt.blockcipher.rijndael;
import dcrypt.blockcipher.rc6;
import dcrypt.blockcipher.serpent;
import dcrypt.crypto.modes.cbc;
import dcrypt.crypto.modes.ctr;

import dcrypt.crypto.modes.gcm.gcm;

import dcrypt.streamcipher.poly1305_chacha;

import dcrypt.benchmark.Benchmark;
import dcrypt.benchmark.DigestBenchmark;
import dcrypt.benchmark.BlockCipherBenchmark;
import dcrypt.benchmark.AEADCipherBenchmark;

import dcrypt.random.random;

version (Benchmark) {

	public void main(string[] args) {
		benchmark();
	}

	/// run various benchmarks
	void benchmark() {
		ulong len = 1<<18;

		debug {
			writeln("\n--- BENCHMARK (slow debug mode)---\n");
		} else {
			writeln("\n--- BENCHMARK ---\n");
		}
		
		Digest[] digests;
		digests ~= new SHA1Digest();
		digests ~= new SHA256Digest();
		digests ~= new SHA384Digest();
		digests ~= new SHA512Digest();
		digests ~= new SHA3_224Digest;
		digests ~= new SHA3_256Digest;
		digests ~= new SHA3_384Digest;
		digests ~= new SHA3_512Digest;
		digests ~= new Blake224Digest;
		digests ~= new Blake256Digest;
		digests ~= new Blake384Digest;
		digests ~= new Blake512Digest;
		
		Benchmark.doBenchmark(len, digests);
		
		
		BlockCipher[] ciphers;
		ciphers ~=	new AESEngine();
		ciphers ~=	new AESNIEngine();
		ciphers ~=	new AESOpenSSLEngine();
		ciphers ~=	new CBCBlockCipher!AES;
		ciphers ~=	new CTRBlockCipher!AES;
		ciphers ~=	new CBCBlockCipher!AESNI;
		ciphers ~=	new CTRBlockCipher!AESNI;
		ciphers ~=	new Rijndael128Engine;
		ciphers ~=	new Rijndael256Engine;
		ciphers ~=	new RC6Engine();
		ciphers ~=	new SerpentEngine();
		ciphers ~=	new CBCBlockCipher!Serpent; 
		ciphers ~=	new CTRBlockCipher!Serpent;
		
		Benchmark.doBenchmark(len, ciphers);
		
		AEADCipher[] aeadCiphers = [
			new GCMCipher(new AESEngine()),
			new GCMCipher(new AESNIEngine()),
			new GCMCipher(new SerpentEngine())
		];
		//aeadCiphers ~=	new Poly1305ChaChaEngine;
		
		Benchmark.doBenchmark(len, aeadCiphers);

		Benchmark.doCurved25519Benchmark(1024);
		Benchmark.doEd25519Benchmark(1024);
		Benchmark.doSphincs256Benchmark(1);
				
	}
} else {
}
