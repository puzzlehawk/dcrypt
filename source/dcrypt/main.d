module dcrypt.main;

import std.stdio;
import std.conv;
import dcrypt.crypto.engines.rc4;
import dcrypt.crypto.streamcipher;
import dcrypt.util.encoders.hex;
import dcrypt.crypto.digest;
import dcrypt.crypto.digests.sha1;
import dcrypt.crypto.digests.sha2;
import dcrypt.crypto.digests.sha3;

import dcrypt.crypto.generators.pkcs5s2;

import dcrypt.crypto.blockcipher;
import dcrypt.crypto.engines.aes;
import dcrypt.crypto.engines.aesni;
import dcrypt.crypto.engines.aesopenssl;
import dcrypt.crypto.engines.rijndael;
import dcrypt.crypto.engines.rc6;
import dcrypt.crypto.engines.serpent;
import dcrypt.crypto.modes.cbc;
import dcrypt.crypto.modes.ctr;

import dcrypt.crypto.modes.gcm.gcm;

import dcrypt.crypto.engines.poly1305_chacha;

import dcrypt.benchmark.Benchmark;
import dcrypt.benchmark.DigestBenchmark;
import dcrypt.benchmark.BlockCipherBenchmark;
import dcrypt.benchmark.AEADCipherBenchmark;

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

		Benchmark.doCurved25519Benchmark(512);
		Benchmark.doEd25519Benchmark(512);
				
	}
} else {
//	public void main(string[] args) {
//	}
}
