module dcrypt.benchmark.Benchmark;

public import std.datetime: StopWatch;
import std.conv;
import dcrypt.benchmark.BlockCipherBenchmark;
import dcrypt.benchmark.AEADBlockCipherBenchmark;
import dcrypt.benchmark.DigestBenchmark;
//import dcrypt.benchmark.PKSS52ParameterGeneratorBenchmark;
import dcrypt.crypto.blockcipher;
import dcrypt.crypto.digest;
import dcrypt.crypto.modes.aead;

import std.stdio;

public class Benchmark {

	
	/// Params:
	/// length	=	the length of benchmark in bytes
	/// ciphers	=	BlockCiphers to test
	public static void doBenchmark(ulong length, BlockCipher[] ciphers...) {
		writeln();

		printTabbed(BlockCipherBenchmark.header);
		writeln();
		foreach(c; ciphers) {
			auto bench = new BlockCipherBenchmark(c);
			printTabbed(bench.benchmark(length));
			stdout.flush();
		}
	}

	public static void doBenchmark(ulong length, AEADBlockCipher[] ciphers...) {
		writeln();
		printTabbed(AEADBlockCipherBenchmark.header);
		writeln();
		foreach(c; ciphers) {
			auto bench = new AEADBlockCipherBenchmark(c);
			printTabbed(bench.benchmark(length));
			stdout.flush();
		}
	}
	
	public static void doBenchmark(ulong length, Digest[] digests...) {
		writeln();
		printTabbed(DigestBenchmark.header);
		writeln();
		foreach(d; digests) {
			auto bench = new DigestBenchmark(d);
			printTabbed(bench.benchmark(length));
			stdout.flush();
		}
	}

	//	public static void doBenchmark(T)(PKCS5S2ParametersGenerator!T[] gen...) {
	//		writeln();
	//		writeln(tabbed(padding, "algorithm", "iterations/s"));
	//		writeln();
	//		foreach(g; gen) {
	//			auto bench = new PKSS52ParameterGeneratorBenchmark(g);
	//			writeln(bench.benchmark(0));
	//			stdout.flush();
	//		}
	//	}

	/// do the calculations, (compute hashes, encrypt data, ...)
	/// Params: length = length of benchmark (numbers of bytes to process)
	/// Returns: a string containing the benchmark results
	public abstract string[] benchmark(ulong length);

	@trusted
	static void printTabbed(string[] strs...) {
		writefln("%-(%-20s%)", strs);
	}
}