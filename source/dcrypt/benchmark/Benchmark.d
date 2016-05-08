module dcrypt.benchmark.Benchmark;

public import std.datetime: StopWatch;
import std.conv;
import dcrypt.benchmark.BlockCipherBenchmark;
import dcrypt.benchmark.AEADCipherBenchmark;
import dcrypt.benchmark.DigestBenchmark;
import dcrypt.blockcipher.blockcipher;
import dcrypt.digest;
import dcrypt.aead.aead;

import std.stdio;
import std.string;

public class Benchmark {

	
	/// Params:
	/// length	=	the length of benchmark in bytes
	/// ciphers	=	BlockCiphers to test
	public static void doBenchmark(ulong length, IBlockCipher[] ciphers...) {
		writeln();

		printTabbed(BlockCipherBenchmark.header);
		writeln();
		foreach(c; ciphers) {
			auto bench = new BlockCipherBenchmark(c);
			printTabbed(bench.benchmark(length));
			stdout.flush();
		}
	}

	public static void doBenchmark(ulong length, IAEADCipher[] ciphers...) {
		writeln();
		printTabbed(AEADCipherBenchmark.header);
		writeln();
		foreach(c; ciphers) {
			auto bench = new AEADCipherBenchmark(c);
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

	public static void doCurved25519Benchmark(ulong length) {
		import dcrypt.benchmark.curved25519;
		
		writeln();
		printTabbed(Curved25519Benchmark.header);
		writeln();
		auto bench = new Curved25519Benchmark;
		printTabbed(bench.benchmark(length));
		stdout.flush();
	}

	public static void doEd25519Benchmark(ulong length) {
		import dcrypt.benchmark.curved25519;
		
		writeln();
		printTabbed(Ed25519Benchmark.header);
		writeln();
		auto bench = new Ed25519Benchmark;
		printTabbed(bench.benchmark(length));
		stdout.flush();
	}

	public static void doSphincs256Benchmark(ulong length) {
		import dcrypt.benchmark.sphincs256;
		
		writeln();
		printTabbed(Sphincs256Benchmark.header);
		writeln();
		auto bench = new Sphincs256Benchmark;
		printTabbed(bench.benchmark(length));
		stdout.flush();
	}

	/// do the calculations, (compute hashes, encrypt data, ...)
	/// Params: length = length of benchmark (numbers of bytes to process)
	/// Returns: a string containing the benchmark results
	public abstract string[] benchmark(ulong length);

	@trusted
	static void printTabbed(string[] strs...) {
		writefln("%-(%-20s%)", strs);
	}

	public string numberFormat(double d) {
		return format("%10.2f", d);
	}
}