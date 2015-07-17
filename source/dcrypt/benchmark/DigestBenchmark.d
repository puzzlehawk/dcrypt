module dcrypt.benchmark.DigestBenchmark;

import dcrypt.benchmark.Benchmark;
import dcrypt.crypto.digest;
import std.conv;

public class DigestBenchmark: Benchmark {
	
	private Digest digest;
	private size_t length;
	
	this (Digest d){
		digest = d;
	}

	@property
	static string[] header() {
		return ["algorithm", "speed MB/s"];
	}
	
	override string[] benchmark(ulong length) {
		StopWatch sw;
		digest.start();
		ubyte[32] block;
		
		sw.start();
		foreach(size_t i; 0 .. length/block.length) {
			digest.put(block);
			this.length += block.length;
		}
		sw.stop();
		digest.doFinal();
		
		
		double speed = 1e9 * length / sw.peek().nsecs();
		speed *= 1e-6;
		return [digest.name, text(speed)];
	}
	
}