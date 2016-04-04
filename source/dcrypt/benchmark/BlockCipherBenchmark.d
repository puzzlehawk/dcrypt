module dcrypt.benchmark.BlockCipherBenchmark;

import dcrypt.benchmark.Benchmark;
import dcrypt.crypto.blockcipher;
import std.conv;
import std.algorithm: swap;

public class BlockCipherBenchmark: Benchmark {
	
	private BlockCipher cipher;
	 
	this (BlockCipher c){
		cipher = c;
	}

	@property
	static string[] header() {
		return ["algorithm", "encrypt MB/s", "decrypt MB/s"];
	}
	
	override string[] benchmark(ulong length) {

		cipher.start(true, new ubyte[16], new ubyte[16]);
		
		double encrSpeed = getSpeed(length)*1e-6;
		
		cipher.start(false, new ubyte[16], new ubyte[16]);
		
		double decrSpeed = getSpeed(length)*1e-6;

		return [cipher.name, numberFormat(encrSpeed), numberFormat(decrSpeed)];
	}
	
	private double getSpeed(ulong length) {
		ubyte[] blockA = new ubyte[cipher.blockSize()];
		ubyte[] blockB = new ubyte[cipher.blockSize()];
		StopWatch sw;
		sw.reset();
		sw.start();
		foreach(size_t i; 0 .. length/blockA.length) {
			
			cipher.processBlock(blockA, blockB);
			swap(blockA, blockB);
		}
		sw.stop();
		
		double speed = 1e9 * length / sw.peek().nsecs();
		return speed;
	}
	
}
