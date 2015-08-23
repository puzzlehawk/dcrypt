module dcrypt.benchmark.AEADCipherBenchmark;

import dcrypt.benchmark.Benchmark;
import dcrypt.crypto.modes.aead;
import std.conv;
import std.algorithm: swap;

public class AEADCipherBenchmark: Benchmark {
	
	private AEADCipher cipher;
	 
	this (AEADCipher c){
		cipher = c;
	}

	@property
	static string[] header() {
		return ["algorithm", "AAD MB/s", "encrypt MB/s", "decrypt MB/s"];
	}

	override string[] benchmark(ulong length) {

		cipher.start(true, new ubyte[16], new ubyte[16]);


		double aadSpeed = getSpeed(length)*1e-6;

		double encrSpeed = getSpeed(length)*1e-6;

		cipher.start(true, new ubyte[16], new ubyte[16]);
		
		//double decrSpeed = getSpeed(length)*1e-6;

		return [cipher.name, text(aadSpeed), text(encrSpeed)];
			 //decrSpeed);
	}

	private double getAADSpeed(ulong length) {
		ubyte[64] blockA;
		StopWatch sw;
		sw.reset();
		sw.start();
		foreach(size_t i; 0 .. length/blockA.length) {
			cipher.processAADBytes(blockA);
		}
		sw.stop();
		
		double speed = 1e9 * length / sw.peek().nsecs();
		return speed;
	}
	
	private double getSpeed(ulong length) {
		ubyte[64] blockA;
		ubyte[128] blockB;
		StopWatch sw;
		sw.reset();
		sw.start();
		foreach(size_t i; 0 .. length/blockA.length) {
			cipher.processBytes(blockA, blockB);
		}
		cipher.doFinal(blockB);
		sw.stop();
		
		double speed = 1e9 * length / sw.peek().nsecs();
		return speed;
	}
	
}