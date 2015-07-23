module dcrypt.benchmark.curve25519;

import dcrypt.benchmark.Benchmark;
import dcrypt.crypto.ecc.curve25519;
import std.conv;

public class Curve25519Benchmark: Benchmark {

	this (){
	}
	
	@property
	static string[] header() {
		return ["curve25519", "operations/s"];
	}
	
	override string[] benchmark(ulong length) {
		StopWatch sw;

		ubyte[32] secretKey;
		secretKey[] = 0x55;
		
		sw.start();
		foreach(size_t i; 0 .. length) {
			secretKey = curve25519(secretKey);
		}
		sw.stop();
		
		
		ulong speed = cast(ulong) (1e9 * length / sw.peek().nsecs());
		return ["key-gen", text(speed)];
	}
	
}