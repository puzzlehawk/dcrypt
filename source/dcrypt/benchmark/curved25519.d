module dcrypt.benchmark.curved25519;

import dcrypt.benchmark.Benchmark;
import dcrypt.crypto.ecc.curve25519;
import dcrypt.crypto.ecc.ed25519;
import std.conv;

public class Curved25519Benchmark: Benchmark {

	this (){
	}
	
	@property
	static string[] header() {
		return ["curved25519", "operations/s"];
	}
	
	override string[] benchmark(ulong length) {
		StopWatch sw;

		ubyte[32] secretKey;
		secretKey[] = 0x55;
		
		sw.start();
		foreach(size_t i; 0 .. length) {
			secretKey = curve25519_scalarmult(secretKey);
		}
		sw.stop();
		
		
		ulong speed = cast(ulong) (1e9 * length / sw.peek().nsecs());
		return ["key-gen", text(speed)];
	}
	
}

public class Ed25519Benchmark: Benchmark {
	
	this (){
	}
	
	@property
	static string[] header() {
		return ["ed25519", "sign/s", "verify/s"];
	}
	
	override string[] benchmark(ulong length) {
		StopWatch sw;
		
		ubyte[32] secretKey;
		ubyte[32] msg;
		secretKey[] = 0x55;

		ubyte[64] buf;
		immutable ubyte[32] pk = secret_to_public(secretKey);

		// signature
		sw.start();
		foreach(size_t i; 0 .. length) {
			buf = sign(buf, secretKey, pk);
		}
		sw.stop();
		ulong speedSign = cast(ulong) (1e9 * length / sw.peek().nsecs());

		// verification
		sw.start();
		foreach(size_t i; 0 .. length) {
			bool v = verify(buf, msg, pk);
		}
		sw.stop();
		ulong speedVerify = cast(ulong) (1e9 * length / sw.peek().nsecs());


		return ["", text(speedSign), text(speedVerify)];
	}
	
}