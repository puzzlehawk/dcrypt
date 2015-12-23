module dcrypt.benchmark.sphincs256;

import dcrypt.benchmark.Benchmark;
import dcrypt.pqc.sphincs.sphincs256: Sphincs256;

public class Sphincs256Benchmark: Benchmark {
	
	this (){
	}
	
	@property
	static string[] header() {
		return ["sphincs256", "sign/s", "verify/s"];
	}
	
	override string[] benchmark(ulong length) {
		StopWatch sw;

		ubyte[Sphincs256.secretkey_bytes] sk;
		ubyte[Sphincs256.publickey_bytes] pk = Sphincs256.pubkey(sk);

		ubyte[Sphincs256.sig_bytes] sig;
		ubyte[100] msg;

		// signature
		sw.reset();
		sw.start();
		foreach(size_t i; 0 .. length) {
			sig = Sphincs256.sign_detached(msg, sk);
		}
		sw.stop();
		auto speedSign = (1.0e9 * length / sw.peek().nsecs());

		// verification
		sw.reset();
		sw.start();
		foreach(size_t i; 0 .. length) {
			bool v = Sphincs256.verify(msg, sig, pk);
			assert(v);
		}
		sw.stop();
		auto speedVerify = (1.0e9 * length / sw.peek().nsecs());


		return ["", numberFormat(speedSign), numberFormat(speedVerify)];
	}
	
}