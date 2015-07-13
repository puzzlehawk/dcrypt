//module dcrypt.benchmark.PKSS52ParameterGeneratorBenchmark;
//
//import dcrypt.benchmark.Benchmark;
//public import dcrypt.crypto.generators.pkcs5s2;
//import dcrypt.crypto.generators.pbe;
//import std.conv;
//
//public class PKSS52ParameterGeneratorBenchmark: Benchmark {
//	
//	private PKCS5S2ParametersGenerator gen;
//	
//	this (PKCS5S2ParametersGenerator generator){
//		gen = generator;
//	}
//
//	/**
//	 * Returns: string contining name of PBKDF and speed in iterations per second
//	 */
//	override string benchmark(ulong length) {
//
//		ubyte[] pass = PKCS5PasswordToBytes("password");
//		ubyte[] salt = PKCS5PasswordToBytes("salt");
//
//		gen.init(pass, salt, 0, 1000);
//		gen.generateDerivedParameters(256);
//		uint speed = gen.getIterationCount();
//
//		return tabbed(padding,
//			gen.getAlgorithmName(),
//			speed);
//	}
//	
//}