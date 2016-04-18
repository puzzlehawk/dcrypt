module dcrypt.keyderivation.pbkdf2;

import dcrypt.macs.hmac;
import dcrypt.digest;
import dcrypt.exceptions;
import dcrypt.bitmanip;
import std.datetime;
import std.algorithm: min;



unittest {
	
	// test vectors from http://tools.ietf.org/html/rfc6070
	
	import dcrypt.digests.sha1;
	import dcrypt.encoders.hex;
	import std.datetime: StopWatch;

	const ubyte[] pass = cast(const ubyte[]) "password";
	const ubyte[] salt = cast(const ubyte[]) "salt";

	ubyte[] key = new ubyte[20];

	pbkdf2!SHA1(key, pass, salt, 1);
	assert(key == x"0c60c80f961f0e71f3a9b524af6012062fe037a6", "PKCS5S2 PBKDF2 failed!");

	pbkdf2!SHA1(key, pass, salt, 2);
	assert(key == x"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "PKCS5S2 PBKDF2 failed!");

	pbkdf2!SHA1(key, pass, salt, 4096);
	assert(key == x"4b007901b765489abead49d926f721d065a429c1", "PKCS5S2 PBKDF2 failed!");

	key.length = 25;
	pbkdf2!SHA1(key, cast(const ubyte[])"passwordPASSWORDpassword", cast(const ubyte[])"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096);
	assert(key == x"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038 ", "PKCS5S2 PBKDF2 failed!");

	//	uint iterTime = 10; // milli seconds
	//	gen.start(pass, salt, 0, iterTime);
	//	
	//	StopWatch sw;
	//	sw.start();
	//	gen.nextBytes(key);
	//	sw.stop();
	//	
	//	assert(sw.peek().msecs() >= iterTime, "PBKDF2 terminated too fast");
	//assert(gen.getIterationCount() > 0, "failed to do any iterations in given time");
}

/// Derive a key from a password and a salt using multiple iterations.
/// 
/// Params:
/// derivedKey = Output buffer for derived key. Slice will be filled.
/// password = Password.
/// salt = Salt.
/// iterationCount = Number of iterations.
@safe
public void pbkdf2(D)(ubyte[] derivedKey, in ubyte[] password, in ubyte[] salt, uint iterationCount) if(isDigest!D) {

	HMac!D hMac;
	ubyte[hMac.macSize] state;
	uint counter = 0;

	hMac.start(password);

	// fill the output buffer
	while(derivedKey.length > 0) {
		++counter;
		state = genBlock(hMac, salt, counter, iterationCount);

		size_t len = min(state.length, derivedKey.length);
		derivedKey[0..len] = state[0..len];
		derivedKey = derivedKey[len..$];
	}
}


private ubyte[M.macSize] genBlock(M)(ref M hMac, in ubyte[] salt, in uint counter, ulong iterCount)
	if(isMAC!M)
	in {
		assert(iterCount > 0, "iterCount can't be 0.");
}
body {
	ubyte[M.macSize] state, output;
	
	if (salt != null)
	{
		hMac.put(salt);
	}
	
	hMac.put(toBigEndian(counter));
	hMac.finish(state);
	
	output[] = state[];
	
	
	foreach (count; 1..iterCount)
	{
		hMac.put(state);
		hMac.finish(state);
		output[] ^= state[];
	}

	return output;
}