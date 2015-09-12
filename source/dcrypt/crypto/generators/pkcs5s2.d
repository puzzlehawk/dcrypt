module dcrypt.crypto.generators.pkcs5s2;

import dcrypt.crypto.macs.hmac;
import dcrypt.crypto.digest;
import dcrypt.exceptions;
import std.datetime;
import std.algorithm: min;
import std.exception: enforce;



unittest {
	
	// test vectors from http://tools.ietf.org/html/rfc6070
	
	import dcrypt.crypto.digests.sha1;
	import dcrypt.util.encoders.hex;
	import std.datetime: StopWatch;

	PBKDF2!SHA1 gen;
	
	const ubyte[] pass = cast(const ubyte[]) "password";
	const ubyte[] salt = cast(const ubyte[]) "salt";

	ubyte[20] key;

	gen.start(pass, salt, 1);
	gen.nextBytes(key);
	assert(key == x"0c60c80f961f0e71f3a9b524af6012062fe037a6", "PKCS5S2 PBKDF2 failed!");

	gen.start(pass, salt, 2);
	gen.nextBytes(key);
	assert(key == x"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "PKCS5S2 PBKDF2 failed!");

	gen.start(pass, salt, 4096);
	gen.nextBytes(key);
	assert(key == x"4b007901b765489abead49d926f721d065a429c1", "PKCS5S2 PBKDF2 failed!");
	
	uint iterTime = 10; // milli seconds
	gen.start(pass, salt, 0, iterTime);
	
	StopWatch sw;
	sw.start();
	gen.nextBytes(key);
	sw.stop();
	
	assert(sw.peek().msecs() >= iterTime, "PBKDF2 terminated too fast");
	//assert(gen.getIterationCount() > 0, "failed to do any iterations in given time");
}


/**
 * Generator for PBE derived keys and ivs as defined by PKCS 5 V2.0 Scheme 2.
 * This generator uses a SHA-1 HMac as the calculation function.
 * 
 * The document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * RSA's PKCS5 Page</a>
 */
@safe
public struct PBKDF2(D) if(isDigest!D)
{

	enum name = "PBKDF2-"~(HMac!D).name;

	private {
		const (ubyte)[] salt;
		ulong iterationCount;
		ulong iterTime;

		HMac!D hMac;
		ubyte[4]  counter;
		ubyte[hMac.macSize] state;
		uint stateOff = state.length;

		bool initialized = false;
	}

	public void start(in ubyte[] password, in ubyte[] salt, uint iterationCount, uint iterTime = 0) 
	{
		enforce(iterTime > 0 || iterationCount > 0, "either iterationCount or iterTime have to be > 0!");

		this.salt = salt;
		this.iterationCount = iterationCount;
		this.iterTime = iterTime;

		hMac.start(password);

		counter[] = 0;
		stateOff = state.length;
		state[] = 0;

		initialized = true;
	}

	public void reset() {
		counter[] = 0;
		stateOff = state.length;
		state[] = 0;
		hMac.reset();
	}

	public void nextBytes(ubyte[] output)
	in {
		assert(initialized, name~" not initialized.");
	} body {
		while(output.length > 0) {
			if(stateOff == state.length) {
				incCounter();
				if(iterationCount > 0) {
					state = genBlock(salt, counter, iterationCount);
				} else {
					assert(iterTime > 0);
					state = genBlock(salt, counter, 0, iterTime);
				}

				stateOff = 0;
			}
			
			size_t len = min(state.length-stateOff, output.length);
			output[0..len] = state[stateOff..stateOff+len];
			output = output[len..$];
			stateOff += len;
			
			assert(stateOff <= state.length);
		}
	}

private:
	
	/// 
	/// msTime = Time in milliseconds.
	ubyte[hMac.macSize] genBlock(in ubyte[] salt, in ubyte[] counter, ulong iterCount, ulong iterTime = 0)
	in {
		assert(initialized, name~" not initialized.");
		if(iterCount == 0) {
			assert(iterTime > 0, "iterTime must be > 0.");
		}
	}
	body {
		ubyte[D.digestLength] state, output;

		if (salt != null)
		{
			hMac.put(salt);
		}

		hMac.put(counter);
		hMac.finish(state);

		output[] = state[];

		if(iterCount > 0) { 
			foreach (count; 1..iterCount)
			{
				hMac.put(state);
				hMac.finish(state);
				
				assert(output.length >= state.length);
				output[] ^= state[];
			}
		} else {
			// run for given amount of time
			StopWatch sw;
			sw.start();
			uint count = 0;
			do {
				hMac.put(state);
				hMac.finish(state);
				
				assert(output.length >= state.length);
				output[] ^= state[];
				
				++count;
			} while(sw.peek().msecs() < iterTime);
			
			iterationCount = count;
		}

		return output;
	}

	
	//	ubyte[] generateDerivedKey(uint dkLen)
	//	{
	//		enum     hLen = hMac.macSize;
	//		size_t     l = (dkLen + hLen - 1) / hLen;
	//		counter[] = 0;
	//
	//		ubyte[]  outBytes = new ubyte[l * hLen];
	//
	//		//hMac.start(password);
	//
	//		nextBytes(outBytes);
	//
	//		return outBytes;
	//	}

	

	nothrow @nogc
	private void incCounter() {uint pos = 3;
		while (++counter[pos] == 0)
		{
			--pos;
		}
	}
}
