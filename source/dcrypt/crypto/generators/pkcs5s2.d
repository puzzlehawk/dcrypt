module dcrypt.crypto.generators.pkcs5s2;

public import dcrypt.crypto.generators.pbe;
import dcrypt.crypto.macs.hmac;
import dcrypt.crypto.digest;
import dcrypt.crypto.params.keyparameter;
import dcrypt.exceptions;
import std.datetime;

/**
 * Generator for PBE derived keys and ivs as defined by PKCS 5 V2.0 Scheme 2.
 * This generator uses a SHA-1 HMac as the calculation function.
 * 
 * The document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * RSA's PKCS5 Page</a>
 */
@safe
public class PKCS5S2ParametersGenerator(D) : PBEParametersGenerator
	if(isDigest!D)
{

	//	unittest {
	//		
	//		// test vectors from http://tools.ietf.org/html/rfc6070
	//		
	//		import dcrypt.crypto.digests.sha1;
	//		import dcrypt.crypto.params.keyparameter;
	//		import dcrypt.util.encoders.hex;
	//		import std.datetime: StopWatch;
	//		
	//		PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA1Digest());
	//		
	//		ubyte[] pass = PKCS5PasswordToBytes("password");
	//		ubyte[] salt = PKCS5PasswordToBytes("salt");
	//		
	//		gen.init(pass, salt, 2);
	//		KeyParameter key = gen.generateDerivedParameters(20*8);
	//		assert(key.getKey() == hexDecode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), "PKCS5S2 PBKDF2 failed!");
	//		
	//		uint iterTime = 10; // milli seconds
	//		gen.init(pass, salt, 0, iterTime);
	//		
	//		StopWatch sw;
	//		sw.start();
	//		key = gen.generateDerivedParameters(20*8);
	//		sw.stop();
	//		
	//		assert(sw.peek().msecs() >= iterTime, "PBKDF2 terminated too fast");
	//		assert(gen.getIterationCount() > 0, "failed to do any iterations in given time");
	//	}

	

	
	public override {
		/**
		 * Generate a key parameter derived from the password, salt, and iteration
		 * count we are currently initialised with.
		 *
		 * Params:
		 * keySize = the size of the key we want (in bits)
		 * Returns:
		 * 	a KeyParameter object.
		 */
		KeyParameter generateDerivedParameters(uint keySize)
		{
			keySize = keySize / 8;
			
			ubyte[]  dKey = generateDerivedKey(keySize);
			
			return new KeyParameter(dKey);
		}
		
		/**
		 * Generate a key with initialization vector parameter derived from
		 * the password, salt, and iteration count we are currently initialized
		 * with.
		 *
		 * Params:
		 * keySize	=	the size of the key we want (in bits)
		 * ivSize	=	the size of the iv we want (in bits)
		 * Returns: a ParametersWithIV object.
		 */
		ParametersWithIV generateDerivedParameters(uint keySize, uint ivSize)
		{
			keySize = keySize / 8;
			ivSize = ivSize / 8;
			
			ubyte[]  dKey = generateDerivedKey(keySize + ivSize);
			
			return new ParametersWithIV(dKey[0..keySize], dKey[keySize..keySize+ivSize]);
		}
		
		/**
		 * Generate a key parameter for use with a MAC derived from the password,
		 * salt, and iteration count we are currently initialized with.
		 *
		 * Params: keySize = the size of the key we want (in bits)
		 * Returns: a KeyParameter object.
		 */
		KeyParameter generateDerivedMacParameters(uint keySize)
		{
			return generateDerivedParameters(keySize);
		}
		
		string getAlgorithmName() {
			return "PBKDF2/"~hMac.name;
		}
	}

private:
	HMac!D hMac;
	ubyte[D.digestLength] state;

	
	void F(in ubyte[]  S, uint iterCount, in ubyte[]  iBuf, ubyte[]  output) 
	in {
		assert(output.length == state.length, "length of output buffer should be equal to state.length");
	}
	body {
		if (S != null)
		{
			hMac.put(S);
		}

		hMac.put(iBuf);
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
			} while(count < iterTime || (sw.peek().msecs() < iterTime));
			
			iterationCount = count;
		}
	}

	ubyte[] generateDerivedKey(uint dkLen)
	{
		enum     hLen = hMac.macSize;
		size_t     l = (dkLen + hLen - 1) / hLen;
		ubyte[4]  iBuf;
		ubyte[]  outBytes = new ubyte[l * hLen];
		uint     outPos = 0;

		hMac.start(password);

		foreach (i; 1..l+1)
		{
			// Increment the value in 'iBuf'
			uint pos = 3;
			while (++iBuf[pos] == 0)
			{
				--pos;
			}

			F(salt, iterationCount, iBuf, outBytes[outPos..outPos+hLen]);
			outPos += hLen;
		}
		return outBytes;
	}
}
