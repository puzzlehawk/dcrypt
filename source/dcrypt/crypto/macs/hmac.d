module dcrypt.crypto.macs.hmac;

public import dcrypt.crypto.macs.mac;
import dcrypt.crypto.digest;

// TODO optimize reset()


@safe
public struct HMac(D) if(isDigest!D) {

	
public:

	public enum name = D.name ~ "/HMAC";
	public enum macSize = D.digestLength;

	
	/**
	 * Params: keyParam = the HMac key
	 */
	@safe
	void init(in ubyte[] macKey)
	in {
		assert(macKey !is null, "mac key can't be null!");
	}
	body {
		key = macKey.dup;

		// replace key by hash(key) if key length > block length of hash function
		if(key.length > digest.blockSize) {
			digest.reset();
			digest.update(key);
			uint len = digest.doFinal(key);
			key.length = len;
		}

		// prepare those digests for faster PBKDF2
		//		initDigest(iPaddedDigest, key, ipadByte);
		//		initDigest(oPaddedDigest, key, opadByte);

		iPad = genPadBytes(key, ipadByte, digest.blockSize);
		oPad = genPadBytes(key, opadByte, digest.blockSize);

		reset();
	}

	
	/**
	 * update the MAC with a single byte.
	 *
	 * Params:
	 *	input	=	the input byte to be entered.
	 */
	@safe
	public void update(ubyte input) nothrow @nogc
	in{
		assert(initialized, "HMac not initialized! Call init() first");
	}
	body {
		digest.update(input);
	}

	/**
	 * update the MAC with a block of bytes.
	 *
	 * Params:
	 * input = the ubyte slice containing the data.
	 */
	@safe
	void update(in ubyte[] input) nothrow @nogc
	in {
		assert(initialized, "HMac not initialized! Call init() first");
	}
	body{
		digest.update(input);
	}

	/**
	 * close the MAC, producing the final MAC value. The doFinal
	 * call leaves the MAC reset(). */
	@safe
	uint doFinal(ubyte[] output) nothrow @nogc {
		digest.doFinal(iHash);
		digest.update(oPad);
		//		initDigest(digest, key, opadByte);
		//		digest = oPaddedDigest.dup;
		digest.update(iHash);

		digest.doFinal(output);
		
		reset();
		
		return macSize;
	}
	
	
	/**
	 * reset the digest back to it's initial state.
	 */
	@safe
	public void reset() nothrow @nogc
	in{
		assert(key !is null || key.length == 0, "HMac not initialized!");
	}
	body {
		digest.reset();
		digest.update(iPad);

		initialized = true;
	}
	
private:
	D digest;
	private ubyte[D.digestLength] iHash;
	//	Digest iPaddedDigest, oPaddedDigest;
	ubyte[] key;
	ubyte[] iPad, oPad;
	bool initialized = false;

	
	enum ubyte opadByte = 0x5c;
	enum ubyte ipadByte = 0x36;
	//	
	//	/**
	//	 init the digest with key and padding
	//	 */
	//	void initDigest(Digest d, in ubyte[] key, in ubyte padByte) nothrow {
	////		ubyte[] paddedKey = key.dup;
	////		paddedKey[] ^= padByte;
	//		ubyte[] paddedKey = genPadBytes(key, padByte, d.blockSize());
	//		d.reset();
	//		d.update(paddedKey);
	////		uint blockSize = d.blockSize();
	////		size_t padLength = blockSize - (key.length%blockSize);
	////		
	////		ubyte[] pad = new ubyte[padLength];
	////		pad[] = padByte;
	////		d.update(pad);
	//	}

	ubyte[] genPadBytes(in ubyte[] key, in ubyte padByte, in uint blockSize) nothrow {
		ubyte[] paddedKey = key.dup;
		paddedKey.length += blockSize - (key.length%blockSize);
		paddedKey[] ^= padByte;
		return paddedKey;
	}
}


/// test vectors from http://tools.ietf.org/html/rfc4231
///
/// test case: 1 2 3 4 6 7 (without 5)
unittest {
	import dcrypt.crypto.digests.sha2;
	import dcrypt.crypto.digests.sha2;
	import dcrypt.util.encoders.hex;
	import dcrypt.crypto.params.keyparameter;
	import std.stdio;
	
	// test vectors from http://tools.ietf.org/html/rfc4231
	
	// test case: 1 2 3 4 6 7 (without 5)
	
	string[] keys = ["0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		"4a656665",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0102030405060708090a0b0c0d0e0f10111213141516171819",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",];
	
	string[] data = ["4869205468657265",
		"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
		"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
	];
	
	string[] macsSHA256 = [
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"];
	
	string[] macsSHA512 = [
		"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
		"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
		"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
		"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"];
	
	
	testHMac!(SHA256)(keys, data, macsSHA256);
	testHMac!(SHA512)(keys, data, macsSHA512);
}

version(unittest) {

	// unittest helper functions

	import dcrypt.util.encoders.hex;
	import dcrypt.crypto.params.keyparameter;
	import std.conv: text;
	
	/// Tests Digest d with given input data and reference hashes.
	///
	/// Params:
	/// hexData	= hex encoded data
	/// hexHashes	= expected hashes
	///
	/// Throws:
	/// AssertionError	if generated hash != expected hash
	@safe
	public void testHMac(Digest)(string[] hexKeys, string[] hexData, string[] hexHashes) 
	if(isDigest!Digest) {
		foreach (i; 0 .. hexData.length)
		{
			HMac!Digest mac;
			
			ubyte[] key = Hex.decode(hexKeys[i]);
			ubyte[] data = Hex.decode(hexData[i]);
			ubyte[] expectedHash = Hex.decode(hexHashes[i]);
			
			mac.init(key);
			
			mac.update(data);
			
			//            ubyte[] hash = mac.doFinal();
			ubyte[] hash = new ubyte[mac.macSize];
			mac.doFinal(hash);
			
			assert(hash == expectedHash, text(mac.name," failed: ",Hex.encode(hash), " != ", hexHashes[i]));
		}
	}
}