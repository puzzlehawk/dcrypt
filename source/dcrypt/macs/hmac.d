module dcrypt.macs.hmac;

public import dcrypt.macs.mac;
import dcrypt.digest;

import dcrypt.util: wipe;

// TODO optimize reset()

static {
	import dcrypt.digests.sha2: SHA256;

	static assert(isMAC!(HMac!SHA256), "HMac is not a valid MAC");
}

@safe
public struct HMac(D, uint blockSize = D.blockSize) if(isDigest!D) {

	
public:

	public enum name = "HMAC-"~D.name;
	public enum macSize = digestLength!D;

	/// Params: keyParam = The HMac key.
	@safe @nogc
	void start(in ubyte[] macKey = null)
	in {
		if(!initialized) {
			assert(macKey !is null, "No mac key!");
		}
	}
	body {
		if(macKey !is null) {
			iKey[] = ipadByte;
			oKey[] = opadByte;
			// replace key by hash(key) if key length > block length of hash function
			if(macKey.length > blockSize) {
				ubyte[blockSize] key;
				digest.start();
				digest.put(macKey);
				key[0..digestLength!D] = digest.finish();
				iKey[] ^= key[];
				oKey[] ^= key[];
			} else {
				iKey[0..macKey.length] ^= macKey[];
				oKey[0..macKey.length] ^= macKey[];
			}
		}

		if(initialized) {
			digest.start();
		}

		digest.put(iKey);
		
		initialized = true;
	}

	
	/// Update the MAC with a block of bytes.
	///
	/// Params:
	/// input = The ubyte slice containing the data.
	@safe
	void put(in ubyte[] input...) nothrow @nogc
	in {
		assert(initialized, "HMac not initialized! Call init() first");
	}
	body{
		digest.put(input);
	}

	/// Close the MAC, producing the final MAC value.
	/// Leaves the MAC reset.
	/// 
	/// Params:
	/// output	=	Output buffer for MAC tag.
	/// 
	/// Returns: Returns a slice pointing to the MAC tag in the output buffer.
	@safe
	ubyte[] finish(ubyte[] output) nothrow @nogc {
		iHash = digest.finish();
		digest.put(oKey);

		digest.put(iHash);

		output[0..macSize] = digest.finish();
		
		digest.put(iKey);

		start();

		return output[0..macSize];
	}

	@safe @nogc nothrow
	ubyte[macSize] finish() {
		ubyte[macSize] buf;
		finish(buf);
		return buf;
	}

	/// Reset the digest back to it's initial state.
	@safe
	public void reset() nothrow @nogc
	in{
		assert(initialized, "HMac not initialized!");
	}
	body {
		start();
	}

	~this () nothrow {
		wipe(iKey);
		wipe(oKey);
		wipe(iHash);
	}
	
private:
	D digest;
	private ubyte[D.digestLength] iHash;
	//	Digest iPaddedDigest, oPaddedDigest;
	ubyte[blockSize] iKey, oKey;
	bool initialized = false;

	
	enum ubyte opadByte = 0x5c;
	enum ubyte ipadByte = 0x36;

}


/// test vectors from http://tools.ietf.org/html/rfc4231
///
/// test case: 1 2 3 4 6 7 (without 5)
unittest {
	import dcrypt.digests.sha2;
	import dcrypt.digests.sha2;
	import std.stdio;
	
	// test vectors from http://tools.ietf.org/html/rfc4231
	
	// test case: 1 2 3 4 6 7 (without 5)
	
	string[] keys = [
		x"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		x"4a656665",
		x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		x"0102030405060708090a0b0c0d0e0f10111213141516171819",
		x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	];
	
	string[] data = [
		x"4869205468657265",
		x"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		x"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		x"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
		x"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
	];
	
	string[] macsSHA256 = [
		x"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		x"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		x"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		x"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		x"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		x"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
	];
	
	string[] macsSHA512 = [
		x"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		x"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		x"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
		x"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
		x"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
		x"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
	];
	
	
	testHMac!(SHA256)(keys, data, macsSHA256);
	testHMac!(SHA512)(keys, data, macsSHA512);
}

version(unittest) {

	// unittest helper functions

	import std.conv: text;

	alias const(ubyte)[] octets;
	
	/// Tests Digest d with given input data and reference hashes.
	///
	/// Params:
	/// keys	= MAC keys.
	/// datas	= Test vector input data.
	/// hashes	= Expected hashes.
	///
	@safe
	public void testHMac(Digest)(string[] keys, string[] datas, string[] hashes) 
	if(isStdDigest!Digest) {
		foreach (i; 0 .. datas.length)
		{
			HMac!Digest mac;
			
			octets key = cast(octets) keys[i];
			octets data = cast(octets) datas[i];
			octets expectedHash = cast(octets) hashes[i];

			mac.start(key);
			
			mac.put(data);

			auto hash = mac.finish();
			
			assert(hash == expectedHash, text(mac.name, " failed."));
		}
	}
}