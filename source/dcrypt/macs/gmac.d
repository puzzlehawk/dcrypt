module dcrypt.macs.gmac;

public import dcrypt.macs.mac;
import dcrypt.blockcipher.modes.gcm.gcm;


/// Special case of GCMCipher where no data gets encrypted
/// but all processed as AAD.
/// 
/// Standards: NIST Special Publication 800-38D
@safe
public struct GMac(T) if(isBlockCipher!T)
{
	enum macSize = 16;

	private {
		GCM!T gcm;
		bool initialized = false;
	}

	public {

		enum name = "GMAC-"~T.name;
		
		void start(in ubyte[] key, in ubyte[] nonce) {
			gcm.start(true, key, nonce);
			initialized = true;
		}

		/// Update the MAC with a block of bytes.
		///
		/// Params:
		/// input = The ubyte slice containing the data.
		void put(in ubyte[] input...) nothrow @nogc
		in {
			assert(initialized, "GMac not initialized. call init() first.");
		}
		body {
			gcm.processAADBytes(input);
		}
		
		/// Close the MAC, producing the final MAC value.
		/// Leaves the MAC reset.
		/// 
		/// Params:
		/// output	=	Output buffer for MAC tag.
		/// 
		/// Returns: Returns a slice pointing to the MAC tag in the output buffer.
		void finish(ubyte[] output) nothrow
		in {
			assert(initialized, "GMac not initialized. call init() first.");
			assert(output.length >= gcm.macSize, "output buffer too short for MAC");
		}
		body {

			scope(exit) {
				reset();
			}

			gcm.finish(output[0..macSize], output[0..0]);
		}

		/// Reset the digest back to it's initial state.
		void reset() nothrow 
		in {
			assert(initialized, "GMac not initialized. call init() first.");
		}
		body {
			gcm.reset();
		}
	}
}

/// simple usage of GMac
/// with test vectors from
/// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf, section 2.1.1
unittest {

	import dcrypt.blockcipher.aes;
	
	alias const(ubyte)[] octets;
	
	octets key = cast(octets)x"AD7A2BD03EAC835A6F620FDCB506B345";
	octets iv = cast(octets)x"12153524C0895E81B2C28465"; 

	auto gmac = new GMac!AES();
	gmac.start(key, iv);
	
	
	octets aad = cast(octets)(
		x"D609B1F056637A0D46DF998D88E5222A
          B2C2846512153524C0895E8108000F10
          1112131415161718191A1B1C1D1E1F20
          2122232425262728292A2B2C2D2E2F30
          313233340001"
		);

	gmac.put(aad);
	
	ubyte[] outbuf = new ubyte[gmac.macSize];

	gmac.finish(outbuf);
	
	octets expectedMac = cast(octets) (x"F09478A9B09007D06F46E9B6A1DA25DD");

	assert(outbuf == expectedMac);
}

