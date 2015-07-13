module dcrypt.util.encoders.hex;

import std.conv: text;

import dcrypt.util.encoders.encoder;

public class Hex {
	
	private static HexEncoder hex;
	
	static this() { 
		hex = new HexEncoder();
	}

	@safe
	public static string encode(string data) nothrow {
		return encode(cast(const ubyte[]) data);
	}

	@safe
	public static string encode(in ubyte[] data) nothrow {
		ubyte[] encoded = hex.encode(data);
		string output = cast(string)encoded.idup;
		return output;
	}
	
	@safe
	public static ubyte[] decode(string hexStr) {
		ubyte[] hexBytes = cast(ubyte[])hexStr.dup;
		return hex.decode(hexBytes);
	}
	
	unittest {
		ubyte[] raw = cast(ubyte[]) x"c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
		string hex = "c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
		assert(Hex.encode(raw) == hex, "failed to encode hex");
		assert(Hex.decode(hex) == raw, "failed to decode hex");
	}

	unittest {
		string raw = x"c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
		string hex = "c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
		assert(Hex.encode(raw) == hex, "failed to encode hex");
		assert(Hex.decode(hex) == raw, "failed to decode hex");
	}
	
}


/**
 * provides encoding from raw bytes into hex and back
 */
@safe
public class HexEncoder : Encoder {
	
	// encoding and decoding tables
	private static immutable{
		ubyte[] hexits = cast(immutable(ubyte[])) "0123456789abcdef";
		ubyte[] HEXITS = cast(immutable(ubyte[])) "0123456789ABCDEF";
		ubyte[128] decodingTable;
	}
	
	private bool upperCase = false;
	
	static this () {
		
		// set up the decoding table
		
		decodingTable[] = 0xFF;
		
		foreach(i,b; hexits) {
			decodingTable[b] = cast(ubyte) i;
		}
		
		decodingTable['A'] = decodingTable['a'];
		decodingTable['B'] = decodingTable['b'];
		decodingTable['C'] = decodingTable['c'];
		decodingTable['D'] = decodingTable['d'];
		decodingTable['E'] = decodingTable['e'];
		decodingTable['F'] = decodingTable['f'];
	}
	
	/**
	 * Params:
	 * upperCase = true: encode like 'CAFEBABE' if false like 'cafebabe'
	 */
	public this(bool upperCase) {
		this.upperCase = upperCase;
	}
	
	/**
	 * Default lower case encoder
	 */
	public this() {
		this(false);
	}
	
	override public ubyte[] encode(in ubyte[] data) pure nothrow  {
		
		ubyte[] output = new ubyte[data.length*2];
		
		immutable ubyte[] table = upperCase ? HEXITS : hexits;
		
		foreach (i, b; data)
		{ 
			output[2*i] = table[b >> 4];
			output[2*i+1] = table[b & 0xF];
		}
		
		return output;
	}
	
	/**
	 * decodes hexData
	 * 
	 * Params: hexData = hex encoded input
	 * 
	 * Throws: InvalidEncodingException if non-hex chars appear or input has uneven length
	 */
	override public ubyte[] decode(in ubyte[] hexData) pure {
		if(hexData.length % 2 != 0) {
			throw new InvalidEncodingException("hex string needs to have a even length");
		}
		ubyte[] output = new ubyte[hexData.length/2];
		
		ubyte[] oBuf = output;
		const(ubyte)[] iBuf = hexData;
		
		while(iBuf.length >= 2){
			
			ubyte b1 = decodingTable[iBuf[0]];
			ubyte b2 = decodingTable[iBuf[1]];
			
			if((b1 | b2) == 0xFF) {
				throw new InvalidEncodingException(text("not a hex character: ", 
						cast(char)iBuf[0], cast(char)iBuf[1]));
			}
			
			oBuf[0] = cast(ubyte) (b1<<4 | b2); // assemble nibbles to byte
			iBuf = iBuf[2..$];
			oBuf = oBuf[1..$];
		}
		
		return output;
	}
	
	/// encode and decode bytes
	unittest {
		HexEncoder hex = new HexEncoder();
		ubyte[] encoded = ['d','e','a','d','0','0','b','e','e','f'];
		ubyte[] raw = [0xde, 0xad, 0x00, 0xbe, 0xef];
		
		ubyte[] decoded = hex.decode(encoded);
		assert(decoded == raw, "failed to decode hex");
		
		ubyte[] encoded2 = hex.encode(raw);
		assert(encoded2 == encoded, "failed to encode hex");
	}
	
}