module dcrypt.encoders.hex;

import std.conv: text;

import dcrypt.encoders.encoder;

unittest {
	ubyte[] raw = cast(ubyte[]) x"c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
	string hex = "c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
	assert(hexEncode(raw) == hex, "failed to encode hex");
	assert(hexDecode(hex) == raw, "failed to decode hex");
}

unittest {
	string raw = x"c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
	string hex = "c371d9573a8f3b347fa0cb80629f079ead15e9fa69cf045d762990a8ac64cc9aaec30989d677b0cee9e5362a25f9528b515ad9cde4abd09acb4abc3daa07e396";
	assert(toHexStr(raw) == hex, "failed to encode hex");
	assert(toHexStr(hex) == raw, "failed to decode hex");
}

/// Convert a string to a hex string.
@safe
public string toHexStr(string data, bool upperCase = false) nothrow pure {
	return toHexStr(cast(const ubyte[]) data, upperCase);
}

/// Convert a byte array to a hex string.
@safe
public string toHexStr(in ubyte[] data, bool upperCase = false) nothrow pure {
	ubyte[] encoded = hexEncode(data);
	string output = cast(string) encoded.idup;
	return output;
}

/// Convert a hex string back to bytes.
/// 
/// Throws: InvalidEncodingException if non-hex chars appear or input has uneven length
@safe
public ubyte[] hexDecode(string hexStr) pure {
	return hexDecode(cast(const ubyte[]) hexStr);
}

@safe
public ubyte[] hexEncode(in ubyte[] data, bool upperCase = false) pure nothrow  {
	
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
@safe
public ubyte[] hexDecode(in ubyte[] hexData) pure {
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


// encoding and decoding tables
private {
	immutable ubyte[16] hexits = cast(immutable(ubyte[16])) "0123456789abcdef";
	immutable ubyte[16] HEXITS = cast(immutable(ubyte[16])) "0123456789ABCDEF";
	immutable ubyte[128] decodingTable = createDecodingTable();
}


private ubyte[128] createDecodingTable() {

	ubyte[128] decodingTable;

	// set up the decoding table
	
	decodingTable[] = 0xFF;	// 0xFF means undefined value
	
	foreach(i,b; hexits) {
		decodingTable[b] = cast(ubyte) i;
	}

	foreach(i,b; HEXITS) {
		decodingTable[b] = cast(ubyte) i;
	}

	return decodingTable;
}