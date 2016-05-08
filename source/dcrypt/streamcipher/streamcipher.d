module dcrypt.streamcipher.streamcipher;


/// Test if struct is a stream cipher.
@safe
template isStreamCipher(T)
{
	enum bool isStreamCipher =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[0] block;
						T c = void; //Can define
						string name = c.name;
						c.start(true, cast(const ubyte[]) block, cast(const ubyte[]) block); // init with key and IV
						ubyte[] outSlice = c.processBytes(cast(const ubyte[]) block, block);
					}));
}

@safe
public interface IStreamCipher {

	/// Initialize the cipher.
	/// 
	/// Params:
	/// forEncryption	=	Encrypt if true, decrypt if false.
	/// key	=	Secret key.
	/// nonce =	Initialization vector.
	@safe
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] nonce);

	/// Returns: the name of the algorithm the cipher implements.
	@safe
	public string name() pure nothrow;

	/// Process a block of bytes from in putting the result into out.
	///
	/// Params:
	/// input = The input byte array.
	/// output = The output buffer the processed bytes go into.
	/// 
	/// Returns:
	/// Returns a slice pointing to the output data.
	@safe
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output);
}

@safe
public class StreamCipherWrapper(T) if(isStreamCipher!T): IStreamCipher {

	private T cipher;

	/// Params:
	/// forEncryption = encrypt or decrypt
	/// key = Secret key.
	/// iv = Initialization vector.
	@safe
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] iv = null) {
		cipher.start(forEncryption, key, iv);
	}
	

	/// Returns: the name of the algorithm the cipher implements.
	@safe @property
	public string name() pure nothrow {
		return cipher.name;
	}

	
	/// Process a block of bytes from in putting the result into out.
	///
	/// Params:
	/// input = The input byte array.
	/// output = The output buffer the processed bytes go into.
	/// 
	/// Returns:
	/// Returns a slice pointing to the output data.
	@safe
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output) {
		return cipher.processBytes(input, output);
	}
}

/// Use this to test a stream cipher with multiple keys, plaintexts and ivs.
/// 
/// Params:
/// c	=	the cipher engine
/// keys	=	keys in binary format
/// plaintexts	=	plaintexts in binary format
/// ciphertexts	=	cipher texts in binary format
/// ivs	=	initialisation vectors, could be 'null'
@safe
void streamCipherTest(IStreamCipher c, string[] keys, string[] plaintexts, string[] ciphertexts, string[] ivs = null) 
in {
	assert(keys.length == plaintexts.length, "expected as much plaintexts as keys");
	assert(keys.length == ciphertexts.length, "expected as much ciphertexts as keys");

	if(ivs != null) {
		assert(keys.length == ivs.length, "expected as much ivs as keys");
	}
}
body {
	import std.conv: text;
	import dcrypt.encoders.hex;
	alias const(ubyte)[] octets;

	ubyte[] buf;

	import std.range: zip;

	void doTest(in ubyte[] key, in ubyte[] plain, in ubyte[] ciphertext, in ubyte[] iv) {
		
		c.start(true, key, iv);
		
		buf.length = plain.length;
		
		c.processBytes(plain, buf);
		
		//debug writeln(hexEncode(buf));
		assert(buf == ciphertext, text(c.name(), " encryption failed: ", buf.toHexStr(),
				" != ", ciphertext.toHexStr));
	}

	if(ivs !is null) {
		foreach(key, plain, cipher, iv; zip(keys, plaintexts, ciphertexts, ivs)) {
			doTest(cast(octets) key, cast(octets) plain, cast(octets) cipher, cast(octets) iv);
		}
	}else {
		foreach(key, plain, cipher; zip(keys, plaintexts, ciphertexts)) {
			doTest(cast(octets) key, cast(octets) plain, cast(octets) cipher, null);
		}
	}

	

}