module dcrypt.crypto.streamcipher;

public import dcrypt.crypto.params.keyparameter;

/// test if struct is a stream cipher
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
						ubyte b = c.returnByte(cast(ubyte)0);
						ubyte[] outSlice = c.processBytes(cast(const ubyte[]) block, block);
						c.reset();
					}));
}

@safe
public interface StreamCipher {
	/**
	 * Initialize the cipher.
	 *
	 * Params: forEncryption = if true the cipher is initialised for
	 *  encryption, if false for decryption.
	 *  params = the key and other data required by the cipher.	 
	 * Throws: IllegalArgumentException if the params argument is
	 * inappropriate.
	 */
	@safe
	public void start(bool forEncryption, in ubyte[] key, in ubyte[] iv);

	/**
	 * Returns: the name of the algorithm the cipher implements.
	 */
	@safe
	public string name() pure nothrow;

	/**
	 * encrypt/decrypt a single byte returning the result.
	 *
	 * Params: in the byte to be processed.
	 * Returns: the result of processing the input byte.
	 */
	@safe
	public ubyte returnByte(ubyte input);

	/**
	 * process a block of bytes from in putting the result into out.
	 *
	 * Params: input = the input byte array.
	 * output = the output buffer the processed bytes go into.
	 * Throws: BufferLengthException if the output buffer is too small.
	 */
	@safe
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output);
	
	@safe
	public void reset();
	
	/**
	 * process a block of bytes from in putting the result into out.
	 *
	 * Params: input = the input byte array.
	 * Returns: slice containing the encrypted or decrypted data
	 * Throws: BufferLengthException if the output buffer is too small.
	 */
	@safe
	public final ubyte[] processBytes(in ubyte[] input) {
		ubyte[] output = new ubyte[input.length];
		processBytes(input, output);
		return output;
	}

}

@safe
public class StreamCipherWrapper(T) if(isStreamCipher!T): StreamCipher {

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
	
	/**
	 * encrypt/decrypt a single byte returning the result.
	 *
	 * Params: in = the byte to be processed.
	 * Returns: the result of processing the input byte.
	 */
	@safe
	public ubyte returnByte(ubyte input) {
		return cipher.returnByte(input);
	}
	
	/**
	 * process a block of bytes from in putting the result into out.
	 *
	 * Params: input = the input byte array.
	 * output = the output buffer the processed bytes go into.
	 * 
	 * Returns: Slice pointing to encrypted or decrypted data. Might be smaller than `output` buffer.
	 * 
	 * Throws: BufferLengthException if the output buffer is too small.
	 * 
	 */
	@safe
	public ubyte[] processBytes(in ubyte[] input, ubyte[] output) {
		return cipher.processBytes(input, output);
	}
	
	@safe
	deprecated("The reset() function might lead to insecure use of a stream cipher.")
	public void reset() {
		cipher.reset();
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
void streamCipherTest(StreamCipher c, string[] keys, string[] plaintexts, string[] ciphertexts, string[] ivs = null) 
in {
	assert(keys.length == plaintexts.length, "expected as much plaintexts as keys");
	assert(keys.length == ciphertexts.length, "expected as much ciphertexts as keys");

	if(ivs != null) {
		assert(keys.length == ivs.length, "expected as much ivs as keys");
	}
}
body {
	import std.conv: text;
	import dcrypt.util.encoders.hex;
	alias const(ubyte)[] octets;

	ubyte[] buf;

	import std.range: zip;

	void doTest(in ubyte[] key, in ubyte[] plain, in ubyte[] ciphertext, in ubyte[] iv) {
		
		c.start(true, key, iv);
		
		buf.length = plain.length;
		
		c.processBytes(plain, buf);
		
		//debug writeln(hexEncode(buf));
		assert(buf == ciphertext, text(c.name(), " encryption failed: ", hexEncode(buf),
				" != ", hexEncode(ciphertext)));
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