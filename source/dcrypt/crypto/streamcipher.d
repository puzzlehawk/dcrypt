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
						c.init(true, new KeyParameter([]));
						c.init(true, cast(const ubyte[]) block, cast(const ubyte[]) block); // init with key and IV
						ubyte b = c.returnByte(cast(ubyte)0);
						c.processBytes(cast(const ubyte[]) block, block);
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
	public void init(bool forEncryption, KeyParameter params);

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
	public void processBytes(in ubyte[] input, ubyte[] output);
	
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
	public void init(bool forEncryption, KeyParameter params) {
		cipher.init(forEncryption, params);
	}
	
	/**
	 * Returns: the name of the algorithm the cipher implements.
	 */
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
	 * Throws: BufferLengthException if the output buffer is too small.
	 */
	@safe
	public void processBytes(in ubyte[] input, ubyte[] output) {
		cipher.processBytes(input, output);
	}
	
	@safe
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

	if(ivs != null)
		assert(keys.length == plaintexts.length, "expected as much ivs as keys");
}
body {
	import std.conv: text;
	import dcrypt.util.encoders.hex;

	ubyte[] buf;

	for(size_t i = 0 ; i < keys.length; ++i) {
		const ubyte[] key = cast(const ubyte[]) keys[i];
		const ubyte[] plain = cast(const ubyte[]) plaintexts[i];
		const ubyte[] ciphertext = cast(const ubyte[]) ciphertexts[i];

		if(ivs != null) {
			const ubyte[] iv = cast(const ubyte[]) ivs[i];
			ParametersWithIV ivparams = new ParametersWithIV(key, iv);
			c.init(true, ivparams);
		} else {
			c.init(true, new KeyParameter(key));
		}
		
		buf.length = plain.length;
		
		c.processBytes(plain, buf);
		//debug writeln(Hex.encode(buf));
		assert(buf == ciphertext, text(c.name(), " encryption failed: ", Hex.encode(buf),
				" != ", Hex.encode(ciphertext)));
	}
}