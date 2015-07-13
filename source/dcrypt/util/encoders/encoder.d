module dcrypt.util.encoders.encoder;

/// This is usually thrown while decoding invalid data.
@safe
public class InvalidEncodingException : Exception {
	pure this(string msg) {
		super(msg);
	}
}

@safe
public class Encoder {

	/**
	 * Params:
	 * input = data to encode
	 * 
	 * Returns:
	 * encoded data
	 */
	@safe
    public pure abstract ubyte[] encode(in ubyte[] input);
    
	/**
	 * Params:
	 * input = data to decode
	 * 
	 * Returns:
	 * decoded data
	 * 
	 * Throws: InvalidEncodingException
	 */
    @safe
    public pure abstract ubyte[] decode(in ubyte[] input);
    

}