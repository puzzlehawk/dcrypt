module dcrypt.crypto.generators.pbe;

public import dcrypt.crypto.params.keyparameter;
import std.conv: to;
import std.exception: enforce;
/**
 * super class for all Password Based Encryption (PBE) parameter generator classes.
 */
@safe
public abstract class PBEParametersGenerator
{
	protected const(ubyte)[]	password;
	protected const(ubyte)[]	salt;
	protected uint		iterationCount = 1;
	protected uint		iterTime;
	
	invariant() {
		assert(iterationCount > 0 || iterTime > 0, "either iterationCount or iterTime have to be > 0!");
	}

	/**
	 * base constructor.
	 */
	protected this()
	{
	}

	/**
	 * initialize the PBE generator.
	 *
	 * Params: password = the password converted into bytes (see below).
	 * 	 salt	=	the salt to be mixed with the password.
	 * 	 iterationCount	=	the (minimal) number of iterations in the "mixing" function
	 * is to be applied for.
	 * 	iterTime	=	spent at least iterTime milli seconds and at least iterationCount iterations to calculate the password
	 * getIterationCount() will return the number of iterations done in the specified time.
	 */
	public void init(in ubyte[] password, in ubyte[] salt, uint iterationCount, uint iterTime = 0) 
	{
		enforce(iterTime > 0 || iterationCount > 0, "either iterationCount or iterTime have to be > 0!");
		
		this.password = password;
		this.salt = salt;
		this.iterationCount = iterationCount;
		this.iterTime = iterTime;
	}

	/**
	 * return the password byte array.
	 */
	public ubyte[] getPassword() pure nothrow
	{
		return password.dup;
	}

	/**
	 * return the salt byte array.
	 */
	public ubyte[] getSalt() pure nothrow
	{
		return salt.dup;
	}

	/**
	 * Returns: the number of iterations done for the last computation.
	 */
	public uint getIterationCount() pure nothrow
	{
		return iterationCount;
	}

	/**
	 * generate derived parameters for a key of length keySize.
	 *
	 * Param: keySize the length, in bits, of the key required.
	 * Returns: a parameters object representing a key.
	 */
	public abstract KeyParameter generateDerivedParameters(uint keySize);

	/**
	 * generate derived parameters for a key of length keySize, and
	 * an initialisation vector (IV) of length ivSize.
	 *
	 * Params: keySize = the length, in bits, of the key required.
	 * 		ivSize = the length, in bits, of the iv required.
	 * Returns: a parameters object representing a key and an IV.
	 */
	public abstract KeyParameter generateDerivedParameters(uint keySize, uint ivSize);

	/**
	 * generate derived parameters for a key of length keySize, specifically
	 * for use with a MAC.
	 *
	 * Params: keySize = the length, in bits, of the key required.
	 * Returns: a parameters object representing a key.
	 */
	public abstract KeyParameter generateDerivedMacParameters(uint keySize);

	public abstract string getAlgorithmName();

}


/**
 * converts a password to a byte array according to the scheme in
 * PKCS5 (ascii, no padding)
 *
 * Params: password = a character array representing the password.
 * Returns: a byte array representing the password.
 */
@safe
public ubyte[] PKCS5PasswordToBytes(in char[] password) pure nothrow
{
	if (password != null)
	{
		ubyte[]  bytes = new ubyte[password.length];
		
		foreach (i; 0..password.length)
		{
			bytes[i] = cast (ubyte) password[i];
		}
		
		return bytes;
	}
	else
	{
		return new ubyte[0];
	}
}

/// test PKCS5PasswordToUTF8Bytes
unittest {
	assert(PKCS5PasswordToBytes(null) == [], "PKCS5PasswordToBytes(null) failed");
	assert(PKCS5PasswordToBytes(x"61415f3021") == [0x61, 0x41, 0x5f, 0x30, 0x21]);
	assert(PKCS5PasswordToBytes(x"0061") == [0x00, 0x61]);
}


/**
 * converts a password to a byte array according to the scheme in
 * PKCS5 (UTF-8, no padding)
 *
 * Params: password = a character array representing the password.
 * Returns: a byte array representing the password.
 */
@safe
public ubyte[] PKCS5PasswordToUTF8Bytes(in char[] password) pure nothrow
{
	if(password is null) {
		return [];
	}
	return cast(ubyte[]) password.dup;
}


/// Test PKCS5PasswordToUTF8Bytes with some special cases.
unittest {
	assert(PKCS5PasswordToUTF8Bytes(null) == [], "PKCS5PasswordToBytes(null) failed");
	assert(PKCS5PasswordToUTF8Bytes(x"00 61 41 5f 30 21") == x"00 61 41 5f 30 21", "PKCS5PasswordToBytes failed");
	assert(PKCS5PasswordToUTF8Bytes("ä") == x"C3 A4", "PKCS5PasswordToBytes('ä') failed");
	assert(PKCS5PasswordToUTF8Bytes("€") == x"E2 82 AC", "PKCS5PasswordToBytes('€') failed");
	assert(PKCS5PasswordToUTF8Bytes("𝄞") == x"F0 9D 84 9E", "PKCS5PasswordToBytes failed");
	assert(PKCS5PasswordToUTF8Bytes("𝄞€ä") == x"F0 9D 84 9E E2 82 AC C3 A4", "PKCS5PasswordToBytes failed");
}


/**
 * converts a password to a byte array according to the scheme in
 * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
 *
 * Params: password = a character array representing the password.
 * Returns: a byte array representing the password.
 */
@safe
public ubyte[] PKCS12PasswordToBytes(in char[] password) pure nothrow
{
	if (password != null && password.length > 0)
	{
		// +1 for extra 2 pad bytes.
		ubyte[]  bytes = new ubyte[(password.length + 1) * 2];
		
		foreach (i; 0..password.length)
		{
			bytes[i * 2] = cast(ubyte)(password[i] >>> 8);
			bytes[i * 2 + 1] = cast(ubyte)password[i];
		}
		
		return bytes;
	}
	else
	{
		return [];
	}
}