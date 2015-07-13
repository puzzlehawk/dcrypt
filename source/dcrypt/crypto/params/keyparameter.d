module dcrypt.crypto.params.keyparameter;


@safe
public class KeyParameter {
	
	private ubyte[] key;
	
	@safe
	this(in ubyte[] key) nothrow {
		this.key = key.dup;
	}
	
	@safe
	~this() nothrow {
		// wipe the key
		key[] = 0;
	}

	@safe
	ubyte[] getKey() pure nothrow {
		return key.dup;
	} 
	
}

@safe
public class ParametersWithIV: KeyParameter {
nothrow:
	
	private ubyte[]              iv;
	
	public this(in ubyte[] key, in ubyte[] iv) nothrow
	{
		super(key);
		this.iv = iv.dup;
	}
	
	@safe @nogc
	public ubyte[] getIV() pure nothrow
	{
		return iv;
	}
}