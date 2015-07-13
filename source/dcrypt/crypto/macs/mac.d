
module dcrypt.crypto.macs.mac;

/// Test if T is a message authentication code (MAC).
template isMAC(T)
{
	enum bool isMAC =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[] data;
						T t = void; // can define
						t.init(data); // set the mac key
						t.reset();  // can reset the digest
						t.update(cast(ubyte)0); // can add a single byte
						t.update(data);	// can add bytes
						uint len = t.doFinal(data);

						uint macSize = T.macSize;
						string name = T.name;
						
					}));
}

@safe
public abstract class Mac {



    @safe @property
    public abstract string name() pure nothrow;

    /**
    * Returns: the size, in bytes, of the MAC.
    */
    @safe @property
    public abstract uint macSize() pure nothrow;

    /**
     * update the MAC with a single byte.
     *
     * Params:
     *	input	=	the input byte to be entered.
     */
    @safe
    public abstract void update(ubyte input) nothrow;

    /**
     * update the MAC with a block of bytes.
    *
    * Params:
     * input the ubyte slice containing the data.
     */
    @safe
    public abstract void update(in ubyte[] input) nothrow;

    /**
     * close the MAC, producing the final MAC value. The doFinal
     * call leaves the MAC reset(). */
    @safe
    public abstract size_t doFinal(ubyte[] output) nothrow;
    
     /**
     * close the MAC, producing the final MAC value. The doFinal
     * call leaves the MAC reset(). */
    @safe
    public final ubyte[] doFinal() nothrow {
    	ubyte[] output = new ubyte[macSize];
    	doFinal(output);
    	return output;
    }
    /**
     * reset the digest back to it's initial state.
     */
    @safe
    public abstract void reset() nothrow ;

}

@safe
public class WrapperMac(T) if(isMAC!T) {

	private T mac;

	@safe @property
	public string name() pure nothrow {
		return mac.name;
	}
	
	/**
    * Returns: the size, in bytes, of the MAC.
    */
	@safe @property
	public uint macSize() pure nothrow {
		return mac.macSize;
	}
	
	/**
     * update the MAC with a single byte.
     *
     * Params:
     *	input	=	the input byte to be entered.
     */
	@safe
	public void update(ubyte input) nothrow {
		mac.update(input);
	}
	
	/**
     * update the MAC with a block of bytes.
    *
    * Params:
     * input the ubyte slice containing the data.
     */
	@safe
	public void update(in ubyte[] input) nothrow {
		mac.update(input);
	}
	
	/**
     * close the MAC, producing the final MAC value. The doFinal
     * call leaves the MAC reset(). */
	@safe
	public size_t doFinal(ubyte[] output) nothrow {
		return mac.doFinal(output);
	}
	
	/**
     * close the MAC, producing the final MAC value. The doFinal
     * call leaves the MAC reset(). */
	@safe
	public final ubyte[] doFinal() nothrow {
		ubyte[] output = new ubyte[macSize];
		doFinal(output);
		return output;
	}
	/**
     * reset the digest back to it's initial state.
     */
	@safe
	public void reset() nothrow {
		mac.reset();
	}
	
}