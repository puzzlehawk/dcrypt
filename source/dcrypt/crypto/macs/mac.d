
module dcrypt.crypto.macs.mac;

// TODO as output range

/// Test if T is a message authentication code (MAC).
template isMAC(T)
{
	enum bool isMAC =
		is(T == struct) &&
			is(typeof(
					{
						ubyte[] data;
						T t = T.init; // can define
						t.start(data); // set the mac key
						t.reset();  // can reset the mac

						t.put(cast(ubyte)0); // can add a single byte
						t.put(data);	// can add bytes
						t.put(cast(ubyte)0, cast(ubyte)0); // has variadic put

						ubyte[] slice = t.finish(data);
						auto macTag = t.finish();

						uint macSize = T.macSize;
						string name = T.name;
						
					}));
}

/// Variadic 'put' helper function for MACs.
/// 
/// Params:
/// mac = The mac to put the data into.
/// data = The data to update the mac with.
/// 
/// Example:
/// 	ubyte[4] buf;
/// 	HMac!SHA256 mac;
/// 	mac.putAll(cast(ubyte) 0x01, buf, buf[0..2]);
@safe
public void putAll(M, T...)(ref M mac, in T data) nothrow @nogc
if(isMAC!M) {
	foreach(d; data) {
		mac.put(d);
	}
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
     * update the MAC with a block of bytes.
    *
    * Params:
     * input the ubyte slice containing the data.
     */
    @safe
    public abstract void put(in ubyte[] input...) nothrow;

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

	@save
	public void start(in ubyte[] key, in ubyte[] nonce = null);
	
	/**
     * update the MAC with a single byte.
     *
     * Params:
     *	input	=	the input byte to be entered.
     */
	@safe
	public void put(ubyte input) nothrow {
		mac.put(input);
	}
	
	/**
     * update the MAC with a block of bytes.
    *
    * Params:
     * input the ubyte slice containing the data.
     */
	@safe
	public void put(in ubyte[] input) nothrow {
		mac.put(input);
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