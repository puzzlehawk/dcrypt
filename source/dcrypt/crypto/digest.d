module dcrypt.crypto.digest;

import std.range: isOutputRange;
import std.range: OutputRange;

public import std.digest.digest: isStdDigest = isDigest;
import std.traits: ReturnType;

// TODO compatibility with std.digest?

template isDigest(T)
{
	enum bool isDigest =
		isStdDigest!T &&
			is(T == struct) &&
			isOutputRange!(T, ubyte) && isOutputRange!(T, const(ubyte)[]) &&
			is(typeof(
					{
						ubyte[] data;
						T dig = void;								// can define
						dig.start();								// can reset the digest

						dig.put(cast(ubyte)0);						// can add a single byte
						dig.put(cast(ubyte)0, cast(ubyte)0);		// variadic function
						dig.put(cast(const (ubyte)[]) data);		// can add bytes

						ubyte[T.digestLength] hash = dig.finish();					// has finish

						uint digestSize = T.digestLength;			// knows the length of the hash value in bytes. TODO use size in bits
						uint blockSize = T.blockSize;				// knows the size if its blocks
						string name = T.name;						// knows its own name

					}));
}

/// Calculate the final hash value.
/// Returns: the hash value
//mixin template finish() {
//	@safe @nogc nothrow
//	ubyte[digestLength] finish() {
//		ubyte[digestLength] buf;
//		doFinal(buf);
//		return buf;
//	}
//}

//unittest {
//	import dcrypt.crypto.digests.sha2: SHA256;
//	ubyte[32] buf;
//	SHA256 digest;
//	digest.finish(buf);
//}
//
public ubyte[] finishTo(D)(ref D digest, ubyte[] output) if(isDigest!D) {
	output[0..D.digestLength] = digest.finish();
	return output[0..D.digestLength];
}

template digestLength(T) if(isStdDigest!T)
{
	enum size_t digestLength = (ReturnType!(T.finish)).length;
}


template name(T) if(isStdDigest!T)
{
	import std.conv: text;
	static if(is(typeof({string name = T.name;}))) {
		enum string name = T.name;
	} else {
		enum string name = text("NoNameDigest");
	}
}

/// Variadic 'put' helper function for digests.
/// 
/// Params:
/// digest = The digest to put the data into.
/// data = The data to update the digest with.
/// 
/// Example:
/// 	ubyte[4] buf;
/// 	SHA256 hash;
/// 	hash.putAll(cast(ubyte) 0x01, buf, buf[0..2]);
@safe
public void putAll(D, T...)(ref D digest, in T data) nothrow @nogc
if(isStdDigest!D) {
	foreach(d; data) {
		digest.put(d);
	}
}

@safe
public abstract class Digest {

	@safe @property
	public string name() pure nothrow;

	/**
	 * return the size, in bytes, of the digest produced by this message digest.
	 *
	 * Returns the size, in bytes, of the digest produced by this message digest.
	 */
	@safe @property
	public uint digestLength() pure nothrow @nogc;
	
	/**
	 Used for padding (i.e. in HMacs)
	 Returns: the block size or 0 if the Digest is not block based
	 */
	@safe @property
	public uint blockSize() pure nothrow @nogc;

	/**
	 * update the message digest with a block of bytes.
	 *
	 * Params:
	 * input the ubyte slice containing the data.
	 */
	@safe
	public void put(in ubyte[] input...) nothrow;

	/// Close the digest, producing the final digest value and resetting the digest.
	/// Returns: Slice to the hash in output buffer.
	@safe
	public ubyte[] finish(ubyte[] output) nothrow;
	
	/**
	 * close the digest, producing the final digest value. The doFinal
	 * call leaves the digest reset. */
	@safe
	public final ubyte[] finish() nothrow {
		ubyte[] output = new ubyte[digestLength];
		finish(output);
		return output;
	}

	/**
	 * reset the digest back to it's initial state.
	 */
	@safe
	public void start() nothrow;
	
	/// create an independant copy of this Digest and it's full state
	@safe @property
	public Digest dup() nothrow;

}


@safe
public class WrapperDigest(T): Digest
if(isDigest!T) {

	private T digest;

	/**
	 * update the message digest with a block of bytes.
	 *
	 * Params:
	 * input = the ubyte slice containing the data.
	 */
	@safe
	override public void put(in ubyte[] input...) nothrow @nogc {
		digest.put(input);
	}

	/// Returns: The name of the digest algorithm.
	@safe @property
	public override string name() pure nothrow @nogc {
		return T.name;
	}
	
	/**
	 * return the size, in bytes, of the digest produced by this message digest.
	 *
	 * Returns the size, in bytes, of the digest produced by this message digest.
	 */
	@safe @property
	public override uint digestLength() pure nothrow @nogc {
		return T.digestLength;
	}
	
	
	/**
	 Used for padding (i.e. in HMacs)
	 Returns: the block size or 0 if the Digest is not block based
	 */
	@safe
	public override uint blockSize() pure nothrow @nogc {
		return T.blockSize;
	}

	
	/// Close the digest, producing the final digest value and resetting the digest.
	/// Returns: Slice to the hash in output buffer.
	@safe
	public override ubyte[] finish(ubyte[] output) nothrow @nogc {
		output[0..T.digestLength] = digest.finish();
		return output[0..T.digestLength];
	}

	/// reset the digest back to it's initial state.
	@safe
	public override void start() nothrow @nogc {
		digest.start();
	}
	
	/// Create an independant copy of this Digest and it's full state.
	@safe @property
	public override Digest dup() nothrow {
		WrapperDigest!T clone = new WrapperDigest!T;

		clone.digest = this.digest;

		return clone;
	}
	
}

version(unittest) {
	
	// unittest helper functions

	/// Use this to tests Digest d with given input data and reference hashes.
	///
	/// Params:
	/// data	=	input for hash
	/// hashes	=	expected hashes
	///
	/// Throws:
	/// AssertionError	if generated hash != expected hash
	@safe
	public void testDigest(Digest d, in string[] plaintext, in  string[] hashes) {
		import dcrypt.util.encoders.hex;
		import std.conv: text;
		
		foreach (i; 0 .. plaintext.length)
		{
			const ubyte[] data = cast(const ubyte[])plaintext[i];
			const ubyte[] expectedHash = cast(const ubyte[])hashes[i];
			
			d.start();
			
			Digest clone = null;
			
			if(data.length > 1) {
				d.put(data[0..1]);
				
				clone = d.dup;
				assert(clone !is d, text(d.name, ".dup did not return an independent Digest"));	
				
				// update d an the clone with the remaining data
				clone.put(data[1..$]);
				d.put(data[1..$]);
			}else {
				d.put(data);
			}

			ubyte[] hash = d.finish();
			assert(hash == expectedHash, text(d.name, " failed: ",hexEncode(hash), " != ", hexEncode(hashes[i])));
			
			// the clone should now create the same hash
			if(clone) {
				hash = clone.finish();
				assert(hash == expectedHash, text(d.name, "dup() did not create an independant clone"));
			}
		}
	}
}