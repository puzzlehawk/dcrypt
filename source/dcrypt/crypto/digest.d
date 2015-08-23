module dcrypt.crypto.digest;

import std.range: isOutputRange;
import std.range: OutputRange;

// TODO compatibility with std.digest?

template isDigest(T)
{
	import std.digest.digest: isStdDigest = isDigest;

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

						ubyte[] result = dig.finish(data);				// can extract the hash value
						ubyte[T.digestLength] hash = dig.finish();					// has finish

						uint digestSize = T.digestLength;			// knows the length of the hash value in bytes. TODO use size in bits
						uint byteLength = T.byteLength;				// knows the length of its internal state. TODO rename
						uint blockSize = T.blockSize;				// knows the size if its blocks
						string name = T.name;						// knows its own name

					}));
}

/// Calculate the final hash value.
/// Returns: the hash value
mixin template finish() {
	@safe @nogc nothrow
	ubyte[digestLength] finish() {
		ubyte[digestLength] buf;
		doFinal(buf);
		return buf;
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
	@safe
	public uint getDigestSize() pure nothrow @nogc;

	
	/**
	 Return the size in bytes of the internal buffer the digest applies it's compression
	 function to.
	 Returns: the size of the internal state in bytes
	 */
	@safe
	public uint getByteLength() pure nothrow @nogc;
	
	
	/**
	 Used for padding (i.e. in HMacs)
	 Returns: the block size or 0 if the Digest is not block based
	 */
	@safe
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
		ubyte[] output = new ubyte[getDigestSize()];
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
	public override uint getDigestSize() pure nothrow @nogc {
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

	/// Return the size in bytes of the internal buffer the digest applies it's compression
	/// function to.
	/// Returns: the size of the internal state in bytes
	@safe
	public override uint getByteLength() pure nothrow @nogc {
		return T.byteLength;
	}
	


	/// Close the digest, producing the final digest value and resetting the digest.
	/// Returns: Slice to the hash in output buffer.
	@safe
	public override ubyte[] finish(ubyte[] output) nothrow @nogc {
		return digest.finish(output);
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