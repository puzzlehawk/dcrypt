module dcrypt.crypto.padding.x923;

import dcrypt.crypto.padding.padding;
import dcrypt.exceptions;
import std.exception: enforce;


static assert(isBlockCipherPadding!X923Pad, "X923Pad violates isBlockCipherPadding.");

/// 
/// A ANSI X.923 block cipher padding implementation.
/// This code does not support random padding anymore,
/// because the author thinks its more susceptible to padding oracle attacks than deterministic zero padding.
/// 
@safe
public struct X923Pad { 

	public enum name = "X.923";

	
	public {

		/**
		 * pad with zeros or random bytes if SecureRandom is specified in constructor.
		 * Params: block = the block to pad
		 * len = the number of data bytes in this block. has to be smaller than block.length.
		 */
		void addPadding(ubyte[] block, in uint len) nothrow
		in{
			assert(len < block.length, "len has to be smaller than block size");
			assert(block.length < 256, "block to long. can't pad blocks with length > 255");
		}
		body {

			if(len < block.length) {
				// zero pad
				block[len..$] = 0;
				// set last byte to length of padding
				block[$-1] = cast(ubyte)(block.length-len); 
			}
		}

		/**
		 * Returns: the number of padding bytes appended to this block
		 * Throws: InvalidCipherTextException if the padding is corrupted
		 */
		uint padCount(in ubyte[] block) pure
		body {
			ubyte len = block[$-1];

			enforce(len <= block.length, new InvalidCipherTextException("pad block corrupted"));

			// check if the padding is really made out of zeros
			foreach(b; block[$-len..$-1]) {
				enforce(b == 0, new InvalidCipherTextException("pad block corrupted"));
			}

			return len;
		}
	}
}

/// Test X923 padding scheme.
unittest {
	X923Pad padding;
	ubyte[] block = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
	padding.addPadding(block, 15);
	assert(block == [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1], "X923Padding failed");
	assert(padding.padCount(block) == 1, "X923Padding failed");
	padding.addPadding(block, 7);
	assert(block == [0,1,2,3,4,5,6,0,0,0,0,0,0,0,0,9], "X923Padding failed");
	assert(padding.padCount(block) == 9, "X923Padding failed");
	padding.addPadding(block, 0);
	assert(block == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16], "X923Padding failed");
	assert(padding.padCount(block) == 16, "X923Padding failed");
}
