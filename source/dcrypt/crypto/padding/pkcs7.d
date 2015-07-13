module dcrypt.crypto.padding.pkcs7;

import dcrypt.crypto.padding.padding;
import dcrypt.crypto.random.prng;
import dcrypt.exceptions;
import std.exception: enforce;

/// test PKCS7 padding scheme on a 16 byte block
unittest {
	PKCS7Pad padding;
	ubyte[16] block = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];

	padding.addPadding(block, 15);
	assert(block == [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1], "PKCS7Padding failed");
	assert(padding.padCount(block) == 1, "PKCS7Padding failed");

	padding.addPadding(block, 7);
	assert(block == [0,1,2,3,4,5,6,9,9,9,9,9,9,9,9,9], "PKCS7Padding failed");
	assert(padding.padCount(block) == 9, "PKCS7Padding failed");

	padding.addPadding(block, 0);
	assert(block == [16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16], "PKCS7Padding failed");
	assert(padding.padCount(block) == 16, "PKCS7Padding failed");
}

// OOP API wrapper
alias PKCS7Padding = BlockCipherPaddingWrapper!PKCS7Pad;

///
/// PKCS7Pad is an implementation of the PKCS7 block cipher padding scheme.
/// A incomplete block will be padded with bytes like this:
/// 
/// 01
/// 02 02
/// 03 03 03
/// 04 04 04 04
/// ...
/// 
/// The block to be padded can't be full.
///	
///	Standard: rfc5652, http://tools.ietf.org/html/rfc5652#section-6.3
/// 
/// Example:
/// PKCS7Pad pad;
/// ubyte[16] block;
/// block[0..2] = [1,2];		// block contains 2 bytes
/// pad.addPadding(block, 2);	// fill the rest with padding bytes
/// assert(pad.padCount(block) == 2);
/// 
///
@safe
public struct PKCS7Pad { 

	enum name = "PKCS7Padding";

	public {

		/**
		 * pad with zeros or random bytes if SecureRandom is specified in constructor.
		 * Params: block = the block to pad
		 * len = the number of data bytes in this block. has to be smaller than the block size.
		 */
		void addPadding(ubyte[] block, in uint len) pure nothrow @nogc
		in{
			assert(len < block.length, "len has to be smaller than block size");
			assert(block.length < 256, "block to long. can't pad blocks with length > 255");
		}
		body {
			block[len..$] = cast(ubyte) (block.length-len);
		}

		/**
		 * Returns: the number of padding bytes appended to this block.
		 * Throws: InvalidCipherTextException if the padding is corrupted.
		 */
		uint padCount(in ubyte[] block) pure
		body {
			ubyte len = block[$-1];

			enforce(len <= block.length, new InvalidCipherTextException("pad block corrupted"));

			foreach(b; block[$-len..$]) {
				if(b != len) {
					throw  new InvalidCipherTextException("pad block corrupted");
				}
			}

			return len;
		}
	}
}