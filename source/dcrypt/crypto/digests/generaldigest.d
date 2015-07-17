module dcrypt.crypto.digests.generaldigest;

public import dcrypt.crypto.digest;

/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
@safe
package class GeneralDigest : Digest
{
	alias put update;

public:

	override void put(in ubyte[] input...) nothrow @nogc
	{
		uint inOff = 0;
		size_t len = input.length;
		//
		// fill the current word
		//
		while ((xBufOff != 0) && (len > 0))
		{
			putSingleByte(input[inOff]);

			inOff++;
			len--;
		}

		//
		// process whole words.
		//
		while (len > xBuf.length)
		{
			processWord(input[inOff .. $]);

			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}

		//
		// load in the remainder.
		//
		while (len > 0)
		{
			putSingleByte(input[inOff]);

			inOff++;
			len--;
		}
	}

	protected void finish() nothrow @nogc
	{
		ulong    bitLength = (byteCount << 3);

		//
		// add the pad bytes.
		//
		put(128);

		while (xBufOff != 0)
		{
			put(0);
		}

		processLength(bitLength);

		processBlock();
	}

	override void start() nothrow @nogc
	{
		byteCount = 0;

		xBufOff = 0;
		xBuf[] = 0;
	}
	
	override uint blockSize() pure nothrow @nogc {
		return 64;
	}
	
	//    abstract string getAlgorithmName() pure nothrow;
	//    abstract uint getDigestSize() pure nothrow;
	//    abstract uint doFinal(ubyte[] output);

	override uint getByteLength() pure nothrow @nogc
	{
		return BYTE_LENGTH;
	}
	
	@property
	public override GeneralDigest dup() nothrow {
		GeneralDigest clone = dupImpl();
		clone.xBuf = xBuf;
		clone.xBufOff = xBufOff;
		clone.byteCount = byteCount;
		return clone;
	}
	
	/// create an independant clone. used by dup()
	protected abstract GeneralDigest dupImpl() nothrow;
	
	protected abstract nothrow @nogc {
		void processWord(in ubyte[] input);
		void processLength(ulong bitLength);
		void processBlock();
	}

	protected void putSingleByte(ubyte input) nothrow @nogc
	{
		xBuf[xBufOff++] = input;
		
		if (xBufOff == xBuf.length)
		{
			processWord(xBuf);
			xBufOff = 0;
		}
		
		byteCount++;
	}
	
	private {
		enum BYTE_LENGTH = 64;
		ubyte[4]  xBuf;
		uint     xBufOff = 0;

		size_t    byteCount;
	}
	
}