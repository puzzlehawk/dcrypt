module dcrypt.crypto.engines.rc4;

public import dcrypt.crypto.streamcipher;

// test RC4
unittest
{
	
	static string[] test_keys = [
		x"0123456789abcdef",
		x"0123456789abcdef",
		x"0000000000000000",
		x"ef012345",
		x"0123456789abcdef"
	];
	
	static string[] test_plaintexts = [
		x"0123456789abcdef",
		x"0000000000000000",
		x"0000000000000000",
		x"00000000000000000000",
		x"01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101
		01010101010101010101010101010101"
	];

	static string[] test_ciphertexts = [
		x"75b7878099e0c596",
		x"7494c2e7104b0879",
		x"de188941a3375d3a",
		x"d6a141a7ec3c38dfbd61",
		x"7595c3e6114a09780c4ad452338e1ffd
		9a1be9498f813d76533449b6778dcad8
		c78a8d2ba9ac66085d0e53d59c26c2d1
		c490c1ebbe0ce66d1b6b1b13b6b919b8
		47c25a91447a95e75e4ef16779cde8bf
		0a95850e32af9689444fd377108f98fd
		cbd4e726567500990bcc7e0ca3c4aaa3
		04a387d20f3b8fbbcd42a1bd311d7a43
		03dda5ab078896ae80c18b0af66dff31
		9616eb784e495ad2ce90d7f772a81747
		b65f62093b1e0db9e5ba532fafec4750
		8323e671327df9444432cb7367cec82f
		5d44c0d00b67d650a075cd4b70dedd77
		eb9b10231b6b5b741347396d62897421
		d43df9b42e446e358e9c11a9b2184ecb
		ef0cd8e7a877ef968f1390ec9b3d35a5
		585cb009290e2fcde7b5ec66d9084be4
		4055a619d9dd7fc3166f9487f7cb2729 
		12426445998514c15d53a18c864ce3a2 
		b7555793988126520eacf2e3066e230c  
		91bee4dd5304f5fd0405b35bd99c7313
		5d3d9bc335ee049ef69b3867bf2d7bd1
		eaa595d8bfc0066ff8d31509eb0c6caa
		006c807a623ef84c3d33c195d23ee320
		c40de0558157c822d4b8c569d849aed5
		9d4e0fd7f379586b4b7ff684ed6a189f
		7486d49b9c4bad9ba24b96abf924372c
		8a8fffb10d55354900a77a3db5f205e1
		b99fcd8660863a159ad4abe40fa48934
		163ddde542a6585540fd683cbfd8c00f
		12129a284deacc4cdefe58be7137541c
		047126c8d49e2755ab181ab7e940b0c0"
	];

	streamCipherTest(new RC4Engine, test_keys, test_plaintexts, test_ciphertexts);
}

alias StreamCipherWrapper!RC4 RC4Engine;

static assert(isStreamCipher!RC4, "RC4 is not a stream cipher!");

@safe
public struct RC4 {

	public enum name = "RC4";

	private enum STATE_LENGTH = 256;
	
	private {
		ubyte[STATE_LENGTH] state;
		ubyte[] workingKey;
		ubyte x, y;
		bool initialized = false, forEncryption;
	}

	@safe @nogc nothrow
	~this() {
		import dcrypt.util.util: wipe;

		wipe(state);
		wipe(workingKey);
		wipe(x, y);
	}


	/**
	 * Initialize the cipher.
	 *
	 * Params:
	 * forEncryption = if true the cipher is initialized for encryption, if false for decryption.
	 * keyParams = the key and other data required by the cipher.
	 */
	public void init(bool forEncryption, KeyParameter keyParams) {
		init(forEncryption, keyParams.getKey(), null);
	}

	/**
	 * Initialize the cipher.
	 *
	 * Params:
	 * forEncryption = if true the cipher is initialized for encryption, if false for decryption.
	 * keyParams = the key and other data required by the cipher.
	 * iv = not used
	 */
	public void init(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) {
		this.forEncryption = forEncryption;
		
		workingKey = userKey.dup;
		reset();
	}
	
	/**
	 * Encrypt one single byte
	 */
	public ubyte returnByte(ubyte b) nothrow @nogc {
		return b ^ nextByte();
	}
	
	public void processBytes(in ubyte[] input, ubyte[] output) nothrow @nogc {
		foreach(i; 0 .. input.length){
			output[i] = nextByte() ^ input[i];
		}
	}

	public void reset() nothrow @nogc {
		KSA(workingKey);
	}
	
	private ubyte nextByte() nothrow @nogc {
		x = cast(ubyte)(x+1);
		y = cast(ubyte)(y + state[x]);
		
		// swap i, j
		ubyte temp = state[x];
		state[x] = state[y];
		state[y] = temp;
		
		return state[(state[x]+state[y])%STATE_LENGTH];
	}

	private void KSA(in ubyte[] workingKey) nothrow @nogc {

		// state = [0,2,3,...,state.length-1]
		foreach(i, ref s; state) {
			s = cast(ubyte) i;
		}
		uint j = 0;
		
		foreach(uint i; 0 .. STATE_LENGTH){
			j = (j + state[i] + workingKey[i%workingKey.length]) % STATE_LENGTH;
			
			// swap i, j
			ubyte temp = state[i];
			state[i] = state[j];
			state[j] = temp;
		}
		x = y = 0;
	}
	
	
}