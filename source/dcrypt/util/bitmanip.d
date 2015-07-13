module dcrypt.util.bitmanip;

alias rotateLeft rol;
alias rotateRight ror;

/// rot shift to the left
/// Params:
/// x = integer to shift
/// shiftAmount = number of bits to shift
@safe
@nogc
T rotateLeft(T)(T x, uint shiftAmount) pure nothrow 
{
	enum nbits = T.sizeof*8;
	//shiftAmount %= nbits;
	return cast(T)(x << shiftAmount) | (x >>> (nbits-shiftAmount));
}

/// test rotateLeft
unittest {
	ubyte b0 = 0b10000001;
	ubyte b1 = 0b00000011;
	ubyte b2 = 0b00000110;
	ubyte b7 = 0b11000000;
	
	assert(rotateLeft(b0,0) == b0);
	assert(rotateLeft(b0,1) == b1);
	assert(rotateLeft(b0,2) == b2);
	assert(rotateLeft(b0,7) == b7);
	assert(rotateLeft(b0,8) == b0);
}

/// rot shift to the right
/// Params:
/// x = integer to shift
/// shiftAmount = number of bits to shift
@safe
@nogc
T rotateRight(T)(T x, uint shiftAmount) pure nothrow
{
	enum nbits = T.sizeof*8;
	//shiftAmount %= nbits;
	return cast(T)((x >>> shiftAmount) | (x << (nbits-shiftAmount)));
}

/// test rotateRight
unittest {
	ubyte b0 = 0b00000101;
	ubyte b1 = 0b10000010;
	ubyte b2 = 0b01000001;
	ubyte b7 = 0b00001010;
	
	assert(rotateRight(b0,0) == b0);
	assert(rotateRight(b0,1) == b1);
	assert(rotateRight(b0,2) == b2);
	assert(rotateRight(b0,7) == b7);
	assert(rotateRight(b0,8) == b0);
}