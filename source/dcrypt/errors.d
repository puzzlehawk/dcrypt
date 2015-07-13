
module dcrypt.errors;


/// Contains Error classes that are thrown if non-recoverable errors are detected,
/// such as errors in program logic. Catching them does not make much sense, because
/// something is terribly wrong with your code if an Error is thrown.


@safe
public class BufferLengthError : Error {
	this(string msg) {
		super(msg);
	}
}

@safe
public class IllegalStateError : Error {
	this(string msg) {
		super(msg);
	}
}