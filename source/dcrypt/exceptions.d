module dcrypt.exceptions;

@safe
public class InvalidKeyException : Exception {
	pure this(string msg) {
		super(msg);
	}
}

@safe
public class IllegalArgumentException : Exception {
	pure this(string msg) {
		super(msg);
	}
}

@safe
public class InvalidParameterException : Exception {
	pure this(string msg) {
		super(msg);
	}
}

@safe
public class InvalidCipherTextException : Exception {
	pure this(string msg) {
		super(msg);
	}
}

@safe
public class MaxBytesExceededException : Exception {
	pure this(string msg) {
		super(msg);
	}
}