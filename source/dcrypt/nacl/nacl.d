module nacl;

public import dcrypt.nacl.secretbox;
public import dcrypt.nacl.box;
public import dcrypt.exceptions: InvalidCipherTextException;

public import dcrypt.random: randombytes = nextBytes;
public import dcrypt.util: wipe;

public alias secretbox crypto_secretbox;
public alias secretbox_open crypto_secretbox_open;
public alias box crypto_box;
public alias box_open crypto_box_open;
public alias box_pubkey crypto_box_pubkey;
public alias box_keypair crypto_box_keypair;

/// Encrypt and decrypt a message using symmetric authenticated encryption.
unittest {
	ubyte[32] secret_key;
	ubyte[24] nonce;

	/// Generate a random key.
	randombytes(secret_key);

	/// Generate a unique nonce.
	/// Don't use the same nonce together with the same key more than once.
	randombytes(nonce);

	const ubyte[] msg = cast (const ubyte[]) "Hi Bob!";

	/// Let's encrypt!
	ubyte[] boxed = crypto_secretbox(msg, nonce, secret_key); /// This can now be transmitted over a insecure channel.

	ubyte[] recv_msg;
	// Decrypt the message.
	try {
		recv_msg = crypto_secretbox_open(boxed, nonce, secret_key);
		assert(recv_msg == msg, "Decryption produced unexpected result.");
	} catch(InvalidCipherTextException e) {
		/// An exception is thrown if the cipher text is not valid.
		/// This is the case if either the ciphertext is not the result
		/// of crypto_secretbox with the same key and nonce.
		assert(false);
	}

	/// Possibly someone tries to maliciously modify the encrypted message ...
	ubyte[] tampered = boxed.dup;
	tampered[$-1] ^= 1;

	/// ... then decryption fails.
	bool exceptionThrown = false;
	try {
		recv_msg = crypto_secretbox_open(tampered, nonce, secret_key);
	} catch(InvalidCipherTextException e) {
		exceptionThrown = true;
	}
	assert(exceptionThrown, "Tampered message has not been rejected!");
}


/// Encrypt and decrypt a message using asymmetric authenticated encryption.
unittest {

	ubyte[32] alice_sk, bob_sk, alice_pk, bob_pk;

	/// Make sure sensitive data gets erased on scope exit.
	scope(exit) {
		wipe(alice_sk);
		wipe(bob_sk);
	}

	/// Generate two random keypairs.
	crypto_box_keypair(alice_sk, alice_pk);
	crypto_box_keypair(bob_sk, bob_pk);

	/// If you already have your secret key, that's the way to get the public key:
	///		alice_pk = crypto_box_pubkey(alice_sk);	/// Alice's public key
	///		bob_pk = crypto_box_pubkey(bob_sk);		/// Bob's public key

	ubyte[24] shared_nonce;	/// A shared nonce. Can be transmitted in plaintext.
	randombytes(shared_nonce);

	/// Alice sends a message to Bob.
	const ubyte[] msg = cast (const ubyte[]) "Hi Bob!";
	ubyte[] boxed = crypto_box(msg, shared_nonce, alice_sk, bob_pk);

	/// Bob receives two messages, one has been modified by Eve.
	ubyte[] tampered = boxed.dup;
	tampered[$-1] ^= 1;

	/// Bob decrypts the messages

	ubyte[] recv_msg;

	// The message as sent by alice
	try {
		recv_msg = crypto_box_open(boxed, shared_nonce, bob_sk, alice_pk);
		assert(recv_msg == msg, "Decryption produced unexpected result.");
	} catch(InvalidCipherTextException e) {
		assert(false);
	}

	// Try to decrypt the forged message.
	bool exceptionThrown = false;
	try {
		recv_msg = crypto_box_open(tampered, shared_nonce, bob_sk, alice_pk);
		assert(false, "Tampered message has not been rejected!");
	} catch(InvalidCipherTextException e) {
		exceptionThrown = true;
	}
	assert(exceptionThrown, "Tampered message has not been rejected!");
}

/// Generate a keypair.
public void box_keypair(out ubyte[32] sk, out ubyte[32] pk) nothrow @safe @nogc {
	randombytes(sk);
	pk = box_pubkey(sk[]);
}

