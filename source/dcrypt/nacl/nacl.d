module nacl;

public import dcrypt.nacl.secretbox;
public import dcrypt.nacl.box;
public import dcrypt.exceptions: InvalidCipherTextException;

public alias secretbox crypto_secretbox;
public alias secretbox_open crypto_secretbox_open;
public alias box crypto_box;
public alias box_open crypto_box_open;
public alias box_keypair crypto_box_keypair;


/// Encrypt and decrypt a message using asymmetric cryptography.
unittest {
	immutable ubyte[32] alice_sk = 1;	/// Alice's secret key
	immutable ubyte[32] bob_sk = 2;	/// Bob's secret key

	immutable ubyte[32] alice_pk = crypto_box_keypair(alice_sk);	/// Alice's public key
	immutable ubyte[32] bob_pk = crypto_box_keypair(bob_sk);		/// Bob's public key

	immutable ubyte[24] shared_nonce = 42;	/// A shared nonce. Can be transmitted in plaintext.

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

	// The modified message
	bool exceptionThrown = false;
	try {
		recv_msg = crypto_box_open(tampered, shared_nonce, bob_sk, alice_pk);
		assert(false, "Tampered message has not been rejected!");
	} catch(InvalidCipherTextException e) {
		exceptionThrown = true;
	}
	assert(exceptionThrown, "Tampered message has not been rejected!");
}