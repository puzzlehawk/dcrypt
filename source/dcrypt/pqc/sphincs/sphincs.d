module dcrypt.pqc.sphincs.sphincs;

import std.traits: ReturnType;

import dcrypt.bitmanip;
import dcrypt.util: wipe;
import dcrypt.crypto.digests.blake: Blake512, hash;
import dcrypt.random: nextBytes;

import dcrypt.pqc.sphincs.common;
import dcrypt.pqc.sphincs.wots: WOTS;
import dcrypt.pqc.sphincs.horst: HORST;
import dcrypt.pqc.sphincs.treeutil: TreeUtil;

private enum seed_bytes = 32;

///
/// Params:
/// n	=	Bitlength of hashes in HORST and WOTS.
/// m	=	Bitlength of the message hash.
/// n_levels = Number of subtree-layers of the hyper-tree.
/// subtree_height = Number of levels of a subtree.
/// hash_n_n	=	A hash function mapping n-bit strings to n-bit strings. hash_n_n: {0,1}^n -> {0,1}^n
/// hash_2n_n	=	A hash function mapping 2 n-bit strings to n-bit strings. hash_2n_n: {0,1}^n x {0,1}^n -> {0,1}^n
/// prg	=	A pseudo random generator function.
public template Sphincs (uint n, uint m, uint n_levels, uint subtree_height, alias hash_n_n, alias hash_2n_n, alias prg)
	if(
		is_hash_n_n!hash_n_n
		&& is_hash_2n_n!hash_2n_n
		&& is_prg!(prg, seed_bytes)
		&& n % 8 == 0
		)
{


	private {
		enum hash_bytes = n/8;

		alias ubyte[hash_bytes] H;
		alias ubyte[2*hash_bytes] M;

		alias TreeUtil!(hash_2n_n, H, M) Tree;

		alias Wots = WOTS!(n, hash_n_n, prg, 4);
		alias Horst = HORST!(n, m, hash_n_n, hash_2n_n, 16, prg);
		
		alias Wots.w  wots_w;
		alias Wots.l  wots_l;
		alias Wots.log_l  wots_log_l;
		alias Wots.sig_bytes  wots_sig_bytes;
		alias Horst.sig_bytes horst_sig_bytes;
		
		enum total_height = n_levels * subtree_height;

		enum message_hash_seed_bytes = hash_bytes;	/// Size of R1 used to randomize the message hash.
		enum leaf_address_bytes	= (total_height+7)/8;	/// Length of the encoded HORST leaf address.
		enum crypto_bytes = 
			message_hash_seed_bytes + leaf_address_bytes
				+ horst_sig_bytes + n_levels*wots_sig_bytes + total_height*hash_bytes;
		/// message hash seed R1, leaf address, HORST signature, one WOTS signature per subtree, authentication paths
		
		enum double_mask_bytes = 2*hash_bytes;
		
	}

	package {
		enum n_masks = 2*Horst.log_t;	/// has to be the max of  (2*(SUBTREE_HEIGHT+WOTS_LOGL)) and (WOTS_W-1) and 2*HORST_LOGT

		enum sk_rand_seed_bytes = seed_bytes;	/// Length of SK2.
	}

	public {
		enum secretkey_bytes = seed_bytes + sk_rand_seed_bytes + n_masks*hash_bytes;	/// (SK1, SK2, Q)
		enum publickey_bytes = hash_bytes + n_masks*hash_bytes;	/// root hash & masks
	}
	
	public {
		
		alias sig_bytes = crypto_bytes;
		
		/// Generate a Sphincs keypair.
		/// 
		/// Params:
		/// sk = [ seed || bitmasks || random seed ]
		/// pk = [ |n_masks*hash_bytes| Bitmasks || root]
		///
		@safe @nogc
		void keypair(out ubyte[secretkey_bytes] sk, out ubyte[publickey_bytes] pk) nothrow {
			nextBytes(sk);
			pk = pubkey(sk);
		}
		
		/// Compute the public key given the secret key.
		/// 
		/// Returns: The matching public key.
		@safe @nogc
		ubyte[publickey_bytes] pubkey(in ref ubyte[secretkey_bytes] sk) pure nothrow {
			ubyte[publickey_bytes] pk;
			
			enum mask_width = 2*hash_bytes;
			const ubyte[mask_width][] masks = cast(const ubyte[mask_width][]) sk[seed_bytes..seed_bytes+n_masks*hash_bytes];
			assert(masks.length == n_masks/2);
			
			pk[0..n_masks*hash_bytes] = cast(const ubyte[]) masks; // copy bitmasks
			
			
			leafaddr addr;
			addr.level = n_levels - 1;
			addr.subleaf = 0;
			addr.subtree = 0;
			
			ubyte[seed_bytes] seed = sk[0..seed_bytes];
			scope(exit) { wipe(seed); }

			// generate root hash
			H root = gen_subtree_root!subtree_height(seed, addr, masks);
			pk[$-hash_bytes..$] = root[];
			
			return pk;
		}
		
		unittest {
			ubyte[secretkey_bytes] sk;
			ubyte[publickey_bytes] pk;
			
			// generate a random key pair
			keypair(sk, pk);
		}
		
		/// Generate a detached sphincs256 signature for message.
		/// 
		/// Params:
		/// message	=	The message to be signed.
		/// sk	=	The secret key.
		///
		/// Returns: Returns the detached signature without the message appended.
		/// 
		@safe @nogc
		ubyte[sig_bytes] sign_detached(in ubyte[] message, in ref ubyte[secretkey_bytes] sk) pure nothrow {
			
			ubyte[seed_bytes] sk1;
			ubyte[sk_rand_seed_bytes] sk2;
			
			scope(exit) {
				wipe(sk1);
				wipe(sk2);
			}
			
			sk1 = sk[0..seed_bytes];
			sk2 = sk[$-sk_rand_seed_bytes..$];
			
			// Generate pseudo random values: leafidx, randomized message hash D.
			// This does not follow the paper but the reference implementation.
			
			enum mask_width = 2*hash_bytes;
			const (ubyte[mask_width][]) masks = cast(const ubyte[mask_width][]) sk[seed_bytes .. $-sk_rand_seed_bytes];
			assert(masks.length == n_masks/2);
			
			immutable ubyte[64] R = hash!Blake512(sk2[], message[]); //
			immutable ubyte[message_hash_seed_bytes] R1 = R[16..16+message_hash_seed_bytes]; // To be published in signature.
			
			assert(total_height == 60, "Code is not yet ready to handle arbitrary tree heights.");
			immutable ulong leafidx = fromLittleEndian!ulong(R[0..8]) & ((1L<<total_height)-1); // truncate to last 60 bits.
			
			immutable ubyte[publickey_bytes] pk = pubkey(sk);
			
			// Randomized message hash D. FIXME: Why hash over pk?
			immutable ubyte[64] msg_hash = hash!Blake512(R1[], pk[], message[]);
			
			ubyte[sig_bytes] sig;
			ubyte[] sigview = sig[];
			
			// Copy R1 into signature.
			sigview[0..message_hash_seed_bytes] = R1[];
			sigview = sigview[message_hash_seed_bytes..$];
			
			// Copy leaf index into signature.
			static assert(leaf_address_bytes == 8);
			sigview[0..leaf_address_bytes] = toLittleEndian!ulong(leafidx)[0..leaf_address_bytes];
			sigview = sigview[leaf_address_bytes..$];
			
			// generate HORST signature
			leafaddr addr;
			addr.level   = n_levels; // Use unique value $d$ for HORST address.
			addr.subleaf = leafidx & ((1<<subtree_height)-1);
			addr.subtree = leafidx >> subtree_height;
			
			ubyte[seed_bytes] seed;
			seed = get_node_seed(sk1, addr);
			H root;
			
			// Add HORST signature to SHPNICS signature.
			sigview[0..horst_sig_bytes] = Horst.sign(root, msg_hash, seed, masks);
			sigview = sigview[horst_sig_bytes..$];
			
			// Convert masks into right format for WOTS.
			const ubyte[hash_bytes][] wots_masks = (cast(const ubyte[hash_bytes][]) masks)[0..wots_w];
			
			for(uint i = 0 ; i < n_levels; ++i) {
				
				addr.level = i;
				
				seed = get_node_seed(sk1, addr);
				
				// Sign root of child tree.
				sigview[0..wots_sig_bytes] = Wots.sign(root, seed, wots_masks);
				sigview = sigview[wots_sig_bytes..$];
				
				H[subtree_height] authpath;
				root = gen_subtree_authpath!subtree_height(authpath, sk1, addr, masks);
				
				// Copy authpath to signature.
				const ubyte[] authpath_bytes = cast(const ubyte[]) authpath;
				sigview[0..authpath_bytes.length] = authpath_bytes[];
				sigview = sigview[authpath_bytes.length..$];
				
				// Compute address of parent subtree.
				addr.subleaf = addr.subtree & ((1<<subtree_height)-1);
				addr.subtree >>= subtree_height;
			}
			
			return sig;
		}
		
		@safe @nogc
		bool verify(in ubyte[] message, in ref ubyte[sig_bytes] signature, in ref ubyte[publickey_bytes] pk) pure nothrow {
			
			const (ubyte[double_mask_bytes][]) masks =  cast(const (ubyte[double_mask_bytes][])) pk[0..n_masks*hash_bytes];
			assert(masks.length == n_masks/2);
			const H pk_root = pk[$-hash_bytes..$];
			
			const(ubyte)[] sigview = signature[];
			
			// Extract seed for message hash.
			const ubyte[message_hash_seed_bytes] R1 = sigview[0..message_hash_seed_bytes];
			sigview = sigview[message_hash_seed_bytes..$];
			
			// Compute message hash.
			immutable ubyte[64] msg_hash = hash!Blake512(R1[], pk[], message[]);
			
			// Extract leaf address.
			static assert(leaf_address_bytes == 8);
			immutable ulong leafidx = fromLittleEndian!ulong(sigview[0..leaf_address_bytes]);

			if((leafidx >> total_height) != 0) {
				// The hightest bits get truncated in sign_detached.
				// We should not allow them to be non-zero to avoid accepting non-deterministic signatures.
				return false;
			}

			sigview = sigview[leaf_address_bytes..$];
			
			const ubyte[] horst_signature = sigview[0..horst_sig_bytes];
			sigview = sigview[horst_sig_bytes..$];
			
			auto result = Horst.verify(msg_hash, horst_signature, masks[0..Horst.log_t]);
			
			if(!result.success) {
				// HORST signature is invalid.
				return false;
			}
			
			H root_hash = result.root_hash;
			
			// Convert masks into right format for WOTS.
			const ubyte[hash_bytes][] wots_masks = (cast(const ubyte[hash_bytes][]) masks)[0..wots_w];
			
			foreach(i; 0..n_levels) {
				const (ubyte[]) wots_signature = sigview[0..wots_sig_bytes];
				sigview = sigview[wots_sig_bytes..$];
				
				const ubyte[wots_sig_bytes] wots_pk = Wots.verify(wots_signature, root_hash, wots_masks);
				
				H pkhash = Tree.hash_tree!wots_l(cast(const H[]) wots_pk, masks);
				
				const H[] authpath = cast(const H[]) sigview[0..subtree_height*hash_bytes];
				assert(authpath.length == subtree_height);
				sigview = sigview[subtree_height*hash_bytes..$];
				
				enum leafidx_mask = (1<<5)-1;
				uint idx = cast(uint) ((leafidx>>5*i) & leafidx_mask);
				root_hash = Tree.validate_authpath(pkhash, idx, authpath, masks[wots_log_l..wots_log_l+subtree_height]);
			}
			
			return root_hash == pk_root;
		}
	}
	
	private struct leafaddr {
		uint level;
		ulong subtree;
		uint subleaf;
	}
	
	/// Convert a leafaddr into a WOTS address.
	/// 
	/// Returns: 0000 || a.subleaf (5 bit) || a.subtree (55 bit) || a.level (4 bit)
	@safe @nogc
	private ulong wots_addr(in leafaddr a) nothrow pure {
		static assert(n_levels == 12 && subtree_height == 5);
		ulong t;
		//4 bits to encode level
		t  = a.level;
		//55 bits to encode subtree
		t |= a.subtree << 4;
		//5 bits to encode leaf
		t |= (cast(ulong) a.subleaf) << 59;
		return t;
	}
	
	/// Generate the seed for WOTS or HORST key with given leaf address.
	@safe @nogc
	private ubyte[seed_bytes] get_node_seed(in ref ubyte[seed_bytes] sk, in leafaddr addr) pure nothrow {
		
		ulong t = wots_addr(addr);
		
		return varlen_hash(sk, toLittleEndian(t));
	}
	
	/// Test get_node_seed
	private unittest {
		ubyte[seed_bytes] sk = 0;
		leafaddr addr; // addr = (0,0,0)
		
		H seed = get_node_seed(sk, addr);
		assert(seed == x"776484204c66ec4894d5a3879aeddb3772cac5fc2795ed26d9ef2c68f73764cc", "get_node_seed failed.");
		
		addr.level = 1;
		addr.subtree = 2;
		addr.subleaf = 3;
		seed = get_node_seed(sk, addr);
		assert(seed == x"4c77cfeac0caa7b90c12230949aebd1bf0148ab68d7d2c9ca8319f3206f892f0", "get_node_seed failed.");
	}
	
	@safe @nogc
	private H gen_leaf_wots(in M[] masks, in ubyte[seed_bytes] sk, in leafaddr addr) pure nothrow {
		const (H)[] wots_bitmasks = cast(const H[]) masks;
		wots_bitmasks = wots_bitmasks[0..wots_w];
		
		ubyte[seed_bytes] wots_seed = get_node_seed(sk, addr);

		H[wots_l] pk = Wots.pkgen(wots_seed, wots_bitmasks);
		return Tree.hash_tree!wots_l(pk, masks);
	}
	
	/// Test gen_leaf_wots
	private unittest {
		immutable ubyte[seed_bytes] sk = 0;
		ubyte[2*hash_bytes][wots_w] masks = 0;
		
		for(uint i = 0; i < masks.length; ++i) { 
			masks[i][0..hash_bytes] = cast(ubyte) (1+2*i);
			masks[i][hash_bytes..$] = cast(ubyte) (2+2*i);
		}
		
		leafaddr addr;
		addr.level = 1;
		addr.subtree = 2;
		addr.subleaf = 3;
		
		H wotsLeaf = gen_leaf_wots(masks, sk, addr);
		assert(wotsLeaf == x"de35de320de2db6acd9a8881084c4b7361f5bd9ba7c87477cb1ddf2120a1a509");
	}
	
	/// Calculate the root hash and the authpath of a subtree with WOTS keypairs as leaves. 
	///
	///	Params:
	/// height	=	The height of the tree.
	/// 
	/// authpath	=	Output buffer for the authentication path.
	/// sk	=	The secret key.
	/// addr	=	The address of the first leaf.
	/// masks	=	Bitmasks for this tree and for the WOTS keypairs.
	/// 
	/// Returns: Return the root hash.
	@nogc @safe pure nothrow
	private H gen_subtree_authpath(uint height)(
		out H[height] authpath,
		in ref ubyte[seed_bytes] sk,
		in leafaddr laddr,
		in ubyte[2*hash_bytes][] masks
		) {
		
		leafaddr addr = laddr;
		addr.subleaf = 0;
		
		Tree.hash_stack!height stack;
		
		/// The algorithm in a nutshell:
		/// Generate the 2^height leaves on the fly and push them on a stack.
		/// After pushing a leaf, reduce the stack size by merging the top two
		/// elements as long as they belong to the same level in the tree.
		/// The number of trailing zeros of the current leaf index +1 tells us how
		/// many times we can merge the top two stack elements.
		
		foreach(i; 0 .. 1<<height) {
			H newleaf = gen_leaf_wots(masks, sk, addr);
			stack.push(newleaf);
			
			if(addr.subleaf == laddr.subleaf) {
				// That's the leaf we want to generate the authpath for.
				stack.start_authpath();
			}
			
			auto zeromap = i+1; // Number of trailing zeros tells us how many times to call stack.reduce().
			const ubyte[2*hash_bytes][] localMasks = masks[wots_log_l..$];
			uint maskLevel = 0;
			while((zeromap & 1) == 0) {
				
				stack.reduce(localMasks[maskLevel]);
				
				++maskLevel;
				zeromap >>= 1;
			}
			
			++addr.subleaf;
		}
		
		H root = stack.pop();
		assert(stack.empty);
		
		authpath = stack.get_authpath();
		
		return root;
	}
	
	
	/// Calculate the root hash of a subtree with WOTS keypairs as leaves. 
	///
	///	Params:
	/// height	=	The height of the tree.
	/// 
	/// sk	=	The secret key.
	/// addr	=	The address of the first leaf.
	/// masks	=	Bitmasks for this tree and for the WOTS keypairs.
	/// 
	/// Returns: Return the root hash.
	@nogc @safe
	private H gen_subtree_root(uint height)(
		in ref ubyte[seed_bytes] sk,
		in leafaddr laddr,
		in ubyte[2*hash_bytes][] masks
		) pure nothrow {
		
		H[height] authpath;
		
		return gen_subtree_authpath!height(authpath, sk, laddr, masks);
	}
	
	/// Test gen_subtree_root_hash() against reference implementation.
	private unittest {
		enum height = 5;
		
		ubyte[2*hash_bytes][wots_w] masks = 1;
		for(uint i = 0; i < masks.length; ++i) { 
			masks[i][0..hash_bytes] = cast(ubyte) (1+2*i);
			masks[i][hash_bytes..$] = cast(ubyte) (2+2*i);
		}
		
		ubyte[seed_bytes] sk = 0;
		leafaddr addr;
		addr.level = 11;
		addr.subtree = 0;
		addr.subleaf = 0;
		
		H[height] authpath;
		H root = gen_subtree_authpath!height(authpath, sk, addr, masks);
		
		assert(root == x"4c4b40d8154e1ca19b92fe0fbc059920e94fefc6a8a3736ef3fc7dda99238319");
		
		assert(cast(const ubyte[]) authpath == x"
			7438319b21934e405f4c99dfbd5e23ea4d24f675510bcd24aa37abc846f821c9
			81c001fe9bc5a6bac218fbc7e8ad06d8cc1b23067007e17e435814ec9ca858c1
			0828381e066cb96f1ed2c54d71399b3f45bd2554e7554782869a69c86f8e25dd
			dbfba97898ccd4e03a2f20f3cd3d24e7666e6e6b1938a127136e51446573785e
			422b3b43164e6fe405ac589efa76ecc6d7e652cb9142342e79575ed275833308"
			);
		
		//	H leaf = gen_leaf_wots(masks, sk, addr);
		//
		//	H root2 = hash_nodes(leaf, authpath[0], masks...
	}
	
	/// Sanity test for validate_authpath().
	private unittest {
		enum height = 5;
		
		ubyte[2*hash_bytes][wots_w] masks = 1;
		for(uint i = 0; i < masks.length; ++i) { 
			masks[i][0..hash_bytes] = cast(ubyte) (1+2*i);
			masks[i][hash_bytes..$] = cast(ubyte) (2+2*i);
		}
		
		ubyte[seed_bytes] sk = 0;
		leafaddr addr;
		addr.level = 11;
		addr.subtree = 0;
		addr.subleaf = 7;
		
		// Generate authpath and root hash.
		H[height] authpath;
		H root = gen_subtree_authpath!height(authpath, sk, addr, masks);
		
		H leaf = gen_leaf_wots(masks, sk, addr);
		
		// Verify wheter validate_authpath generates 'root' given the authpath and the leaf.
		// Note that the first wots_log_l masks are used to generate the WOTS leaf.
		H root2 = Tree.validate_authpath(leaf, addr.subleaf, authpath, masks[wots_log_l..wots_log_l+height]);
		
		assert(root2 == root, "validate_authpath() did not compute an expected root hash.");
	}
}
