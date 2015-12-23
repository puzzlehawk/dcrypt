module dcrypt.pqc.sphincs.wots;

/// Winternitz one-time signature.


import dcrypt.pqc.sphincs.common: is_hash_n_n, is_prg, num_digits;

private enum seed_bytes = 32;

/// Winternitz one-time signature scheme as described in
/// https://cryptojedi.org/papers/sphincs-20150202.pdf
/// 
/// Params:
/// n	=	Bitlength of the hash values.
/// hash_n_n	=	A hash function mapping n-bit strings to n-bit strings.
/// hash_2n_n	=	A hash function mapping two n-bit strings to n-bit strings.
/// log_w	=	The log2 of the Winternitz parameter.
package template WOTS (uint n, alias hash_n_n, alias prg, uint log_w)
	if(
		is_hash_n_n!hash_n_n 
		&& is_prg!(prg, seed_bytes)
		&& n % 8 == 0)
{

	package {
		enum l = l1+l2; /// l1 + l2;
		enum w = 1 << log_w;	/// Winternitz parameter.
		enum log_l = num_digits(l-1, 2); /// Number of levels in the l-tree.
		enum sig_bytes = l*hash_bytes;
	}

	/// Generate a public key.
	/// 
	/// Returns: The public key derived from sk and masks.
	@safe @nogc
	H[l] pkgen(in ref ubyte[seed_bytes] sk, in H[] masks) pure nothrow
	in {
		assert(masks.length == w, "Number of masks must be w.");
	} body {
		
		H[l] pk;
		prg(cast(ubyte[])pk, sk);
		
		foreach(i; 0..l) {
			pk[i] = chain(pk[i], masks, w-1);
		}

		return pk;
	}

	/// Create a one-time signature for `msg`.
	/// 
	/// Params:
	/// msg =	The message to sign.
	/// sk	=	The secret seed.
	/// masks	=	List of masks.
	/// 
	/// Returns: Returns the signature.
	@safe @nogc
	ubyte[sig_bytes] sign(in ref H msg, in ref ubyte[seed_bytes] sk, in H[] masks) pure nothrow
	in {
		assert(masks.length == w, "Number of masks must be w (16 for sphincs256).");
	} body {
		uint[l] B = toBaseW(msg);
		H[l] sig;
		prg(cast(ubyte[])sig, sk);

		foreach(i; 0..l) {
			sig[i] = chain(sig[i], masks, B[i]);
		}

		return cast(ubyte[sig_bytes]) sig;
	}

	/// From given signature, message and mask computes the public key.
	/// The signature is valid if and only if the return value is equal to the real public key.
	/// 
	/// Note: The caller is responsible for checking for equality of the return value and the public key.
	/// 
	/// Params:
	/// sig	=	Signature.
	/// msg	=	Signed message.
	/// masks = List of masks.
	/// 
	/// Returns: The public key that would match this signature.
	@safe @nogc
	ubyte[sig_bytes] verify(in ubyte[] sig, in ref H msg, in H[] masks) pure nothrow
	in {
		assert(masks.length == w, "Number of masks must be w (16 for sphincs256).");
		assert(sig.length == sig_bytes, "Length of `sig` must be wots_sig_bytes!");
	} body {
		uint[l] B = toBaseW(msg);
		H[l] pk;

		const H[] sig_wrap = cast(const H[]) sig[];

		foreach(i; 0..l) {
			pk[i] = chain(sig_wrap[i], masks[B[i]..$], w-1-B[i]);
		}

		return cast(ubyte[sig_bytes]) pk;
	}

	
	private {
		enum hash_bytes = n/8;
		
		enum l1 = (n+log_w-1)/log_w;	/// Number of chunks to split the message hash into.
		enum l2 = num_digits(l1*(w-1), w);	/// Length of checksum in base w representation.
		
		alias H = ubyte[n/8];
		
		/// Chaining function. c^i(x,r)=F(c^{i-1}(x,r) xor r_i)
		///
		@safe @nogc
		H chain(in ref H x, in H[] masks, in uint chain_len) pure nothrow
		in {
			assert(chain_len < w, "chain_len must be smaller than w!");
			assert(masks.length >= chain_len, "Number of masks must >= chain length.");
		} body {
			H buf = x;
			
			foreach(i; 0..chain_len) {
				buf[] ^= masks[i][];
				buf = hash_n_n(buf);
			}
			
			return buf;
		}
		
		
		/// Returns: Base w representation of M || C.
		@safe @nogc
		uint[l] toBaseW(in ref H msg) pure nothrow {
			static assert(w == 16, "`toBaseW` is designed for sphincs256 with w = 16 only.");
			
			uint[l] basew;
			uint i;
			uint c;
			for(i = 0; i < l1; i += 2)
			{
				basew[i]   = msg[i/2] % w;
				basew[i+1] = msg[i/2] / w;
				
				c += w - 1 - basew[i];
				c += w - 1 - basew[i+1];
			}
			
			for( ;i < l; i++)
			{
				basew[i] = c % w;
				c /= w;
			}
			
			return basew;
		}
	}
}

// Generic sanity test.
private unittest {
	import dcrypt.crypto.random.drng: DRNG = HashDRNG_SHA256;
	import dcrypt.pqc.sphincs.sphincs256;
	alias Wots = WOTS!(256, hash_n_n, prg, 4);

	DRNG drng;

	ubyte[seed_bytes] seed;
	hash256[Wots.w] masks;
	foreach(i;0..Wots.w) {
		masks[i][] = cast(ubyte) i;
	}

	hash256 msg;
	drng.nextBytes(msg);
	msg[0] = 0x00; // 'extreme' cases
	msg[1] = 0xFF;

	ubyte[Wots.sig_bytes] pk, sig, vpk;

	pk = cast(ubyte[Wots.sig_bytes]) Wots.pkgen(seed, masks);
	sig = Wots.sign(msg, seed, masks);

	vpk = Wots.verify(sig, msg, masks);

	assert(pk == vpk, "WOTS failed.");

	// forge a message
	msg[0] ^= 1;
	vpk = Wots.verify(sig, msg, masks);
	assert(pk != vpk, "WOTS failed with a forged message.");
}

// Test pkgen against ref implementation.
private unittest {
	import dcrypt.pqc.sphincs.sphincs256;
	alias Wots = WOTS!(256, hash_n_n, prg, 4);

	ubyte[seed_bytes] seed = 0;
	hash256[Wots.w] masks;
	foreach(i;0..Wots.w) {
		masks[i][] = cast(ubyte) i;
	}

	ubyte[Wots.sig_bytes] pk = cast(ubyte[Wots.sig_bytes]) Wots.pkgen(seed, masks);

	
	string expected_pk = x"
		f663d5c2f249ab6f92994c83fac9a02ed8959025656ae2de36924aca635487a0
		83904c2c7ee54afa6ded0c001f20072d48623c17bf986748debee84fcdfd66c6
		ea53468409ca7e9b8014f6d5b0577260e89c36db19e576eb6dc62fd22c3e92d8
		94ec7f2f441840daacfb3268a54ee66f4b812c6009d04056058139bff73876b8
		aa1fe1181d90d439650396de6daca34311b9ab946c8882e78816b327ada25c4c
		140310a47085511fa214385a7837533833e286fcd7faed6b1ca44e46f8856eb2
		1d1138d6cd5a31e709570591e8b94f62f83b023941e7667551ba31cb6fbf6660
		0b224fc538d8cc9921599071b59ca3e4635b78791a1c74610cc011b58b391214
		6325f4e989865bdabb4de1002e94d047fec0b32816c9574a00cec751306097d0
		69419dfecb3e154aec6b53dca2d68682d9a8865fc168776fededed4cd19c0efc
		6ed752d156264711e9a9c86113aa5f6b7ca1bec814a8f680d019bf8a72484e59
		e72127d0fddd2abb3090c3ba1947d6ca304cf11aff9fbf177d921ff694245fa2
		a2107eb6f711cd44f26a5baa89458d4413a8ff66441a5c7ef62656e86e263c38
		3833945fb8b0095b9e9cad5682d900ffc8a6c9ec86856d060e5f4c465be9f9ce
		de0fecdfca7adc360a8ccbe30d314110a6c74852ac04d3be7d66298075a14b47
		a0e569a7b933bca0c97a5d2fb5e822210135deb036153c9a453c91715052eb5a
		6cf513ef5128451f60c28775ec82cb2f3b3e1fbc6330d4a0d4c0700bba92c87a
		06310954e56181030921857ab31469f89368082ce0e65090a2dc58aa19c0a903
		1a8dd4040475e7d5731b6dace1ca4c582e21a50848e89cc25460f225d96e500a
		2ac522bd9f34b57db735a35d2aff556c0330406f020ac90aeba659c4bd762b36
		9502c01c099857f68402d8b11ad962c49c773cba255226831ffc95fc61c9aafa
		cf4f6809defc0ca0e43c74a833cdcb000d5b51706658f06f5be892fc100ec076
		b9598de1727ea631ce73b58821c6852e5c9672992175c4226c143da9e4187625
		e96ff1d2f84a3698c450e1e2bd0b35b0ff337308e78186a5e9fa7eece3ffe3e6
		f9e7c1adbe12132c35304df9447ac974891052a9a386c6394e0167658d16ab51
		30788110c83b9727bf9c58c22513b9bf94e085fd9aa76b2569f373cd1228b67a
		18760fd78b6bf562f55b020c0ee52d2050de223f3db9206f867021ef68aa03ab
		d731de377d565f05ab440692cebbdba006e1dfb54ee8d5d9b6fb3a85d4f02236
		bfa028bc3c898dbee9297402aca8fe0f99a342492cdc69d37f41b84d7365c034
		77eddbe43dc4f9c779e3b82287d9b765f2440cf8f4b9167af6cb5e07d14a5988
		a9df921d39a0b423d8ab0e726f12d997621b02c49f8d5e7c7a967b08e7f6b385
		c2e8e8645b593625e4ec5cb33818354610919edf97a98070df8799b77673bcb2
		42b55dd78166f07e295be1eb9fbeb7729227e77b222187b7f602acb998e37e37
		ce307e24d334592b041a0f304d54f860f7588d1c1ac8acd3f5fd22c27406e6ef
		1ba1fe2846f83959309eb90d25a0026764bf00aa15265b1da93e703e35119ab3
		7a7e36d822924dc2e3c97748f9574b1950d47a4a8ae08e063086be4e35bcfd18
		b9ff0e83bbaa5bf99beacc6178988c7b213f52bd64d73202cb1a58b3e5d2bda7
		c187325244de26b1645137c70b517b3b1f2eec384d521d2d925390041fadbfe6
		293056e7001be0cbde4a1549d237d1fc4b33e164fb8babc5aef4e85b3cbee7a5
		2c97eaab30ce0a92ac9817aeb1ea423972fbd1c72fa5e7fc1a7a475942caa03c
		12a3b9f910c63bde3de6cf4cb2672047e1bbb4a28c892931efd84f40143b6480
		277cc9df53114e6a049331277ab5fc3b019611579f678c6ce7beb4a8421e5409
		2872c1711a67104db703e54bec443e549fc752df680008ff62fcc346a11e3a0d
		22884ee843921cb657bbbf5c0c8f0c4fd1479dc030c810ef6ef0354fa8c64d0e
		ed948d621e3d3f7810e89107af9889e84e368fde685683038ed751f7a995a6cc
		a2b3e0df1f7cd56cff1682d75324dcf29f8f173b18826570923176def9948f5b
		8ee744256499e9804d573a8b66f73d806ab263ef902eb5eb0a88dd0c0baa941a
		9ff56e85552e8d3c1c2f8a17ff750d1731f456af158224f4492aaa94b0608cc6
		e04b8317456a64e064f96d9fb9e6c7a4fc5300295f78167e4e16eb63908b1087
		f4a48b0758e924add4e65ec108538b7d0a9ba7ddcc7fd07c46c6809ca310689a
		41bcd0062885d460d8f4c992491da67f48762028e1ffd29bd1b9622402f00116
		0037c0aec8cbecddd89a08fff0eebb4898cf9035d733ae4f38808c762a109278
		8dadbed71a496444cd85f855c0c4baca726eda975ade23766da1da613b7cd1cc
		9deb14e431b12e99d337f83554771f0fc72caa224d3ea3ddde13c00d96a78007
		fa63e850f64b556d081f0b8bbce2b67d5ec6032fe3893eb796a11c587ce73258
		3ecdf264d8b470a3b1d7cb221ea4c3b9e172bcce55b1252a66f135fe62fe5669
		8001cf7e9148e18f2e8ea0288425556abd009993ee1b6f597a4fdcbfb5fac4bf
		28c93373b00e13520fc388fde8ee693274bc72e47a4c490c9e4d42ad8883ec32
		468f2cdeed1e90afc3a9df53edba0c77ed56bcac184e2a4efe206706b6be9c47
		b43701ad8602e1eb2a0ddb1e469fac27b3aad465553cce52f1c61af187222ed6
		97b9b0a8a088c17a46396855046adc34b58f1e0c7c59e1e8b414d60bc9a33e14
		05ed37aa342b9ea31c7f5e65a2f72ec0f07c1900cad2fca08d00f47699b477a2
		6e5eae3deba854df0d31c5398960bd4ea9e6e15310155a0625dc4b5d8db97819
		fb929a513637e997574d241cc988c4b995d667d303cd3dca15e6da34457691dc
		1c660ab6c0bf5d4a3b5963ced9c39a354c2839c8e43557017b58a02f9f360e52
		3d2f4f5ce01670e9d78e17c511421af7044b14ef7fec17aff6c8211e46189740
		87e52a883869955eb4774c8e492ba91ef784145bcd30806638c194d0690e9103
		";

	assert(pk == expected_pk, "WOTS pkgen failed.");
}

// Test sign against ref implementation.
private unittest {
	import dcrypt.pqc.sphincs.sphincs256;
	alias Wots = WOTS!(256, hash_n_n, prg, 4);

	ubyte[seed_bytes] seed = 0;
	hash256[Wots.w] masks;
	foreach(i;0..Wots.w) {
		masks[i][] = cast(ubyte) i;
	}

	hash256 msg;
	foreach(i, ref m; msg) {m = cast(ubyte) i;}
	
	ubyte[Wots.sig_bytes] sig = Wots.sign(msg, seed, masks);

	
	ubyte[Wots.sig_bytes] pk = cast(ubyte[Wots.sig_bytes]) Wots.pkgen(seed, masks);
	ubyte[Wots.sig_bytes] vpk = Wots.verify(sig, msg, masks);
	assert(vpk == pk);
	
	string expected_sig = x"
		9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f
		0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be
		b4411187ef8e1f5d114bd88d7e32e8daae4d268eaf533f428b2243a5c5efd8e4
		42258dcda14cf111c602b8971b8cc843e91e46ca905151c02744a6b017e69316
		558b0d6d61ae89df9bf942a0234acfb139224477cea757e71ae2cc400ed167da
		f59fddd0b7f52dcc0c60a448cbf9511610b0a742f1e4d238a7a45cae054ec21c
		fd78c6894ffe3018fdd0b03a0f1d4b1e7fa95d5090803dfb0786f68820ac405c
		d202f5628b6cabe10d5ab83244e4b230efd4dcccefc4635892d35e9dcb7225df
		87ccff776e74b13a9648defb5a615acde234489426b6eb03357c102894de8336
		9183f4776b3ea59a1781e564a3eae96769397b8ab435b25dda4189e103d031cf
		a68793fa7bd669a648d56bdbb4073f306231875d254ece952d82a5b208b1ab78
		a73ceacbb5fbdb93619fe47144798f36653dec8192d787ed4056c4733c4f0076
		0a70c251fa111a3562544030bbe3388802b549b648b7aa201616491d527b41c8
		110c21543f215fb79f8c854061fb802e64727e63ea43879b280e4f6a67888790
		6e4b43cd56f219dac9c1ed0e21ad283e9e0b148aa299af7853935f05495f39c2
		46e0508fde225ab6952876e854759ac2f06d266b3ff6159c277f1647a8e03dc9
		8fd40ae35f01bb44399921504f6dd1618e9ec7f9d5250ba3b0a2696d959b2e0c
		35eaa8eb7e0b32b72ba59619d9d4f98ce1bcc32839b4aea762b44660519ae161
		84da784456e1c91fa213572d42d4fd2c497eba1de78b53e3f92a353037312666
		25f708eff054e9ecffa59975bed26ab489d4739f7c72532df4f1fbcd76b42690
		46f4722b0c30795bee7e1bbaf8ec2a4c8fa7f2165cb42edd591c1eba386e3103
		4a6c311dc576810cf12a805cb39b77f550e5a62eaa9f8093165bd675c4366e8f
		6ed4970adf3db61a7a6ee65d91edd84cb88eb552aac568ea97ef654f1957834a
		43d2f93d6cb533dae78f5172a9f8ca1b25778cc54bf11033309c3d39d2227c75
		656d89dfe93df7aff066b0ac57d0451675d93ca92d3a9675b829b13051d4d320
		cea5c5c584295b2ac8671dc80ae291cba89ef969bc9bde679bd5badee6a2837e
		86cee388ee4fd00e51d2412d36dc11eba3c2b0c62abf82e0abb49f22feaf58b2
		ae5b8053f3c4f26600ce50665acfce76e60a175b736b8ad43812a24c09de5f4b
		f4c393ae45c12701eb1617f86de925f211b4cd956440098ebd570182874c9fbb
		e126e652938b85dbb9852b6ff8ff4ded8d0f6908e4b23438a99e8deb94c6ddf6
		a9df921d39a0b423d8ab0e726f12d997621b02c49f8d5e7c7a967b08e7f6b385
		3ef3cedb75dc7fbfa93b85e925e4d293e1e76c1bc7a261f97a25d9adc3fa103f
		4112579427583d94c85b5ff9ba4d51ccef0a4513be24bc68a079150893311a2b
		dba6df40d2bebe492c845d63e7112d3ea3c33f281c6382270bb43a20b2b3742b
		1a36a33e76a5a26683b58827c0711b3bb0e84e10866cad4cf66dc4d2b0d68b03
		c3c22938b3d76ff66c636d4dc8e8bbf573e046415e08b0dc68950cc1b91e8186
		8ab61f4bd32b27f2e8ee42a558b8f209f777efc5a0f4b860ffd47f0fb6d9f0c5
		4d0313a66537e4d413dc7b61267cdcb9de608a61c11b575bacd5b0fd24cbb2ef
		e8247dfe71402ef4a839bbe09e50174a76c735e0608aeedc7009559edfe82948
		dd77bae064bf93a22bd831c6278d2403f174e9020932c048fa04ef7aa5b6505c
		38138e5134fa3646d1357fa32deb26a0582c96a1938ac89331ff57a9f892d3c4
		91d39e0cd7f66c29c750e631213c2270545ca109fe2aeac1de7780c6763b015b
		bedcfce22f68825440351a8b616024092cf3361c1c578779643c4e2f1a0135f6
		73637e6c218befcb6813931737850b97a28026b938b37b049273e5832ff84c93
		6b7061eab15101a6711da53a6d04e90e24fef43dbaad851a205a637b7f94af52
		bca6c5d5433e6dfa380c178f969a7cb1066e059afea875a978b317faa634d91c
		705325c493b63a1134e2952091cd50aec9db022136fdf6fffeaa5e81c4b4fa5a
		964822eeaf1cb629c4cd4c1364849d2df3fbbea79464213ee30dce19ac27672b
		1c25aa272bfd31f0d801f08ed91394c1f4fc3ba88104110d1758b168d606a548
		c1427849da80fbe8baec549ea1ea4ef275f90dab9a1dd6c39a86077ba7b69027
		e7a6261d72c184c7c8a149fbac03914f9b881056a1eab9afbe59045656f31dc5
		8bd313610404d4445cf4778f4e67a25547386a061de5f302b82e2e2d6980f464
		ea78ee8697f63340b014a6b564ce4ee38eab4707a930141571d2a08ca8aa8089
		d4aa475387b6a54378dfaeff3dffd09a71661e03881df10cd649675f2bd3e4c2
		1def9afa74fb4f548fedb943edb688ea2ab20d2da6e8113580dca09c7ef660be
		d2b2aaaec1ddc7bdbe6f5300aa91b021d63c5154670a47477b15aff0a850778e
		85e72104197fa9556dafbd528da65d73b5c1ac9550c3df97a56770a1d5f071b1
		780c6b9c0e0b75adb94a762b46b253f4fd25f9f6bb54d6ac3abd0bbe93f643b5
		2260150eb9bc4cc2912d09fe446336235bf0f80c6dcd91c09e1efdb6497e99e0
		88586cf9e25c678ef78e19ed9d90efaf61a6b1b025092f6e01a4a15e73aac4af
		b6c119ab764305e5713b3525705eeb817d791f27eb7fb076d286be8bdefe7323
		9d39c884b2dc8eb1fc8eb4cc7a4669457f3638496eac96ffa9a2899cb92169c0
		6e5eae3deba854df0d31c5398960bd4ea9e6e15310155a0625dc4b5d8db97819
		70a0efaa154f88206fb5cfde4f9727d49df9a33cf2f42a82cc8c6186ecab4f1f
		0cbbde5e0d6810ae6eff109e3f7061ecc9d34dc459bc71c66b3579f345712904
		9c0c5bac54c9412706532f30ee00eba219f9bb9f82e3c8351e60eed9059ad634
		0b67c60235cc3d36e8474413152346257ec9dc12263a6e11987cdb361020d1ed
		";
	
	assert(sig == expected_sig , "WOTS sign failed.");
}