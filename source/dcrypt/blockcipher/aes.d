module dcrypt.blockcipher.aes;

import dcrypt.blockcipher.blockcipher;
import dcrypt.errors, dcrypt.exceptions;
import dcrypt.bitmanip;

/// Test AES encryption and decryption of a single block with 128, 192 and 256 bits key length.
/// test vectors from http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
@safe
unittest {
	
	static string[] test_keys = [
		x"2b7e151628aed2a6abf7158809cf4f3c",
		x"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
	];

	static string[] test_plaintexts = [
		x"6bc1bee22e409f96e93d7e117393172a",
		x"6bc1bee22e409f96e93d7e117393172a",
		x"6bc1bee22e409f96e93d7e117393172a",
		x"ae2d8a571e03ac9c9eb76fac45af8e51"
	];
	
	static string[] test_ciphertexts = [
		x"3ad77bb40d7a3660a89ecaf32466ef97",
		x"bd334f1d6e45f25ff712a214571fa5cc",
		x"f3eed1bdb5d2a03c064b5a7e3db181f8",
		x"591ccb10d410ed26dc5ba74a31362870"
		
	];
	
	AESEngine t = new AESEngine();
	
	blockCipherTest(t, test_keys, test_plaintexts, test_ciphertexts);
	
}

static assert(isBlockCipher!AES, "AES is not a block cipher!");

/// OOP API wrapper for AES
alias BlockCipherWrapper!AES AESEngine;

@safe
public struct AES
{

	public enum name = "AES";
	public enum blockSize = 16;

	public {
	
		/// Params:
		/// forEncryption = `false`: decrypt, `true`: encrypt
		/// userKey = Secret key.
		/// iv = Not used.
		void start(bool forEncryption, in ubyte[] userKey, in ubyte[] iv = null) nothrow @nogc
		in {
			size_t len = userKey.length;
			assert(len == 16 || len == 24 || len == 32, this.name~": Invalid key length (requires 16, 24 or 32 bytes)");
		}
		body {
			this.forEncryption = forEncryption;
			
			generateWorkingKey(userKey, forEncryption);
			
			initialized = true;
		}

		uint processBlock(in ubyte[] input, ubyte[] output) nothrow @nogc
		in {
			assert(initialized, "AES engine not initialized");
			assert(blockSize<=input.length, "input buffer too short");
			assert(blockSize<=output.length, "output buffer too short");
		}
		body {

			if (forEncryption)
			{
				unpackBlock(input);
				encryptBlock();
				packBlock(output);
			}
			else
			{
				unpackBlock(input);
				decryptBlock();
				packBlock(output);
			}

			return blockSize;
		}

		void reset() nothrow @nogc
		{

		}
	}

	// begin of private section
private:

//	@safe @nogc nothrow
//	~this() {
//		import dcrypt.util: wipe;
//
//		wipe(workingKey);
//		wipe(C0, C1, C2, C3);
//	}

	enum MAXROUNDS = 14;

	uint ROUNDS; // Number of rounds depends on keysize
	uint C0, C1, C2, C3; // State

	uint[4][MAXROUNDS+1] workingKey;

	bool forEncryption;
	bool initialized;

	
	// Sbox and its inverse
	static immutable ubyte[256] S = [
		0x63u, 0x7cu, 0x77u, 0x7bu, 0xf2u, 0x6bu, 0x6fu, 0xc5u,
		0x30u, 0x01u, 0x67u, 0x2bu, 0xfeu, 0xd7u, 0xabu, 0x76u,
		0xcau, 0x82u, 0xc9u, 0x7du, 0xfau, 0x59u, 0x47u, 0xf0u,
		0xadu, 0xd4u, 0xa2u, 0xafu, 0x9cu, 0xa4u, 0x72u, 0xc0u,
		0xb7u, 0xfdu, 0x93u, 0x26u, 0x36u, 0x3fu, 0xf7u, 0xccu,
		0x34u, 0xa5u, 0xe5u, 0xf1u, 0x71u, 0xd8u, 0x31u, 0x15u,
		0x04u, 0xc7u, 0x23u, 0xc3u, 0x18u, 0x96u, 0x05u, 0x9au,
		0x07u, 0x12u, 0x80u, 0xe2u, 0xebu, 0x27u, 0xb2u, 0x75u,
		0x09u, 0x83u, 0x2cu, 0x1au, 0x1bu, 0x6eu, 0x5au, 0xa0u,
		0x52u, 0x3bu, 0xd6u, 0xb3u, 0x29u, 0xe3u, 0x2fu, 0x84u,
		0x53u, 0xd1u, 0x00u, 0xedu, 0x20u, 0xfcu, 0xb1u, 0x5bu,
		0x6au, 0xcbu, 0xbeu, 0x39u, 0x4au, 0x4cu, 0x58u, 0xcfu,
		0xd0u, 0xefu, 0xaau, 0xfbu, 0x43u, 0x4du, 0x33u, 0x85u,
		0x45u, 0xf9u, 0x02u, 0x7fu, 0x50u, 0x3cu, 0x9fu, 0xa8u,
		0x51u, 0xa3u, 0x40u, 0x8fu, 0x92u, 0x9du, 0x38u, 0xf5u,
		0xbcu, 0xb6u, 0xdau, 0x21u, 0x10u, 0xffu, 0xf3u, 0xd2u,
		0xcdu, 0x0cu, 0x13u, 0xecu, 0x5fu, 0x97u, 0x44u, 0x17u,
		0xc4u, 0xa7u, 0x7eu, 0x3du, 0x64u, 0x5du, 0x19u, 0x73u,
		0x60u, 0x81u, 0x4fu, 0xdcu, 0x22u, 0x2au, 0x90u, 0x88u,
		0x46u, 0xeeu, 0xb8u, 0x14u, 0xdeu, 0x5eu, 0x0bu, 0xdbu,
		0xe0u, 0x32u, 0x3au, 0x0au, 0x49u, 0x06u, 0x24u, 0x5cu,
		0xc2u, 0xd3u, 0xacu, 0x62u, 0x91u, 0x95u, 0xe4u, 0x79u,
		0xe7u, 0xc8u, 0x37u, 0x6du, 0x8du, 0xd5u, 0x4eu, 0xa9u,
		0x6cu, 0x56u, 0xf4u, 0xeau, 0x65u, 0x7au, 0xaeu, 0x08u,
		0xbau, 0x78u, 0x25u, 0x2eu, 0x1cu, 0xa6u, 0xb4u, 0xc6u,
		0xe8u, 0xddu, 0x74u, 0x1fu, 0x4bu, 0xbdu, 0x8bu, 0x8au,
		0x70u, 0x3eu, 0xb5u, 0x66u, 0x48u, 0x03u, 0xf6u, 0x0eu,
		0x61u, 0x35u, 0x57u, 0xb9u, 0x86u, 0xc1u, 0x1du, 0x9eu,
		0xe1u, 0xf8u, 0x98u, 0x11u, 0x69u, 0xd9u, 0x8eu, 0x94u,
		0x9bu, 0x1eu, 0x87u, 0xe9u, 0xceu, 0x55u, 0x28u, 0xdfu,
		0x8cu, 0xa1u, 0x89u, 0x0du, 0xbfu, 0xe6u, 0x42u, 0x68u,
		0x41u, 0x99u, 0x2du, 0x0fu, 0xb0u, 0x54u, 0xbbu, 0x16u
	];

	static immutable ubyte[256] Si = [
		0x52u, 0x09u, 0x6au, 0xd5u, 0x30u, 0x36u, 0xa5u, 0x38u,
		0xbfu, 0x40u, 0xa3u, 0x9eu, 0x81u, 0xf3u, 0xd7u, 0xfbu,
		0x7cu, 0xe3u, 0x39u, 0x82u, 0x9bu, 0x2fu, 0xffu, 0x87u,
		0x34u, 0x8eu, 0x43u, 0x44u, 0xc4u, 0xdeu, 0xe9u, 0xcbu,
		0x54u, 0x7bu, 0x94u, 0x32u, 0xa6u, 0xc2u, 0x23u, 0x3du,
		0xeeu, 0x4cu, 0x95u, 0x0bu, 0x42u, 0xfau, 0xc3u, 0x4eu,
		0x08u, 0x2eu, 0xa1u, 0x66u, 0x28u, 0xd9u, 0x24u, 0xb2u,
		0x76u, 0x5bu, 0xa2u, 0x49u, 0x6du, 0x8bu, 0xd1u, 0x25u,
		0x72u, 0xf8u, 0xf6u, 0x64u, 0x86u, 0x68u, 0x98u, 0x16u,
		0xd4u, 0xa4u, 0x5cu, 0xccu, 0x5du, 0x65u, 0xb6u, 0x92u,
		0x6cu, 0x70u, 0x48u, 0x50u, 0xfdu, 0xedu, 0xb9u, 0xdau,
		0x5eu, 0x15u, 0x46u, 0x57u, 0xa7u, 0x8du, 0x9du, 0x84u,
		0x90u, 0xd8u, 0xabu, 0x00u, 0x8cu, 0xbcu, 0xd3u, 0x0au,
		0xf7u, 0xe4u, 0x58u, 0x05u, 0xb8u, 0xb3u, 0x45u, 0x06u,
		0xd0u, 0x2cu, 0x1eu, 0x8fu, 0xcau, 0x3fu, 0x0fu, 0x02u,
		0xc1u, 0xafu, 0xbdu, 0x03u, 0x01u, 0x13u, 0x8au, 0x6bu,
		0x3au, 0x91u, 0x11u, 0x41u, 0x4fu, 0x67u, 0xdcu, 0xeau,
		0x97u, 0xf2u, 0xcfu, 0xceu, 0xf0u, 0xb4u, 0xe6u, 0x73u,
		0x96u, 0xacu, 0x74u, 0x22u, 0xe7u, 0xadu, 0x35u, 0x85u,
		0xe2u, 0xf9u, 0x37u, 0xe8u, 0x1cu, 0x75u, 0xdfu, 0x6eu,
		0x47u, 0xf1u, 0x1au, 0x71u, 0x1du, 0x29u, 0xc5u, 0x89u,
		0x6fu, 0xb7u, 0x62u, 0x0eu, 0xaau, 0x18u, 0xbeu, 0x1bu,
		0xfcu, 0x56u, 0x3eu, 0x4bu, 0xc6u, 0xd2u, 0x79u, 0x20u,
		0x9au, 0xdbu, 0xc0u, 0xfeu, 0x78u, 0xcdu, 0x5au, 0xf4u,
		0x1fu, 0xddu, 0xa8u, 0x33u, 0x88u, 0x07u, 0xc7u, 0x31u,
		0xb1u, 0x12u, 0x10u, 0x59u, 0x27u, 0x80u, 0xecu, 0x5fu,
		0x60u, 0x51u, 0x7fu, 0xa9u, 0x19u, 0xb5u, 0x4au, 0x0du,
		0x2du, 0xe5u, 0x7au, 0x9fu, 0x93u, 0xc9u, 0x9cu, 0xefu,
		0xa0u, 0xe0u, 0x3bu, 0x4du, 0xaeu, 0x2au, 0xf5u, 0xb0u,
		0xc8u, 0xebu, 0xbbu, 0x3cu, 0x83u, 0x53u, 0x99u, 0x61u,
		0x17u, 0x2bu, 0x04u, 0x7eu, 0xbau, 0x77u, 0xd6u, 0x26u,
		0xe1u, 0x69u, 0x14u, 0x63u, 0x55u, 0x21u, 0x0cu, 0x7du
	];

	// Round constants
	static immutable uint[30] rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
	];

	// precomputation tables of calculations for rounds
	static immutable uint[256] T0 =
	[
		0xa56363c6u, 0x847c7cf8u, 0x997777eeu, 0x8d7b7bf6u, 0x0df2f2ffu,
		0xbd6b6bd6u, 0xb16f6fdeu, 0x54c5c591u, 0x50303060u, 0x03010102u,
		0xa96767ceu, 0x7d2b2b56u, 0x19fefee7u, 0x62d7d7b5u, 0xe6abab4du,
		0x9a7676ecu, 0x45caca8fu, 0x9d82821fu, 0x40c9c989u, 0x877d7dfau,
		0x15fafaefu, 0xeb5959b2u, 0xc947478eu, 0x0bf0f0fbu, 0xecadad41u,
		0x67d4d4b3u, 0xfda2a25fu, 0xeaafaf45u, 0xbf9c9c23u, 0xf7a4a453u,
		0x967272e4u, 0x5bc0c09bu, 0xc2b7b775u, 0x1cfdfde1u, 0xae93933du,
		0x6a26264cu, 0x5a36366cu, 0x413f3f7eu, 0x02f7f7f5u, 0x4fcccc83u,
		0x5c343468u, 0xf4a5a551u, 0x34e5e5d1u, 0x08f1f1f9u, 0x937171e2u,
		0x73d8d8abu, 0x53313162u, 0x3f15152au, 0x0c040408u, 0x52c7c795u,
		0x65232346u, 0x5ec3c39du, 0x28181830u, 0xa1969637u, 0x0f05050au,
		0xb59a9a2fu, 0x0907070eu, 0x36121224u, 0x9b80801bu, 0x3de2e2dfu,
		0x26ebebcdu, 0x6927274eu, 0xcdb2b27fu, 0x9f7575eau, 0x1b090912u,
		0x9e83831du, 0x742c2c58u, 0x2e1a1a34u, 0x2d1b1b36u, 0xb26e6edcu,
		0xee5a5ab4u, 0xfba0a05bu, 0xf65252a4u, 0x4d3b3b76u, 0x61d6d6b7u,
		0xceb3b37du, 0x7b292952u, 0x3ee3e3ddu, 0x712f2f5eu, 0x97848413u,
		0xf55353a6u, 0x68d1d1b9u, 0x00000000u, 0x2cededc1u, 0x60202040u,
		0x1ffcfce3u, 0xc8b1b179u, 0xed5b5bb6u, 0xbe6a6ad4u, 0x46cbcb8du,
		0xd9bebe67u, 0x4b393972u, 0xde4a4a94u, 0xd44c4c98u, 0xe85858b0u,
		0x4acfcf85u, 0x6bd0d0bbu, 0x2aefefc5u, 0xe5aaaa4fu, 0x16fbfbedu,
		0xc5434386u, 0xd74d4d9au, 0x55333366u, 0x94858511u, 0xcf45458au,
		0x10f9f9e9u, 0x06020204u, 0x817f7ffeu, 0xf05050a0u, 0x443c3c78u,
		0xba9f9f25u, 0xe3a8a84bu, 0xf35151a2u, 0xfea3a35du, 0xc0404080u,
		0x8a8f8f05u, 0xad92923fu, 0xbc9d9d21u, 0x48383870u, 0x04f5f5f1u,
		0xdfbcbc63u, 0xc1b6b677u, 0x75dadaafu, 0x63212142u, 0x30101020u,
		0x1affffe5u, 0x0ef3f3fdu, 0x6dd2d2bfu, 0x4ccdcd81u, 0x140c0c18u,
		0x35131326u, 0x2fececc3u, 0xe15f5fbeu, 0xa2979735u, 0xcc444488u,
		0x3917172eu, 0x57c4c493u, 0xf2a7a755u, 0x827e7efcu, 0x473d3d7au,
		0xac6464c8u, 0xe75d5dbau, 0x2b191932u, 0x957373e6u, 0xa06060c0u,
		0x98818119u, 0xd14f4f9eu, 0x7fdcdca3u, 0x66222244u, 0x7e2a2a54u,
		0xab90903bu, 0x8388880bu, 0xca46468cu, 0x29eeeec7u, 0xd3b8b86bu,
		0x3c141428u, 0x79dedea7u, 0xe25e5ebcu, 0x1d0b0b16u, 0x76dbdbadu,
		0x3be0e0dbu, 0x56323264u, 0x4e3a3a74u, 0x1e0a0a14u, 0xdb494992u,
		0x0a06060cu, 0x6c242448u, 0xe45c5cb8u, 0x5dc2c29fu, 0x6ed3d3bdu,
		0xefacac43u, 0xa66262c4u, 0xa8919139u, 0xa4959531u, 0x37e4e4d3u,
		0x8b7979f2u, 0x32e7e7d5u, 0x43c8c88bu, 0x5937376eu, 0xb76d6ddau,
		0x8c8d8d01u, 0x64d5d5b1u, 0xd24e4e9cu, 0xe0a9a949u, 0xb46c6cd8u,
		0xfa5656acu, 0x07f4f4f3u, 0x25eaeacfu, 0xaf6565cau, 0x8e7a7af4u,
		0xe9aeae47u, 0x18080810u, 0xd5baba6fu, 0x887878f0u, 0x6f25254au,
		0x722e2e5cu, 0x241c1c38u, 0xf1a6a657u, 0xc7b4b473u, 0x51c6c697u,
		0x23e8e8cbu, 0x7cdddda1u, 0x9c7474e8u, 0x211f1f3eu, 0xdd4b4b96u,
		0xdcbdbd61u, 0x868b8b0du, 0x858a8a0fu, 0x907070e0u, 0x423e3e7cu,
		0xc4b5b571u, 0xaa6666ccu, 0xd8484890u, 0x05030306u, 0x01f6f6f7u,
		0x120e0e1cu, 0xa36161c2u, 0x5f35356au, 0xf95757aeu, 0xd0b9b969u,
		0x91868617u, 0x58c1c199u, 0x271d1d3au, 0xb99e9e27u, 0x38e1e1d9u,
		0x13f8f8ebu, 0xb398982bu, 0x33111122u, 0xbb6969d2u, 0x70d9d9a9u,
		0x898e8e07u, 0xa7949433u, 0xb69b9b2du, 0x221e1e3cu, 0x92878715u,
		0x20e9e9c9u, 0x49cece87u, 0xff5555aau, 0x78282850u, 0x7adfdfa5u,
		0x8f8c8c03u, 0xf8a1a159u, 0x80898909u, 0x170d0d1au, 0xdabfbf65u,
		0x31e6e6d7u, 0xc6424284u, 0xb86868d0u, 0xc3414182u, 0xb0999929u,
		0x772d2d5au, 0x110f0f1eu, 0xcbb0b07bu, 0xfc5454a8u, 0xd6bbbb6du,
		0x3a16162cu];

	static immutable uint[256] Tinv0 =
	[
		0x50a7f451u, 0x5365417eu, 0xc3a4171au, 0x965e273au, 0xcb6bab3bu,
		0xf1459d1fu, 0xab58faacu, 0x9303e34bu, 0x55fa3020u, 0xf66d76adu,
		0x9176cc88u, 0x254c02f5u, 0xfcd7e54fu, 0xd7cb2ac5u, 0x80443526u,
		0x8fa362b5u, 0x495ab1deu, 0x671bba25u, 0x980eea45u, 0xe1c0fe5du,
		0x02752fc3u, 0x12f04c81u, 0xa397468du, 0xc6f9d36bu, 0xe75f8f03u,
		0x959c9215u, 0xeb7a6dbfu, 0xda595295u, 0x2d83bed4u, 0xd3217458u,
		0x2969e049u, 0x44c8c98eu, 0x6a89c275u, 0x78798ef4u, 0x6b3e5899u,
		0xdd71b927u, 0xb64fe1beu, 0x17ad88f0u, 0x66ac20c9u, 0xb43ace7du,
		0x184adf63u, 0x82311ae5u, 0x60335197u, 0x457f5362u, 0xe07764b1u,
		0x84ae6bbbu, 0x1ca081feu, 0x942b08f9u, 0x58684870u, 0x19fd458fu,
		0x876cde94u, 0xb7f87b52u, 0x23d373abu, 0xe2024b72u, 0x578f1fe3u,
		0x2aab5566u, 0x0728ebb2u, 0x03c2b52fu, 0x9a7bc586u, 0xa50837d3u,
		0xf2872830u, 0xb2a5bf23u, 0xba6a0302u, 0x5c8216edu, 0x2b1ccf8au,
		0x92b479a7u, 0xf0f207f3u, 0xa1e2694eu, 0xcdf4da65u, 0xd5be0506u,
		0x1f6234d1u, 0x8afea6c4u, 0x9d532e34u, 0xa055f3a2u, 0x32e18a05u,
		0x75ebf6a4u, 0x39ec830bu, 0xaaef6040u, 0x069f715eu, 0x51106ebdu,
		0xf98a213eu, 0x3d06dd96u, 0xae053eddu, 0x46bde64du, 0xb58d5491u,
		0x055dc471u, 0x6fd40604u, 0xff155060u, 0x24fb9819u, 0x97e9bdd6u,
		0xcc434089u, 0x779ed967u, 0xbd42e8b0u, 0x888b8907u, 0x385b19e7u,
		0xdbeec879u, 0x470a7ca1u, 0xe90f427cu, 0xc91e84f8u, 0x00000000u,
		0x83868009u, 0x48ed2b32u, 0xac70111eu, 0x4e725a6cu, 0xfbff0efdu,
		0x5638850fu, 0x1ed5ae3du, 0x27392d36u, 0x64d90f0au, 0x21a65c68u,
		0xd1545b9bu, 0x3a2e3624u, 0xb1670a0cu, 0x0fe75793u, 0xd296eeb4u,
		0x9e919b1bu, 0x4fc5c080u, 0xa220dc61u, 0x694b775au, 0x161a121cu,
		0x0aba93e2u, 0xe52aa0c0u, 0x43e0223cu, 0x1d171b12u, 0x0b0d090eu,
		0xadc78bf2u, 0xb9a8b62du, 0xc8a91e14u, 0x8519f157u, 0x4c0775afu,
		0xbbdd99eeu, 0xfd607fa3u, 0x9f2601f7u, 0xbcf5725cu, 0xc53b6644u,
		0x347efb5bu, 0x7629438bu, 0xdcc623cbu, 0x68fcedb6u, 0x63f1e4b8u,
		0xcadc31d7u, 0x10856342u, 0x40229713u, 0x2011c684u, 0x7d244a85u,
		0xf83dbbd2u, 0x1132f9aeu, 0x6da129c7u, 0x4b2f9e1du, 0xf330b2dcu,
		0xec52860du, 0xd0e3c177u, 0x6c16b32bu, 0x99b970a9u, 0xfa489411u,
		0x2264e947u, 0xc48cfca8u, 0x1a3ff0a0u, 0xd82c7d56u, 0xef903322u,
		0xc74e4987u, 0xc1d138d9u, 0xfea2ca8cu, 0x360bd498u, 0xcf81f5a6u,
		0x28de7aa5u, 0x268eb7dau, 0xa4bfad3fu, 0xe49d3a2cu, 0x0d927850u,
		0x9bcc5f6au, 0x62467e54u, 0xc2138df6u, 0xe8b8d890u, 0x5ef7392eu,
		0xf5afc382u, 0xbe805d9fu, 0x7c93d069u, 0xa92dd56fu, 0xb31225cfu,
		0x3b99acc8u, 0xa77d1810u, 0x6e639ce8u, 0x7bbb3bdbu, 0x097826cdu,
		0xf418596eu, 0x01b79aecu, 0xa89a4f83u, 0x656e95e6u, 0x7ee6ffaau,
		0x08cfbc21u, 0xe6e815efu, 0xd99be7bau, 0xce366f4au, 0xd4099feau,
		0xd67cb029u, 0xafb2a431u, 0x31233f2au, 0x3094a5c6u, 0xc066a235u,
		0x37bc4e74u, 0xa6ca82fcu, 0xb0d090e0u, 0x15d8a733u, 0x4a9804f1u,
		0xf7daec41u, 0x0e50cd7fu, 0x2ff69117u, 0x8dd64d76u, 0x4db0ef43u,
		0x544daaccu, 0xdf0496e4u, 0xe3b5d19eu, 0x1b886a4cu, 0xb81f2cc1u,
		0x7f516546u, 0x04ea5e9du, 0x5d358c01u, 0x737487fau, 0x2e410bfbu,
		0x5a1d67b3u, 0x52d2db92u, 0x335610e9u, 0x1347d66du, 0x8c61d79au,
		0x7a0ca137u, 0x8e14f859u, 0x893c13ebu, 0xee27a9ceu, 0x35c961b7u,
		0xede51ce1u, 0x3cb1477au, 0x59dfd29cu, 0x3f73f255u, 0x79ce1418u,
		0xbf37c773u, 0xeacdf753u, 0x5baafd5fu, 0x146f3ddfu, 0x86db4478u,
		0x81f3afcau, 0x3ec468b9u, 0x2c342438u, 0x5f40a3c2u, 0x72c31d16u,
		0x0c25e2bcu, 0x8b493c28u, 0x41950dffu, 0x7101a839u, 0xdeb30c08u,
		0x9ce4b4d8u, 0x90c15664u, 0x6184cb7bu, 0x70b632d5u, 0x745c6c48u,
		0x4257b8d0u];

	private enum uint  m1 = 0x80808080, m2 = 0x7f7f7f7f, m3 = 0x0000001b;;

	@safe
	@nogc
	private static uint FFmulX(uint x) nothrow
	{
		return (((x & m2) << 1) ^ (((x & m1) >>> 7) * m3));
	}

	@safe
	@nogc
	private static uint inv_mcol(uint x) nothrow
	{
		uint f2 = FFmulX(x);
		uint f4 = FFmulX(f2);
		uint f8 = FFmulX(f4);
		uint f9 = x ^ f8;

		return f2 ^ f4 ^ f8 ^ rotateRight(f2 ^ f9, 8) ^ rotateRight(f4 ^ f9, 16) ^ rotateRight(f9, 24);
	}

	@safe
	@nogc
	private static uint subWord(uint x) nothrow
	{
		return (S[x&255] | ((S[(x>>8)&255])<<8) | ((S[(x>>16)&255])<<16) | S[(x>>24)&255]<<24);
	}

	/**
	 * Calculate the necessary round keys
	 * The number of calculations depends on key size and block size
	 * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
	 * This code is written assuming those are the only possible values
	 */
	private void generateWorkingKey(in ubyte[] key, bool forEncryption) nothrow @nogc
	in {
		size_t len = key.length;
		assert(len == 16 || len == 24 || len == 32, this.name~": Invalid key length (requires 16, 24 or 32 bytes)");
	}
	body {
		uint KC = cast(uint)key.length / 4;  // key length in words
		uint t;

		ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
		//uint[][] W = new uint[][](ROUNDS+1,4);   // 4 words in a block

		alias workingKey W;

		//
		// copy the key into the round key array
		//

		t = 0;
		uint i = 0;
		while (i < key.length)
		{
			W[t >> 2][t & 3] = (key[i]&0xff) | ((key[i+1]&0xff) << 8) | ((key[i+2]&0xff) << 16) | (key[i+3] << 24);
			i+=4;
			t++;
		}

		//
		// while not enough round key material calculated
		// calculate new values
		//
		uint k = (ROUNDS + 1) << 2;
		for (i = KC; (i < k); i++)
		{
			int temp = W[(i-1)>>2][(i-1)&3];
			if ((i % KC) == 0)
			{
				temp = subWord(rotateRight(temp, 8)) ^ rcon[(i / KC)-1];
			}
			else if ((KC > 6) && ((i % KC) == 4))
			{
				temp = subWord(temp);
			}

			W[i>>2][i&3] = W[(i - KC)>>2][(i-KC)&3] ^ temp;
		}

		if (!forEncryption)
		{
			for (int j = 1; j < ROUNDS; j++)
			{
				for (i = 0; i < 4; i++)
				{
					W[j][i] = inv_mcol(W[j][i]);
				}
			}
		}
	}

	
	@safe
	@nogc
	private void unpackBlock(in ubyte[] bytes) nothrow
	in {
		assert(bytes.length == 16, "invalid input length ");
	}
	body {
		C0 = (bytes[0]);
		C0 |= (bytes[1]) << 8;
		C0 |= (bytes[2]) << 16;
		C0 |= bytes[3] << 24;
		

		C1 = (bytes[4]);
		C1 |= (bytes[5]) << 8;
		C1 |= (bytes[6]) << 16;
		C1 |= bytes[7] << 24;
		

		C2 = (bytes[8]);
		C2 |= (bytes[9]) << 8;
		C2 |= (bytes[10]) << 16;
		C2 |= bytes[11] << 24;

		
		C3 = (bytes[12]);
		C3 |= (bytes[13]) << 8;
		C3 |= (bytes[14]) << 16;
		C3 |= bytes[15] << 24;
		
	}

	@safe
	@nogc
	private void packBlock(ubyte[] bytes) nothrow
	{
		bytes[0] = cast(ubyte)C0;
		bytes[1] = cast(ubyte)(C0 >> 8);
		bytes[2] = cast(ubyte)(C0 >> 16);
		bytes[3] = cast(ubyte)(C0 >> 24);

		bytes[4] = cast(ubyte)C1;
		bytes[5] = cast(ubyte)(C1 >> 8);
		bytes[6] = cast(ubyte)(C1 >> 16);
		bytes[7] = cast(ubyte)(C1 >> 24);

		bytes[8] = cast(ubyte)C2;
		bytes[9] = cast(ubyte)(C2 >> 8);
		bytes[10] = cast(ubyte)(C2 >> 16);
		bytes[11] = cast(ubyte)(C2 >> 24);

		bytes[12] = cast(ubyte)C3;
		bytes[13] = cast(ubyte)(C3 >> 8);
		bytes[14] = cast(ubyte)(C3 >> 16);
		bytes[15] = cast(ubyte)(C3 >> 24);
	}

	@safe
	@nogc
	private void encryptBlock() nothrow
	{
		alias workingKey wk;
		uint r, r0, r1, r2, r3;

		C0 ^= wk[0][0];
		C1 ^= wk[0][1];
		C2 ^= wk[0][2];
		C3 ^= wk[0][3];

		r = 1;

		while (r < ROUNDS - 1)
		{
			r0 = T0[C0&255] ^ rotateRight(T0[(C1>>8)&255], 24) ^ rotateRight(T0[(C2>>16)&255],16) ^ rotateRight(T0[(C3>>24)&255],8) ^ wk[r][0];
			r1 = T0[C1&255] ^ rotateRight(T0[(C2>>8)&255], 24) ^ rotateRight(T0[(C3>>16)&255], 16) ^ rotateRight(T0[(C0>>24)&255], 8) ^ wk[r][1];
			r2 = T0[C2&255] ^ rotateRight(T0[(C3>>8)&255], 24) ^ rotateRight(T0[(C0>>16)&255], 16) ^ rotateRight(T0[(C1>>24)&255], 8) ^ wk[r][2];
			r3 = T0[C3&255] ^ rotateRight(T0[(C0>>8)&255], 24) ^ rotateRight(T0[(C1>>16)&255], 16) ^ rotateRight(T0[(C2>>24)&255], 8) ^ wk[r++][3];
			C0 = T0[r0&255] ^ rotateRight(T0[(r1>>8)&255], 24) ^ rotateRight(T0[(r2>>16)&255], 16) ^ rotateRight(T0[(r3>>24)&255], 8) ^ wk[r][0];
			C1 = T0[r1&255] ^ rotateRight(T0[(r2>>8)&255], 24) ^ rotateRight(T0[(r3>>16)&255], 16) ^ rotateRight(T0[(r0>>24)&255], 8) ^ wk[r][1];
			C2 = T0[r2&255] ^ rotateRight(T0[(r3>>8)&255], 24) ^ rotateRight(T0[(r0>>16)&255], 16) ^ rotateRight(T0[(r1>>24)&255], 8) ^ wk[r][2];
			C3 = T0[r3&255] ^ rotateRight(T0[(r0>>8)&255], 24) ^ rotateRight(T0[(r1>>16)&255], 16) ^ rotateRight(T0[(r2>>24)&255], 8) ^ wk[r++][3];
		}

		r0 = T0[C0&255] ^ rotateRight(T0[(C1>>8)&255], 24) ^ rotateRight(T0[(C2>>16)&255], 16) ^ rotateRight(T0[(C3>>24)&255], 8) ^ wk[r][0];
		r1 = T0[C1&255] ^ rotateRight(T0[(C2>>8)&255], 24) ^ rotateRight(T0[(C3>>16)&255], 16) ^ rotateRight(T0[(C0>>24)&255], 8) ^ wk[r][1];
		r2 = T0[C2&255] ^ rotateRight(T0[(C3>>8)&255], 24) ^ rotateRight(T0[(C0>>16)&255], 16) ^ rotateRight(T0[(C1>>24)&255], 8) ^ wk[r][2];
		r3 = T0[C3&255] ^ rotateRight(T0[(C0>>8)&255], 24) ^ rotateRight(T0[(C1>>16)&255], 16) ^ rotateRight(T0[(C2>>24)&255], 8) ^ wk[r++][3];

		// the final round's table is a simple function of S so we don't use a whole other four tables for it

		C0 = (S[r0&255]) ^ ((S[(r1>>8)&255])<<8) ^ ((S[(r2>>16)&255])<<16) ^ (S[(r3>>24)&255]<<24) ^ wk[r][0];
		C1 = (S[r1&255]) ^ ((S[(r2>>8)&255])<<8) ^ ((S[(r3>>16)&255])<<16) ^ (S[(r0>>24)&255]<<24) ^ wk[r][1];
		C2 = (S[r2&255]) ^ ((S[(r3>>8)&255])<<8) ^ ((S[(r0>>16)&255])<<16) ^ (S[(r1>>24)&255]<<24) ^ wk[r][2];
		C3 = (S[r3&255]) ^ ((S[(r0>>8)&255])<<8) ^ ((S[(r1>>16)&255])<<16) ^ (S[(r2>>24)&255]<<24) ^ wk[r][3];

	}

	@safe @nogc
	private void decryptBlock() nothrow
	{
		alias workingKey wk;

		uint r, r0, r1, r2, r3;

		C0 ^= wk[ROUNDS][0];
		C1 ^= wk[ROUNDS][1];
		C2 ^= wk[ROUNDS][2];
		C3 ^= wk[ROUNDS][3];

		r = ROUNDS-1;

		while (r>1)
		{
			r0 = Tinv0[C0&255] ^ rotateRight(Tinv0[(C3>>8)&255], 24) ^ rotateRight(Tinv0[(C2>>16)&255], 16) ^ rotateRight(Tinv0[(C1>>24)&255], 8) ^ wk[r][0];
			r1 = Tinv0[C1&255] ^ rotateRight(Tinv0[(C0>>8)&255], 24) ^ rotateRight(Tinv0[(C3>>16)&255], 16) ^ rotateRight(Tinv0[(C2>>24)&255], 8) ^ wk[r][1];
			r2 = Tinv0[C2&255] ^ rotateRight(Tinv0[(C1>>8)&255], 24) ^ rotateRight(Tinv0[(C0>>16)&255], 16) ^ rotateRight(Tinv0[(C3>>24)&255], 8) ^ wk[r][2];
			r3 = Tinv0[C3&255] ^ rotateRight(Tinv0[(C2>>8)&255], 24) ^ rotateRight(Tinv0[(C1>>16)&255], 16) ^ rotateRight(Tinv0[(C0>>24)&255], 8) ^ wk[r--][3];
			C0 = Tinv0[r0&255] ^ rotateRight(Tinv0[(r3>>8)&255], 24) ^ rotateRight(Tinv0[(r2>>16)&255], 16) ^ rotateRight(Tinv0[(r1>>24)&255], 8) ^ wk[r][0];
			C1 = Tinv0[r1&255] ^ rotateRight(Tinv0[(r0>>8)&255], 24) ^ rotateRight(Tinv0[(r3>>16)&255], 16) ^ rotateRight(Tinv0[(r2>>24)&255], 8) ^ wk[r][1];
			C2 = Tinv0[r2&255] ^ rotateRight(Tinv0[(r1>>8)&255], 24) ^ rotateRight(Tinv0[(r0>>16)&255], 16) ^ rotateRight(Tinv0[(r3>>24)&255], 8) ^ wk[r][2];
			C3 = Tinv0[r3&255] ^ rotateRight(Tinv0[(r2>>8)&255], 24) ^ rotateRight(Tinv0[(r1>>16)&255], 16) ^ rotateRight(Tinv0[(r0>>24)&255], 8) ^ wk[r--][3];
		}

		r0 = Tinv0[C0&255] ^ rotateRight(Tinv0[(C3>>8)&255], 24) ^ rotateRight(Tinv0[(C2>>16)&255], 16) ^ rotateRight(Tinv0[(C1>>24)&255], 8) ^ wk[r][0];
		r1 = Tinv0[C1&255] ^ rotateRight(Tinv0[(C0>>8)&255], 24) ^ rotateRight(Tinv0[(C3>>16)&255], 16) ^ rotateRight(Tinv0[(C2>>24)&255], 8) ^ wk[r][1];
		r2 = Tinv0[C2&255] ^ rotateRight(Tinv0[(C1>>8)&255], 24) ^ rotateRight(Tinv0[(C0>>16)&255], 16) ^ rotateRight(Tinv0[(C3>>24)&255], 8) ^ wk[r][2];
		r3 = Tinv0[C3&255] ^ rotateRight(Tinv0[(C2>>8)&255], 24) ^ rotateRight(Tinv0[(C1>>16)&255], 16) ^ rotateRight(Tinv0[(C0>>24)&255], 8) ^ wk[r][3];

		// the final round's table is a simple function of Si so we don't use a whole other four tables for it

		C0 = (Si[r0&255]) ^ ((Si[(r3>>8)&255])<<8) ^ ((Si[(r2>>16)&255])<<16) ^ (Si[(r1>>24)&255]<<24) ^ wk[0][0];
		C1 = (Si[r1&255]) ^ ((Si[(r0>>8)&255])<<8) ^ ((Si[(r3>>16)&255])<<16) ^ (Si[(r2>>24)&255]<<24) ^ wk[0][1];
		C2 = (Si[r2&255]) ^ ((Si[(r1>>8)&255])<<8) ^ ((Si[(r0>>16)&255])<<16) ^ (Si[(r3>>24)&255]<<24) ^ wk[0][2];
		C3 = (Si[r3&255]) ^ ((Si[(r2>>8)&255])<<8) ^ ((Si[(r1>>16)&255])<<16) ^ (Si[(r0>>24)&255]<<24) ^ wk[0][3];
	}
}
