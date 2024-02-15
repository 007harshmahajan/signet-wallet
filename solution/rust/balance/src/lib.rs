#![allow(unused)]

use std::{arch::x86_64::_mm_sha256msg1_epu32, hash, process::Command, ptr::hash};

use bitcoin_hashes::hash160;
use bs58;
use hmac::Hmac;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;

// Provided by administrator
pub const WALLET_NAME: &str = "wallet_152";
pub const EXTENDED_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPdisufuN1WwxfQGPpBAm9DD11kyTANuq8LDBh6nGFj1kaddVP5U9if6LypPkdnUkuxLMUFkEyMNDSreXx12hxJC6WsboYbbs";

//wpkh(tprv8ZgxMBicQKsPdisufuN1WwxfQGPpBAm9DD11kyTANuq8LDBh6nGFj1kaddVP5U9if6LypPkdnUkuxLMUFkEyMNDSreXx12hxJC6WsboYbbs/84h/1h/0h/0/*)#6jjugh90
#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // Add relevant error variants for various cases.
}

struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 33],
}

// final wallet state struct
pub struct WalletState {
    utxos: Vec<Vec<u8>>,
    witness_programs: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
    private_keys: Vec<Vec<u8>>,
}

impl WalletState {
    // Given a WalletState find the balance in satoshis
    pub fn balance(&self) -> u32 {
        self.utxos.iter().map(|utxo| self.get_value_from_utxo(utxo)).sum()
    }

    // Helper function to extract the value from a UTXO
    fn get_value_from_utxo(&self, utxo: &[u8]) -> u32 {
        // Assuming the value is stored at a specific index in the UTXO
        // You should adjust this according to your actual data structure
        // For example, if the value is stored in the first 4 bytes, you would do something like this:
        // u32::from_le_bytes(utxo[..4].try_into().unwrap())
        unimplemented!("Implement logic to extract value from UTXO")
    }
}


// Decode a base58 string into an array of bytes
fn base58_decode(base58_string: &str) -> Vec<u8> {
    let mut decoded_bytes = bs58::decode(base58_string).into_vec().expect("Invalid base58 string");
    decoded_bytes.truncate(decoded_bytes.len() - 4);
    decoded_bytes
    // BONUS points for verifying checksum
}

// Deserialize the extended pubkey bytes and return a ExKey object
// Bip32 Serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
// 32 bytes: the chain code
// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
fn deserialize_key(bytes: &[u8]) -> ExKey {
    if bytes.len() < 78 {
        panic!("Invalid input: insufficient bytes for BIP32 key");
    }

    let version = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let depth = [bytes[4]];
    let finger_print = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
    let child_number = u32::from_be_bytes(bytes[9..13].try_into().unwrap());

    let mut chaincode = [0u8; 32];
    chaincode.copy_from_slice(&bytes[13..45]);

    let mut key = [0u8; 33];
    key.copy_from_slice(&bytes[45..78]);

    ExKey {
        version: version.to_be_bytes(),
        depth,
        finger_print: finger_print.to_be_bytes(),
        child_number: child_number.to_be_bytes(),
        chaincode,
        key,
    }
}

// Derive the secp256k1 compressed public key from a given private key
// BONUS POINTS: Implement ECDSA yourself and multiply your key by the generator point!
fn derive_public_key_from_private(key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(key).expect("Invalid private key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_public_key = public_key.serialize();

    compressed_public_key.to_vec()
}

// Perform a BIP32 parent private key -> child private key derivation
// Return a derived child Xpriv, given a child_number. Check the struct docs for APIs.
// Key derivation steps: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
fn derive_priv_child(key: ExKey, child_num: u32) -> ExKey {
    let (kpar, cpar) = (&key.key, &key.chaincode);
    let is_hardened = child_num >= 0x80000000;
    let mut data = Vec::new();

    type HmacSha512 = HmacSha512;
    if is_hardened {
        data.push(0x00);
    }
    data.extend_from_slice(&kpar);
    data.extend_from_slice(&child_num.to_be_bytes());

    let mut hmac = HmacSha512::new_from_slice(&cpar).unwrap();
    hmac.update(&data);
    let result = hmac.finalize().into_bytes();

    let il = &result[0..32];
    let ir = &result[32..64];

    let mut ki_bytes = [0u8; 32];
    ki_bytes.copy_from_slice(il);
    let mut kpar_bytes = [0u8; 32];
    kpar_bytes[1..].copy_from_slice(&kpar[1..]);

    // Compute ki = IL + kpar (mod n)
    let mut ki = [0u8; 32];
    let mut carry = 0;
    for i in (0..32).rev() {
        let sum = il[i] + kpar_bytes[i] + carry;
        ki[i] = sum % 256;
        carry = sum / 256;
    }

    let curve_order = &secp256k1::constants::CURVE_ORDER;
    if ki >= *curve_order {
        panic!("Invalid child key: ki is greater than or equal to the curve order");
    }

    let mut child_key = ExKey {
        version: key.version,
        depth: [key.depth[0] + 1],
        finger_print: key.finger_print,
        child_number: child_num.to_be_bytes(),
        chaincode: ir.try_into().unwrap(),
        key: [0; 33],
    };

    child_key.key[1..].copy_from_slice(&ki);

    child_key
}


// Given an extended private key and a BIP32 derivation path, compute the child private key found at the path
// Derivation paths are strings like "m/0'/1/2h/2"
fn get_child_key_at_path(key: ExKey, derivation_path: &str) -> ExKey {
    let mut derived_key = key.clone();
    
    for path_segment in derivation_path.split('/') {
        if path_segment.is_empty() {
            continue;
        }
        
        let (index, hardened) = if path_segment.ends_with('\'') || path_segment.ends_with('h') {
            (path_segment[..path_segment.len() - 1].parse::<u32>().unwrap(), true)
        } else {
            (path_segment.parse::<u32>().unwrap(), false)
        };
        
        let child_number = &key.child_number;
        
        derived_key = derived_key.derive_priv(&Secp256k1::new(), &child_number)
            .expect("Derivation failed");
    }
    
    derived_key
}

// Compute the first N child private keys.
// Return an array of keys.
fn get_keys_at_child_key_path(child_key: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut main_keys = child_key.clone();;
    let mut current_key:ExKey;
    let mut current_index = 0;

    let mut vec:Vec<ExKey>;

    while current_index < num_keys {

        let data = derive_priv_child(current_key, current_index);
        vec.push(data);
        
        current_index += 1;
        current_key = data;
    }

    vec
}

// Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key
// Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
// so we can find our received transactions in blocks
// These are segwit version 0 pay-to-public-key-hash witness programs
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    let hash = hash160::Hash::hash(pubkey);
    
    let mut program = vec![0x00]; // Witness version
    program.extend_from_slice(&hash[..]); // Program length and hash160(pubkey)
    
    program
}

// Assuming Bitcoin Core is running and connected to signet using default datadir,
// execute an RPC and return its value or error message.
// https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
// Examples: bcli("getblockcount")
//            bcli("getblockhash 100")
fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let args = cmd.split(' ').collect::<Vec<&str>>();

    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;

    if result.status.success() {
        return Ok(result.stdout);
    } else {
        let error_message = String::from_utf8_lossy(&result.stderr).into_owned();
        Err(BalanceError::BitcoinCliError(error_message))
    }
}

// public function that will be called by `run` here as well as the spend program externally
pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {
    // Deserialize the provided extended private key
    
    // Derive the key and chaincode at the path in the descriptor (`84h/1h/0h/0`)

    // Get the child key at the derivation path

    // Compute 2000 private keys from the child key path
    // For each private key, collect compressed public keys and witness programs
    let private_keys = vec![];
    let public_keys = vec![];
    let witness_programs = vec![];

    // Collect outgoing and spending txs from a block scan
    let mut outgoing_txs: Vec<Vec<u8>> = vec![];
    let mut spending_txs: Vec<Vec<u8>> = vec![];
    let mut utxos: Vec<Vec<u8>> = vec![];

    // Scan blocks 0 to 300 for transactions
    // Check every tx input (witness) for our own compressed public keys. These are coins we have spent.
    // Check every tx output for our own witness programs. These are coins we have received.
    // Keep track of outputs by their outpoint so we can check if it was spent later by an input
    // Collect outputs that have not been spent into a utxo set
    // Return Wallet State
    Ok(WalletState {
        utxos,
        public_keys,
        private_keys,
        witness_programs,
    })
}
