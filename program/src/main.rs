use blake2::{Blake2s, Digest};
use core::hash;
use ethabi::ethereum_types::U256;
use ethabi::{param_type, Function, Param, ParamType, Token, TupleParam};
use hex::{FromHex, ToHex};
use rlp::{Rlp, RlpStream};
use secp256k1::ecdsa::{self, RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::Deserialize;
use serde_json::Result;
use std::hash::Hash;
use std::io::BufReader;
use std::str::{Bytes, FromStr};
use std::{fs::File, thread::current};
use tiny_keccak::{Hasher, Keccak};

const ZKSYNC_MAINNNET_OPERATOR: &str = "0d3250c3d5facb74ac15834096397a3ef790ec99";

#[derive(Deserialize, Debug)]
struct TxProof {
    transaction_id: String,
    #[serde(rename = "transactionsInBlock")]
    transactions_in_block: Vec<String>,
    #[serde(rename = "blockNumber")]
    block_number: u64,
    #[serde(rename = "blockTimestamp")]
    block_timestamp: u64,
    #[serde(rename = "parentHash")]
    parent_hash: String,
    #[serde(rename = "storageProof")]
    storage_proof: StorageProof,
    #[serde(rename = "batchRoothash")]
    batch_root_hash: String,

    #[serde(rename = "batchCommitTx")]
    batch_commit_tx: String,

    #[serde(rename = "batchNumber")]
    batch_number: u64,
}

#[derive(Deserialize, Debug)]
struct StorageProof {
    proof: Vec<String>,
    value: String,
    index: u64,
}

fn compute_keccak(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn compute_blake_hash(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Blake2s::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

impl StorageProof {
    pub fn verify_storage_proof(&self, account: &str, key: &str, root_hash: Vec<u8>) -> bool {
        let account = hex_str_to_bytes(account);
        let key = hex_str_to_bytes(key);

        if account.len() != 20 || key.len() != 32 {
            println!("Wrong key / account lenghts");
            return false;
        }

        let tree_key = [vec![0u8; 12], account, key].concat();

        println!("Tree key: {:?}", hex::encode(&tree_key));

        let tree_key_hash = compute_blake_hash(&tree_key);

        println!("blake tree key: {:?}", hex::encode(&tree_key_hash));

        let mut empty_hash = compute_blake_hash(&vec![0u8; 40]);
        let index = self.index.to_be_bytes();
        let value = hex_str_to_bytes(&self.value);
        if value.len() != 32 {
            println!("Invalid value length");
            return false;
        }

        let value_hash = compute_blake_hash(&[index.to_vec(), value].concat());

        println!("value hash : {:?}", hex::encode(&value_hash));

        // now we walk from the leaves up.
        let mut depth = 255;
        let mut current_hash = value_hash;
        for u64pos in (0..tree_key_hash.len()).step_by(8) {
            let slice = &tree_key_hash[u64pos..u64pos + 8];
            let u64byte =
                u64::from_le_bytes(slice.try_into().expect("slice with incorrect length"));
            // Bits are determining whether we are the left or right sibling.
            for i in 0..64 {
                let other_hash = match self.proof.get(depth) {
                    Some(proof_hash) => hex_str_to_bytes(&proof_hash),
                    None => empty_hash.clone(),
                };

                // update empty hash for the next level
                empty_hash = compute_blake_hash(&[empty_hash.clone(), empty_hash].concat());

                let bit = (u64byte >> i) & 1;
                current_hash = if bit == 1 {
                    compute_blake_hash(&[other_hash, current_hash].concat())
                } else {
                    compute_blake_hash(&[current_hash, other_hash].concat())
                };
                depth = depth.saturating_sub(1);
            }
        }

        if current_hash != root_hash {
            println!("Root hash doesn't match");
            return false;
        }

        true
    }
}

fn hex_str_to_bytes(hex_str: &str) -> Vec<u8> {
    // Check for and remove the "0x" prefix if it exists
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Decode the hex string to bytes
    let bytes = Vec::from_hex(hex_str).unwrap();

    bytes
}

fn calculate_transaction_rolling_hash(transaction_hashes: &Vec<String>) -> Vec<u8> {
    let mut prev: Vec<u8> = [0u8; 32].into();

    for entry in transaction_hashes.iter() {
        let mut hasher = Keccak::v256();
        hasher.update(prev.as_slice());
        let entry_as_bytes = hex_str_to_bytes(entry);
        hasher.update(entry_as_bytes.as_slice());

        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        prev = output.into();
    }
    prev
}

fn u64_to_solidity_u256(value: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    let value_bytes = value.to_be_bytes(); // Convert u64 to big-endian bytes

    // Copy the 8 bytes of the u64 value to the last 8 bytes of the 32-byte array
    result[24..32].copy_from_slice(&value_bytes);

    result
}

fn calculate_block_hash(
    block_number: u64,
    block_timestamp: u64,
    prev_block_hash: &[u8],
    rolling_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Keccak::v256();

    hasher.update(&u64_to_solidity_u256(block_number));

    hasher.update(&u64_to_solidity_u256(block_timestamp));

    hasher.update(prev_block_hash);
    hasher.update(rolling_hash);

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output.into()
}

fn get_key_for_recent_block(block_number: u64) -> String {
    const MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT: u64 = 11;
    format!(
        "0x{:064x}",
        block_number % 257 + MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT
    )
}

#[derive(Deserialize, Debug)]
struct BlobTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    pub to_address: String,
    pub value: u64,
    pub calldata: String,
    pub access_list: Vec<Vec<u8>>,
    pub max_fee_per_blob_gas: u64,
    pub blob_versioned_hashes: Vec<String>,
    pub signature: Signature,
}

#[derive(Deserialize, Debug)]
struct Signature {
    pub v: u32,
    pub r: String,
    pub s: String,
}

impl Signature {
    pub fn from_rlp(rlp: &Rlp, start_index: usize) -> Self {
        Signature {
            v: rlp.val_at(start_index).unwrap(),
            r: hex::encode(rlp.val_at::<Vec<u8>>(start_index + 1).unwrap()),
            s: hex::encode(rlp.val_at::<Vec<u8>>(start_index + 2).unwrap()),
        }
    }

    fn key_to_address(key: &PublicKey) -> String {
        let public_key_as_eth = &key.serialize_uncompressed()[1..];

        let h = compute_keccak(&public_key_as_eth);

        hex::encode(&h[12..])
    }

    pub fn verify_signature(&self, msg: &Message) -> Result<String> {
        let secp = Secp256k1::new();

        let recovery = RecoveryId::from_i32(self.v as i32).unwrap();

        let mut signature = [0u8; 64];

        signature[..32].copy_from_slice(&hex_str_to_bytes(&self.r));
        signature[32..].copy_from_slice(&hex_str_to_bytes(&self.s));

        let sig = RecoverableSignature::from_compact(&signature, recovery).unwrap();
        let key = secp.recover_ecdsa(&msg, &sig).unwrap();

        let sig = ecdsa::Signature::from_compact(&signature).unwrap();

        let address = Signature::key_to_address(&key);

        println!("Address is: {:?}", address);

        secp.verify_ecdsa(&msg, &sig, &key).unwrap();
        Ok(address)
    }
}

impl rlp::Encodable for Signature {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&self.v)
            .append(&hex_str_to_bytes(&self.r))
            .append(&hex_str_to_bytes(&self.s));
    }
}

impl rlp::Encodable for BlobTransaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        self.rlp_append_without_signature(s);
        s.append(&self.signature);
        s.finalize_unbounded_list();
    }
}

impl BlobTransaction {
    fn from_rlp(rlp: &Rlp) -> Self {
        BlobTransaction {
            chain_id: rlp.val_at(0).unwrap(),
            nonce: rlp.val_at(1).unwrap(),
            max_priority_fee: rlp.val_at(2).unwrap(),
            max_fee_per_gas: rlp.val_at(3).unwrap(),
            gas_limit: rlp.val_at(4).unwrap(),
            to_address: hex::encode(rlp.val_at::<Vec<u8>>(5).unwrap()),
            value: rlp.val_at(6).unwrap(),
            calldata: hex::encode(rlp.val_at::<Vec<u8>>(7).unwrap()),
            access_list: rlp.at(8).unwrap().as_list().unwrap(),
            max_fee_per_blob_gas: rlp.val_at(9).unwrap(),
            blob_versioned_hashes: rlp
                .at(10)
                .unwrap()
                .as_list()
                .unwrap()
                .into_iter()
                .map(|h: Vec<u8>| hex::encode(h))
                .collect(),
            signature: Signature::from_rlp(rlp, 11),
        }
    }

    fn rlp_append_without_signature(&self, s: &mut rlp::RlpStream) {
        let blob_hash_bytes: Vec<Vec<u8>> = self
            .blob_versioned_hashes
            .iter()
            .map(|k| hex_str_to_bytes(k))
            .collect();

        s.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.max_priority_fee)
            .append(&self.max_fee_per_gas)
            .append(&self.gas_limit)
            .append(&hex_str_to_bytes(&self.to_address))
            .append(&self.value)
            .append(&hex_str_to_bytes(&self.calldata))
            .append_list::<Vec<u8>, Vec<u8>>(&self.access_list)
            .append(&self.max_fee_per_blob_gas)
            .append_list::<Vec<u8>, Vec<u8>>(&blob_hash_bytes);
    }

    fn transaction_hash(&self) -> String {
        let mut hasher = Keccak::v256();
        hasher.update(&[3u8]);
        hasher.update(&rlp::encode(self));
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        hex::encode(output)
    }

    fn pre_sign_hash(&self) -> [u8; 32] {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        self.rlp_append_without_signature(&mut stream);
        stream.finalize_unbounded_list();

        let mut hasher = Keccak::v256();
        hasher.update(&[3u8]);
        hasher.update(&stream.out());
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        output
    }

    fn verify_signature(&self) -> bool {
        let hash = self.pre_sign_hash();
        let msg = Message::from_digest(hash);

        let address = self.signature.verify_signature(&msg).unwrap();

        if address != ZKSYNC_MAINNNET_OPERATOR {
            println!("Wrong signer");
            return false;
        }
        true
    }
}
#[derive(Deserialize, Debug)]
struct CommitBatchInfo {
    batch_number: U256,
    state_root: Vec<u8>,
}

impl CommitBatchInfo {
    fn from_token(token: &Token) -> Self {
        let tokens = token.clone().into_tuple().unwrap();

        Self {
            batch_number: tokens[0].clone().into_uint().unwrap(),
            state_root: tokens[3].clone().into_fixed_bytes().unwrap(),
        }
    }
}

struct CommitCalldata {
    pub batch_info_list: Vec<CommitBatchInfo>,
}
impl CommitCalldata {
    fn from_input(input: &Vec<u8>) -> Self {
        let function = Function {
            name: "commitBatchesSharedBridge".to_string(),
            inputs: vec![
                Param {
                    name: "chain_id".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "prev".to_string(),
                    kind: ParamType::Tuple(vec![
                        ParamType::Uint(64),
                        ParamType::FixedBytes(32),
                        ParamType::Uint(64),
                        ParamType::Uint(256),
                        ParamType::FixedBytes(32),
                        ParamType::FixedBytes(32),
                        ParamType::Uint(256),
                        ParamType::FixedBytes(32),
                    ]),

                    //uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32
                    internal_type: None,
                },
                Param {
                    name: "new".to_string(),
                    // uint64,uint64,uint64,bytes32,uint256,bytes32,bytes32,bytes32,bytes,bytes
                    kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Uint(64),
                        ParamType::Uint(64),
                        ParamType::Uint(64),
                        ParamType::FixedBytes(32),
                        ParamType::Uint(256),
                        ParamType::FixedBytes(32),
                        ParamType::FixedBytes(32),
                        ParamType::FixedBytes(32),
                        ParamType::Bytes,
                        ParamType::Bytes,
                    ]))),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: None,
            state_mutability: ethabi::StateMutability::NonPayable,
        };

        let selector = hex::encode(&input[..4]);
        // commitBatchesSharedBridge
        if selector != hex::encode(function.short_signature()) {
            panic!("Wrong selector");
        }

        let t = function.decode_input(&input[4..]).unwrap();
        let batch_info_list = t[2]
            .clone()
            .into_array()
            .unwrap()
            .iter()
            .map(|e| CommitBatchInfo::from_token(e))
            .collect::<Vec<_>>();

        println!("parsed: {:?}", batch_info_list);

        CommitCalldata { batch_info_list }
    }

    fn get_batch_stateroot(&self, batch_number: u64) -> Option<Vec<u8>> {
        self.batch_info_list
            .iter()
            .find(|x| x.batch_number == U256::try_from(batch_number).unwrap())
            .map(|entry| entry.state_root.clone())
    }
}

fn verify_batch_commit_tx(commit_tx: &str, batch_number: u64, root_hash: &str) -> bool {
    let commit_tx = hex_str_to_bytes(commit_tx);

    // Just for sanity checking.
    println!(
        "Commit batch Tx hash is {:?}",
        hex::encode(compute_keccak(&commit_tx))
    );

    if commit_tx[0] != 3 {
        println!("Only supporting type 3 transactions - blobs");
        return false;
    }

    let rlp = Rlp::new(&commit_tx[1..]);

    let blob_transaction = BlobTransaction::from_rlp(&rlp);

    println!("Blob tx: {:?}", blob_transaction);
    println!("Blob tx hash is {:?}", blob_transaction.transaction_hash());

    blob_transaction.verify_signature();

    let commit_calldata = CommitCalldata::from_input(&hex_str_to_bytes(&blob_transaction.calldata));

    let root_hash_in_commit = commit_calldata.get_batch_stateroot(batch_number).unwrap();
    if root_hash_in_commit != hex_str_to_bytes(root_hash) {
        println!("Wrong root hashes -- fail");
        return false;
    }

    true
}

const SYSTEM_CONTEXT_ADDRESS: &str = "0x000000000000000000000000000000000000800B";

fn verify_proof(proof: &TxProof) -> bool {
    println!("Checking proof for transaction {:?}", proof.transaction_id);

    if !proof.transactions_in_block.contains(&proof.transaction_id) {
        return false;
    }

    let rolling_hash = calculate_transaction_rolling_hash(&proof.transactions_in_block);

    println!(
        "Rolling hash is {:?}",
        rolling_hash.as_slice().encode_hex::<String>()
    );

    let block_hash = calculate_block_hash(
        proof.block_number,
        proof.block_timestamp,
        &hex_str_to_bytes(&proof.parent_hash),
        &rolling_hash,
    );

    println!(
        "block hash is {:?}",
        block_hash.as_slice().encode_hex::<String>()
    );

    let storage_proof_value = hex_str_to_bytes(&proof.storage_proof.value);
    if storage_proof_value != block_hash {
        println!("Invalid value in storage proof");
        return false;
    }

    if proof.storage_proof.verify_storage_proof(
        SYSTEM_CONTEXT_ADDRESS,
        &get_key_for_recent_block(proof.block_number),
        hex_str_to_bytes(&proof.batch_root_hash),
    ) {
        println!("STORAGE VERIFIED")
    } else {
        println!("STORAGE VERIFICATION FAILED");
        return false;
    }

    // Now that we know that storage matches, we have to check that this batch_root_hash was
    // really included.

    if verify_batch_commit_tx(
        &proof.batch_commit_tx,
        proof.batch_number,
        &proof.batch_root_hash,
    ) {
        println!("COMMIT VERIFIED");
    } else {
        println!("COMMIT VERIFICATION FAILED");
        return false;
    }

    true
}

fn main() -> Result<()> {
    // Open the file in read-only mode.
    let file = File::open("../output.json").unwrap();
    let reader = BufReader::new(file);

    // Parse the JSON into the Person struct.
    let tx_proof: TxProof = serde_json::from_reader(reader)?;

    // Print the parsed data.
    println!("{:?}", tx_proof);
    let result = verify_proof(&tx_proof);
    println!("Verification: {:?}", result);

    Ok(())
}
