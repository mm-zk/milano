use blake2::{Blake2s, Digest};
use ethabi::ethereum_types::U256;
use ethabi::{Address, Function, Param, ParamType, Token};
use hex::FromHex;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::VerifyingKey;
use rlp::{Rlp, RlpStream};
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

const ZKSYNC_MAINNNET_OPERATOR: &str = "0d3250c3d5facb74ac15834096397a3ef790ec99";

#[derive(Deserialize, Debug)]
pub struct TxProof {
    pub transaction_id: String,
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

    #[serde(rename = "txFrom")]
    pub tx_from: String,
    #[serde(rename = "txTo")]
    pub tx_to: String,

    #[serde(rename = "txCalldata")]
    pub tx_calldata: String,

    #[serde(rename = "txBody")]
    tx_body: String,
}

#[derive(Deserialize, Debug)]
struct StorageProof {
    proof: Vec<String>,
    value: String,
    index: u64,
}

// Compute keccak hash for a given bytes.
fn compute_keccak(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

// Computes Blake2s hash.
fn compute_blake_hash(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Blake2s::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

impl StorageProof {
    pub fn verify_storage_proof(
        &self,
        account: &str,
        key: &str,
        root_hash: Vec<u8>,
    ) -> Result<(), String> {
        let account = hex_str_to_bytes(account);
        let key = hex_str_to_bytes(key);

        if account.len() != 20 || key.len() != 32 {
            return Err("Wrong key / account lenghts".to_owned());
        }

        let tree_key = [vec![0u8; 12], account, key].concat();

        println!("Tree key: {:?}", hex::encode(&tree_key));

        let tree_key_hash = compute_blake_hash(&tree_key);

        println!("blake tree key: {:?}", hex::encode(&tree_key_hash));

        let mut empty_hash = compute_blake_hash(&vec![0u8; 40]);
        let index = self.index.to_be_bytes();
        let value = hex_str_to_bytes(&self.value);
        if value.len() != 32 {
            return Err("Invalid value length".to_owned());
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
            return Err(format!(
                "Root hash doesn't match {:?} vs {:?}",
                current_hash, root_hash
            ));
        }

        Ok(())
    }
}

// Hex string (with potentially 0x prefix) to bytes.
pub fn hex_str_to_bytes(hex_str: &str) -> Vec<u8> {
    // Check for and remove the "0x" prefix if it exists
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Decode the hex string to bytes
    let bytes = Vec::from_hex(hex_str).unwrap();

    bytes
}

fn calculate_transaction_rolling_hash(transaction_hashes: &Vec<String>) -> [u8; 32] {
    let mut prev = [0u8; 32];

    for entry in transaction_hashes.iter() {
        prev = compute_keccak(&[&prev, hex_str_to_bytes(entry).as_slice()].concat());
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
) -> [u8; 32] {
    compute_keccak(
        &[
            &u64_to_solidity_u256(block_number),
            &u64_to_solidity_u256(block_timestamp),
            prev_block_hash,
            rolling_hash,
        ]
        .concat(),
    )
}

fn get_key_for_recent_block(block_number: u64) -> String {
    const MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT: u64 = 11;
    format!(
        "0x{:064x}",
        block_number % 257 + MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT
    )
}

#[derive(Deserialize, Debug)]

struct Type2Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    pub to_address: String,
    pub value: u64,
    pub calldata: String,
    pub access_list: Vec<Vec<u8>>,
    pub signature: Signature,
}

impl rlp::Encodable for Type2Transaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        self.rlp_append_without_signature(s);
        s.append(&self.signature);
        s.finalize_unbounded_list();
    }
}

impl Type2Transaction {
    fn from_rlp(rlp: &Rlp) -> Self {
        Type2Transaction {
            chain_id: rlp.val_at(0).unwrap(),
            nonce: rlp.val_at(1).unwrap(),
            max_priority_fee: rlp.val_at(2).unwrap(),
            max_fee_per_gas: rlp.val_at(3).unwrap(),
            gas_limit: rlp.val_at(4).unwrap(),
            to_address: hex::encode(rlp.val_at::<Vec<u8>>(5).unwrap()),
            value: rlp.val_at(6).unwrap(),
            calldata: hex::encode(rlp.val_at::<Vec<u8>>(7).unwrap()),
            access_list: rlp.at(8).unwrap().as_list().unwrap(),
            signature: Signature::from_rlp(rlp, 9),
        }
    }
    fn rlp_append_without_signature(&self, s: &mut rlp::RlpStream) {
        s.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.max_priority_fee)
            .append(&self.max_fee_per_gas)
            .append(&self.gas_limit)
            .append(&hex_str_to_bytes(&self.to_address))
            .append(&self.value)
            .append(&hex_str_to_bytes(&self.calldata))
            .append_list::<Vec<u8>, Vec<u8>>(&self.access_list);
    }
    fn transaction_hash(&self) -> String {
        let mut hasher = Keccak::v256();
        hasher.update(&[2u8]);
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
        hasher.update(&[2u8]);
        hasher.update(&stream.out());
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        output
    }

    fn verify_signature(&self) -> String {
        let hash = self.pre_sign_hash();

        let address = self.signature.verify_signature(hash).unwrap();

        address
    }
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

    fn key_to_address(key: &VerifyingKey) -> String {
        let pkey = key.to_encoded_point(false);

        let public_key_as_eth = &pkey.as_bytes()[1..];

        let h = compute_keccak(&public_key_as_eth);

        hex::encode(&h[12..])
    }

    pub fn verify_signature(&self, prehash: [u8; 32]) -> Result<String, String> {
        let r = hex_str_to_bytes(&self.r);
        let s = hex_str_to_bytes(&self.s);

        let r1: [u8; 32] = r.as_slice().try_into().unwrap();
        let s1: [u8; 32] = s.as_slice().try_into().unwrap();

        let sign1 = k256::ecdsa::Signature::from_scalars(r1, s1).unwrap();

        let recoveryid = k256::ecdsa::RecoveryId::try_from(self.v as u8).unwrap();

        let recovered_key =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &sign1, recoveryid).unwrap();

        let pkey = recovered_key.to_encoded_point(false);

        println!("k256 key -- {:?}", hex::encode(pkey.as_bytes()));
        let address = Signature::key_to_address(&recovered_key);

        println!("Address is: {:?}", address);

        recovered_key.verify_prehash(&prehash, &sign1).unwrap();

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

        let address = self.signature.verify_signature(hash).unwrap();

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

fn verify_batch_commit_tx(
    commit_tx: &str,
    batch_number: u64,
    root_hash: &str,
) -> Result<(), String> {
    let commit_tx = hex_str_to_bytes(commit_tx);

    // Just for sanity checking.
    println!(
        "Commit batch Tx hash is {:?}",
        hex::encode(compute_keccak(&commit_tx))
    );

    if commit_tx[0] != 3 {
        return Err("Only supporting type 3 transactions - blobs".to_owned());
    }

    let rlp = Rlp::new(&commit_tx[1..]);

    let blob_transaction = BlobTransaction::from_rlp(&rlp);

    println!("Blob tx: {:?}", blob_transaction);
    println!("Blob tx hash is {:?}", blob_transaction.transaction_hash());

    blob_transaction.verify_signature();

    let commit_calldata = CommitCalldata::from_input(&hex_str_to_bytes(&blob_transaction.calldata));

    let root_hash_in_commit = commit_calldata.get_batch_stateroot(batch_number).unwrap();
    if root_hash_in_commit != hex_str_to_bytes(root_hash) {
        return Err(format!(
            "Wrong root hashes -- fail {:?} vs {:?}",
            root_hash_in_commit,
            hex_str_to_bytes(root_hash)
        ));
    }

    Ok(())
}

const SYSTEM_CONTEXT_ADDRESS: &str = "0x000000000000000000000000000000000000800B";

pub fn verify_user_tx(proof: &TxProof) -> Result<(), String> {
    let tx_body = hex_str_to_bytes(&proof.tx_body);
    let rlp = Rlp::new(&tx_body[1..]);
    let user_tx = Type2Transaction::from_rlp(&rlp);
    if hex_str_to_bytes(&user_tx.transaction_hash()) != hex_str_to_bytes(&proof.transaction_id) {
        return Err("Tx body has different hash than transaction id".to_owned());
    }
    let signer = user_tx.verify_signature();
    if hex_str_to_bytes(&signer) != hex_str_to_bytes(&proof.tx_from) {
        return Err("Tx signer doesnt match tx from".to_owned());
    }

    if hex_str_to_bytes(&user_tx.to_address) != hex_str_to_bytes(&proof.tx_to) {
        return Err("TO address doesn't match".to_owned());
    }

    if hex_str_to_bytes(&user_tx.calldata) != hex_str_to_bytes(&proof.tx_calldata) {
        return Err("Calldata doesn't match".to_owned());
    }

    Ok(())
}

pub fn verify_proof(proof: &TxProof) -> Result<(), String> {
    println!("Checking proof for transaction {:?}", proof.transaction_id);

    verify_user_tx(proof)?;

    if !proof.transactions_in_block.contains(&proof.transaction_id) {
        return Err("transation not in block".to_owned());
    }

    let rolling_hash = calculate_transaction_rolling_hash(&proof.transactions_in_block);

    println!("Rolling hash is {:?}", hex::encode(rolling_hash));

    let block_hash = calculate_block_hash(
        proof.block_number,
        proof.block_timestamp,
        &hex_str_to_bytes(&proof.parent_hash),
        &rolling_hash,
    );

    println!("block hash is {:?}", hex::encode(block_hash));

    let storage_proof_value = hex_str_to_bytes(&proof.storage_proof.value);
    if storage_proof_value != block_hash {
        return Err("Invalid value in storage proof".to_owned());
    }

    proof
        .storage_proof
        .verify_storage_proof(
            SYSTEM_CONTEXT_ADDRESS,
            &get_key_for_recent_block(proof.block_number),
            hex_str_to_bytes(&proof.batch_root_hash),
        )
        .map_err(|e| format!("STORAGE VERIFICATION FAILED {:?}", e))?;

    // Now that we know that storage matches, we have to check that this batch_root_hash was
    // really included.

    verify_batch_commit_tx(
        &proof.batch_commit_tx,
        proof.batch_number,
        &proof.batch_root_hash,
    )
    .map_err(|e| format!("COMMIT VERIFICATION FAILED: {}", e))?;

    Ok(())
}

#[derive(Debug)]
pub struct TokenTransfer {
    pub from: Address,
    pub to: Address,
    pub token: Address,
    pub amount: U256,
}

impl TryFrom<TxProof> for TokenTransfer {
    type Error = String;

    fn try_from(value: TxProof) -> Result<Self, Self::Error> {
        let calldata = hex_str_to_bytes(&value.tx_calldata);
        if hex::encode(&calldata[..4]) != "a9059cbb" {
            return Err("Wrong selector".to_owned());
        }

        Ok(Self {
            from: Address::from_slice(&hex_str_to_bytes(&value.tx_from)),
            token: Address::from_slice(&hex_str_to_bytes(&value.tx_to)),
            to: Address::from_slice(&calldata[16..36]),
            amount: U256::from_big_endian(&calldata[36..68]),
        })
    }
}
