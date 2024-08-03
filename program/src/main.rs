use core::hash;
use hex::{FromHex, ToHex};
use serde::Deserialize;
use serde_json::Result;
use std::fs::File;
use std::io::BufReader;
use tiny_keccak::{Hasher, Keccak};

#[derive(Deserialize, Debug)]
struct TxProof {
    transaction_id: String,
    transactionsInBlock: Vec<String>,
    blockNumber: u64,
    blockTimestamp: u64,
    parentHash: String,
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

fn verify_proof(proof: &TxProof) -> bool {
    if !proof.transactionsInBlock.contains(&proof.transaction_id) {
        return false;
    }

    let rolling_hash = calculate_transaction_rolling_hash(&proof.transactionsInBlock);

    println!(
        "Rolling hash is {:?}",
        rolling_hash.as_slice().encode_hex::<String>()
    );

    let block_hash = calculate_block_hash(
        proof.blockNumber,
        proof.blockTimestamp,
        &hex_str_to_bytes(&proof.parentHash),
        &rolling_hash,
    );

    println!(
        "block hash is {:?}",
        block_hash.as_slice().encode_hex::<String>()
    );

    // TODO: storage proof verification is next.

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
