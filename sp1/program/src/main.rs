//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolType;
use fibonacci_lib::PublicValuesStruct;
use tx_verifier::{
    hex_str_to_bytes, verify_nft_proof, verify_proof, NFTOwnership, NFTProof, TokenTransfer,
    TxProof,
};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.

    let json_data = sp1_zkvm::io::read::<String>();

    let tx_proof: Result<TxProof, serde_json::Error> = serde_json::from_str(&json_data);

    let bytes = if let Ok(tx_proof) = tx_proof {
        let tx_id = tx_proof.transaction_id.clone();

        verify_proof(&tx_proof).unwrap();
        let token_transfer = TokenTransfer::try_from(tx_proof).unwrap();

        let mut tmp = [0u8; 32];
        token_transfer.amount.to_big_endian(&mut tmp);

        PublicValuesStruct::abi_encode(&PublicValuesStruct {
            struct_type: U256::from(0),
            sender: Address::from_slice(token_transfer.from.as_bytes()),
            receiver: Address::from_slice(token_transfer.to.as_bytes()),
            token: Address::from_slice(token_transfer.token.as_bytes()),
            amount: U256::from_be_bytes(tmp),
            tx_id: hex_str_to_bytes(&tx_id).as_slice().try_into().unwrap(),
            nft: Address::ZERO,
            owner: Address::ZERO,
            batch_number: U256::ZERO,
            slot_position: U256::ZERO,
        })
    } else {
        let proof: NFTProof = serde_json::from_str(&json_data).unwrap();

        verify_nft_proof(&proof).unwrap();
        let nft_ownership = NFTOwnership::try_from(proof).unwrap();

        PublicValuesStruct::abi_encode(&PublicValuesStruct {
            struct_type: U256::from(1),
            sender: Address::ZERO,
            receiver: Address::ZERO,
            token: Address::ZERO,
            amount: U256::ZERO,
            tx_id: [0u8; 32].try_into().unwrap(),
            nft: Address::from_slice(nft_ownership.nft.as_bytes()),
            owner: Address::from_slice(nft_ownership.owner.as_bytes()),
            batch_number: U256::from(nft_ownership.batch),
            slot_position: U256::from(nft_ownership.position),
        })
    };

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
