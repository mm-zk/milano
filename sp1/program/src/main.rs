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
use tx_verifier::{hex_str_to_bytes, verify_proof, TokenTransfer, TxProof};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    let json_data = sp1_zkvm::io::read::<String>();
    let tx_proof: TxProof = serde_json::from_str(&json_data).unwrap();

    let tx_id = tx_proof.transaction_id.clone();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.

    verify_proof(&tx_proof).unwrap();
    let token_transfer = TokenTransfer::try_from(tx_proof).unwrap();

    // Encode the public values of the program.

    let mut tmp = [0u8; 32];
    token_transfer.amount.to_big_endian(&mut tmp);

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        sender: Address::from_slice(token_transfer.from.as_bytes()),
        receiver: Address::from_slice(token_transfer.to.as_bytes()),
        token: Address::from_slice(token_transfer.token.as_bytes()),
        amount: U256::from_be_bytes(tmp),
        tx_id: hex_str_to_bytes(&tx_id).as_slice().try_into().unwrap(),
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
