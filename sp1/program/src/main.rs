//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::U256;
use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, other_stuff, PublicValuesStruct};
use tx_verifier::{hex_str_to_bytes, verify_proof, TxProof};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    let json_data = sp1_zkvm::io::read::<String>();
    let tx_proof: TxProof = serde_json::from_str(&json_data).unwrap();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let (a, b) = fibonacci(n);
    let foo = other_stuff();

    verify_proof(&tx_proof).unwrap();

    let tx_id = U256::from_le_slice(&hex_str_to_bytes(&tx_proof.transaction_id));

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b, tx_id });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
