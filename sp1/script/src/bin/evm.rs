//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use fibonacci_lib::PublicValuesStruct;
use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use std::{
    fs::File,
    io::{BufReader, Read},
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct EVMArgs {
    #[clap(long)]
    input_file: String,

    #[clap(long)]
    output_proof_file: String,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1FibonacciProofFixture {
    struct_type: String,
    sender: String,
    receiver: String,
    token: String,
    amount: String,
    tx_id: String,
    nft: String,
    owner: String,
    batch_number: String,
    slot_position: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(FIBONACCI_ELF);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();

    let file = File::open(args.input_file).unwrap();
    let mut reader = BufReader::new(file);
    let mut data = String::new();
    reader.read_to_string(&mut data).unwrap();

    stdin.write(&data);

    // Generate the proof.
    let proof = client
        .prove(&pk, stdin)
        .plonk()
        .run()
        .expect("failed to generate proof");

    create_plonk_fixture(&proof, &vk, args.output_proof_file);
}

/// Create a fixture for the given proof.
fn create_plonk_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    output_file: String,
) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let PublicValuesStruct {
        struct_type,
        sender,
        receiver,
        token,
        amount,
        tx_id,
        nft,
        owner,
        batch_number,
        slot_position,
    } = PublicValuesStruct::abi_decode(bytes, false).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1FibonacciProofFixture {
        sender: sender.to_string(),
        receiver: receiver.to_string(),
        token: token.to_string(),
        amount: amount.to_string(),
        tx_id: tx_id.to_string(),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
        nft: nft.to_string(),
        owner: owner.to_string(),
        batch_number: batch_number.to_string(),
        slot_position: slot_position.to_string(),
        struct_type: struct_type.to_string(),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.

    std::fs::write(output_file, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("failed to write fixture");
}
