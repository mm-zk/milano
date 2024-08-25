use std::{fs::File, io::BufReader};

use tx_verifier::{verify_proof, TxProof};

fn main() -> Result<(), String> {
    // Open the file in read-only mode.
    let file = File::open("../output.json").unwrap();
    let reader = BufReader::new(file);

    // Parse the JSON into the Person struct.
    let tx_proof: TxProof =
        serde_json::from_reader(reader).map_err(|e| format!("Json failed {}", e))?;

    // Print the parsed data.
    println!("{:?}", tx_proof);
    verify_proof(&tx_proof)?;
    println!("Verification: SUCESS");

    Ok(())
}
