use std::{fs::File, io::BufReader};

use tx_verifier::{verify_nft_proof, verify_proof, NFTOwnership, NFTProof, TokenTransfer, TxProof};

fn main() -> Result<(), String> {
    {
        let file = File::open("../output_nft.json").unwrap();
        let reader = BufReader::new(file);

        // Parse the JSON into the Person struct.
        let nft_proof: NFTProof =
            serde_json::from_reader(reader).map_err(|e| format!("Json failed {}", e))?;

        // Print the parsed data.
        println!("{:?}", nft_proof);
        verify_nft_proof(&nft_proof)?;
        println!("Verification: SUCESS");

        let aa: NFTOwnership = NFTOwnership::try_from(nft_proof).unwrap();
        println!("NFT Ownership: {:?}", aa);
    }
    {
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

        let aa = TokenTransfer::try_from(tx_proof).unwrap();
        println!("Token transfer: {:?}", aa);
    }

    Ok(())
}
