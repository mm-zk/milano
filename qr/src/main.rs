use std::fs::File;
use std::io::BufReader;

use clap::Parser;
use hex::FromHex;
use image::Luma;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    input_file: String,
    #[clap(long)]
    output_file: String,
}

#[derive(Deserialize, Debug)]
pub struct ProofFixture {
    proof: String,
    #[serde(rename = "publicValues")]
    public_values: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file = File::open(args.input_file).unwrap();
    let reader = BufReader::new(file);

    let proof_fixture: ProofFixture = serde_json::from_reader(reader).unwrap();

    let proof = Vec::from_hex(
        proof_fixture
            .proof
            .strip_prefix("0x")
            .unwrap_or(&proof_fixture.proof),
    )
    .unwrap();

    let public_values = Vec::from_hex(
        proof_fixture
            .public_values
            .strip_prefix("0x")
            .unwrap_or(&proof_fixture.public_values),
    )
    .unwrap();

    let public_values_size = public_values.len() as u32;

    let public_vals = public_values_size.to_be_bytes();

    let data = [&public_vals[..], &public_values, &proof].concat();

    let data_64 = base64::encode(&data);
    println!("Encoding {} bytes as QR", data_64.len());
    let code = qrcode::QrCode::new(data_64).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image.save(&args.output_file).unwrap();
    println!("QR code saved as {}", args.output_file);
    Ok(())
}
