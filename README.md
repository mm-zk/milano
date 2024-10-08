# milano

Experimenting with client side offline zk proofs.


The goal is to create a QR code that contains a self-contained zk proof of some transfer transaction from era mainnet.





## Running

Generate the .json file with all the data using the python creator file:

```shell
python3 online_creator.py transaction 0xbe8d5c1eba50aec04e07d627fb2bfcf71cafd242c9e231681ffc5aba12cc385c tmp/output_file.json
```

(or for NFT):
### Running (for NFT)

```shell
python3 online_creator.py nft 0x1f13941d0995e111675124af4b0f9bdcc70390c3 0xfac041bcf2c4b43319c2c0a39aba53f4cbe44fe5 tmp/output_file.json
```

### Proving

This will result in the `output_file.json` file with necessary data.

Then you can verify it in sp1, by running (from the `sp1` directory):

```shell
cargo run --release -- --input-file=../tmp/output_file.json --execute
```

This will check that the output_file.json file is correct.

Then you can generate the 'large' but fast proof (will take around 30 seconds):

```shell
cargo run --release -- --input-file=../tmp/output_file.json  --prove 
```

And then finally, the 'small' (KZG) proof (will take multiple minutes) - and this is what we need for the next step.

```shell
RUST_LOG=info cargo run --bin evm --release --  --input-file=../tmp/output_file.json --output-proof-file=../tmp/proof.json
```

### Generating QR code with proof

Now you can generate the QR code that will contain your proof:

```shell
cargo run -- --input-file=../examples/proof_nft.json --output-file=../examples/proof_nft_qr.jpg
```


### Verify (on raspberry pi)

Finally you can verify the proof from the QR code on your offline device:

```shell
python3 verifier.py qr ../examples/proof_nft_qr.jpg
```

In this case, you also have to 'hardcode' the verification key in the device code.

You can see the example in 'open_door.py' on how this can be used.

## Stuff to do

* Verify that transaction has executed correctly (get the receipt too).
* The QR codes should also be 'signed' by the holder/sender.
* And verifier should check that signature.