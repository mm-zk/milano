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
cargo run --release -- --prove 
```

And then finally, the 'small' (KZG) proof (will take multiple minutes) - and this is what we need for the next step.

```shell
cargo run --bin prove --release -- --evm
```

### Verify (on raspberry pi)

```shell
python3 verifier.py
```

## Stuff to do

* Verify that transaction has executed correctly (get the receipt too).
* hook up the QR code generator
* start passing the file names directly.