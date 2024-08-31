# milano

Experimenting with client side offline zk proofs.


The goal is to create a QR code that contains a self-contained zk proof of some transfer transaction from era mainnet.




## Running

Generate the .json file with all the data using the python creator file:

```shell
python3 online_creator.py 0xbe8d5c1eba50aec04e07d627fb2bfcf71cafd242c9e231681ffc5aba12cc385c
```

This will result in the output.json file with necessary data.

Then you can verify it in sp1, by running (from the sp1/script directory):

```shell
cargo run --release -- --execute
```

This will check that the output.json file is correct.

Then you can generate the 'large' but fast proof (will take around 30 seconds):

```shell
cargo run --release -- --prove 
```

And then finally, the 'small' (KZG) proof (will take multiple minutes):

```shell
cargo run --bin prove --release -- --evm
```




## Stuff to do

* Verify that transaction has executed correctly (get the receipt too).
* Add code for simply checking that someone holds the NFT.
* hook up the QR code generator
* create the raspberry pi version of verifier.