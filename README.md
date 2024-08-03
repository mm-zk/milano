# milano


## Stuff to do

* config to handle different networks + operators
* cleanup the code
* create the rust version of the online creator
* also pass the contents of the original transaction.

### for ZK
* design the public input
* figure out the snark vs start verifier (how big would be the 'stark')


## Public inputs
(for simple scenario of burning FT)
* FT address
* 'sender'
* transaction id (for uniqueness)
* (stuff like ERA BLOB OPERATOR and CHAIN could be part of verification key - embedded in device)

(in future - future, you might also need a way to update those verification keys via the QR codes..)


## What has to be passed in the QR code:
* proof that you 'own' that account (so something 'signed' with that key that is not public)
* public inputs.
