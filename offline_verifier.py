import sys
import json
import utils

import rlp
from eth_utils import decode_hex, keccak, to_checksum_address, to_bytes
from eth_keys import keys
from eth_keys.exceptions import BadSignature


# Account on ERA that sends 'commits' with blobs.
ERA_BLOB_OPERATOR = "0x0D3250c3D5FAcb74Ac15834096397a3Ef790ec99"
# and we expect proofs from ERA.
EXPECTED_CHAIN_ID = 324




def verify(data):
    tx_id = data["transaction_id"]

    # TODO: also check that the transaction is actually doing what it was supposed to do (for example transfer).
    

    if tx_id not in data['transactionsInBlock']:
        raise "Tx not presetn in transactions in blocks"

    # compute block that this tx belongs to.
    tx_rolling_hash = utils.compute_transaction_rolling_hash(data['transactionsInBlock'])
    calculated_block_hash  = utils.calculate_block_hash(data['blockNumber'], data['blockTimestamp'], data['parentHash'], tx_rolling_hash)

    print(calculated_block_hash.hex())

    # So now we know that this TX belongs to this block.
    # Now we have to check that this block belongs to a batch.


    utils.verify_storage_proof(utils.SYSTEM_CONTEXT_ADDRESS, "0x" + utils.get_key_for_recent_block(data['blockNumber']), data['storageProof']['proof'], calculated_block_hash.hex(), data['storageProof']['index'],
                         data['batchRoothash'])
    

    # Now we know that this block belongs to the batch with 'batchRootHash'.
    # Now we have to prove that this batch was actually submitted to L1.

    batch_commit_tx = data['batchCommitTx']
    raw_tx_bytes = decode_hex(batch_commit_tx[2:])

    batch_commit_hash = utils.calculate_tx_hash(raw_tx_bytes)


    print(f"Batch commit tx hash: {batch_commit_hash.hex()}")

    # For now, we'll only verify the signature of the transaction - in the future, we should check on L1 instead.

    

    decoded_tx = rlp.decode(raw_tx_bytes[1:])

    # Extract transaction fields
    chain_id = decoded_tx[0]
    nonce = decoded_tx[1]
    max_priority_fee_per_gas = decoded_tx[2]
    max_fee_per_gas = decoded_tx[3]

    gas_limit = decoded_tx[4]
    to_address = decoded_tx[5]
    value = decoded_tx[6]
    calldata = decoded_tx[7]
    access_list = decoded_tx[8]
    max_fee_per_blob_gas = decoded_tx[9]
    blob_versioned_hashes = decoded_tx[10]

    v = int(decoded_tx[11].hex(),16)
    r = int(decoded_tx[12].hex(), 16)
    s = int(decoded_tx[13].hex(), 16)

    # Reconstruct the transaction hash
    tx_parts = [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to_address, value, calldata, access_list, max_fee_per_blob_gas, blob_versioned_hashes]
    tx_hash = keccak(b'\x03' + rlp.encode(tx_parts))

    # Recover the public key from the signature
    signature = keys.Signature(vrs=(v, r, s))
    try:
        public_key = signature.recover_public_key_from_msg_hash(tx_hash)
        sender_address = public_key.to_checksum_address()
        print(f"Sender's Address: {sender_address}")
        if sender_address != ERA_BLOB_OPERATOR:
            raise "Invalid sender - doesn't match the blob operator"
    except BadSignature:
        print("Invalid Signature")


    commit_calldata = utils.parse_commitcall_calldata(calldata, data['batchNumber'])

    if commit_calldata['batchStateRoot'] != bytes.fromhex(data['batchRoothash'][2:]):
        print(f"Batch state root doesnt match {commit_calldata['batchStateRoot'].hex()} vs {data['batchRoothash']}")
        raise "Batch state root doesnt match"
    
    if commit_calldata['chainId'] != EXPECTED_CHAIN_ID:
        print(f"Chain ids: {commit_calldata['chainId']} vs  {EXPECTED_CHAIN_ID}")
        raise "Chain id doesn't match"


    # At this moment, we know that the 'trusted' operator, has sent the commitBatches request with
    # a batch, that contains a block that contains our transaction.


    # In the future, instead of checking the commitBatch signature, we should check that this transaction was executed succesfully on
    # ethereum.


    print("VERIFICATION SUCCESSFUL")
    

def main():
    # Check if at least one argument is provided
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        with open(file_path, 'r') as file:
            data = json.load(file)
            verify(data)
    else:
        print("Please pass file path")

if __name__ == "__main__":
    main()