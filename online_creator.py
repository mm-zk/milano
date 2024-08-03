import sys
import json
from web3 import Web3
import utils
import requests
from eth_abi import decode
import rlp

ZKSYNC_URL = 'https://mainnet.era.zksync.io'
ETH_URL = 'https://rpc.ankr.com/eth'



# Fetches the storage proof for a given account, key, batch.
# In the response, you get the value + index (which is used for repeated writes), and proof (a list of siblings on merkle path).
def get_storage_proof(account, key, batch):
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "id": 1, "method": "zks_getProof", "params": [account, [key], batch]}
    response = requests.post(ZKSYNC_URL, headers=headers, data=json.dumps(data))
    storage_proof = response.json()["result"]["storageProof"][0]
    return {'proof': storage_proof["proof"], 'value': storage_proof['value'], "index": storage_proof["index"]}


# Checks that tx belongs to a block.
# Retuns the block number and block hash and (unverified batch number).
# After calling this - you should verify that this block and 
# hash was correctly included in the chain.
def verify_tx_inclusion_in_block(txn):    
    web3 = Web3(Web3.HTTPProvider(ZKSYNC_URL))
    # Check if connected successfully
    if not web3.is_connected():
        print("Failed to connect to zkSync node.")
        raise 
    
    print(f"\033[92m[OK]\033[0m Connected to {ZKSYNC_URL}")

    # Fetch the transaction
    try:
        tx = web3.eth.get_transaction(txn)
    except Exception as e:
        print(f"An error occurred: {e}")
        raise 
    
    print(f"\033[92m[OK]\033[0m Transaction {txn} found. Checking block {tx['blockNumber']}")
    

    # now fetch the blockinfo
    try:
        block = web3.eth.get_block(tx['blockNumber'])
    except Exception as e:
        print(f"An error occurred: {e}")
        raise
    
    print(f"\033[92m[OK]\033[0m Block found with hash {block['hash'].hex()}.")
    
    transactions_in_block = block['transactions']
    
    found = False
    for transaction in transactions_in_block:
        if transaction.hex() == txn:
            found = True

    if not found:
        print(f"\033[91m[FAIL] Could not find transaction {txn} in a block {block['number']} \033[0m")
        raise Exception
    
    print(f"\033[92m[OK]\033[0m Transation found in a block.")
    

    # Now check that block hash is correctly computed and that it contains all the transactions.
    # block hash is computed as a hash of block number, timestamp, previous block and rolling hash of all the included transactions.
    tx_rolling_hash = utils.compute_transaction_rolling_hash(transactions_in_block)
    calculated_block_hash  = utils.calculate_block_hash(tx['blockNumber'], block['timestamp'], block['parentHash'], tx_rolling_hash)
    if calculated_block_hash.hex() != block['hash'].hex():
        print(f"\033[91m[FAIL] Block hash doesn't match for {block['number']} \033[0m")
        raise 
    
    print(f"\033[92m[OK]\033[0m Block hash is valid {calculated_block_hash.hex()}")
    
    return {
        'blockNumber': tx['blockNumber'], 
        'blockHash': block['hash'].hex(),
        'batchNumber': int(block['l1BatchNumber'], 16),
        'transactionsInBlock': transactions_in_block,
        'blockTimestamp': block['timestamp'],
        'parentHash': block['parentHash'],
    }




WHITELISTED_ADDRESSES = set(
    [
        "0x32400084c286cf3e17e7b677ea9583e60a000324", # zksync era mainnet diamond proxy
        "0xa0425d71cB1D6fb80E65a5361a04096E0672De03", # zksync era timelock
    ]
)

def get_l1_address():
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "id": 1, "method": "zks_getMainContract", "params": []}
    response = requests.post(ZKSYNC_URL, headers=headers, data=json.dumps(data))
    return response.json()["result"]

def get_commit_and_prove_and_verify(l1_batch):
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "id": 1, "method": "zks_getL1BatchDetails", "params": [l1_batch]}
    response = requests.post(ZKSYNC_URL, headers=headers, data=json.dumps(data))
    response_json = response.json()["result"]
    return response_json["commitTxHash"], response_json["proveTxHash"], response_json["executeTxHash"]


PROVE_BATCHES_SHARED_BRIDGE_SELECTOR = "0xc37533bb"

def parse_provecall_calldata(calldata, batch_to_find):
    selector = calldata[0:4]

    if selector.hex() != PROVE_BATCHES_SHARED_BRIDGE_SELECTOR:
        print(f"\033[91m[FAIL] Invalid selector {selector.hex()} - expected {PROVE_BATCHES_SHARED_BRIDGE_SELECTOR}. \033[0m")
        raise Exception
    
    (chain_id, prev_batch, commited_batches, proofs) = decode(["uint256", "(uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32)", "(uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32)[]", "(uint256[],uint256[])"], calldata[4:])

    # We might be commiting multiple batches in one call - find the one that we're looking for
    selected_batch = None
    for batch in commited_batches:
        if batch[0] == batch_to_find:
            selected_batch = batch
    
    if not selected_batch:
        print(f"\033[91m[FAIL] Could not find batch {batch_to_find} in calldata.. \033[0m")
        raise Exception
    
    (batch_number_, batch_hash_, index_repeated_storage_changes_,  num_l1_tx_, priority_op_hash_, logs2_tree_root, timestamp_, commitment) = selected_batch

    return batch_hash_





def get_batch_root_hash(l1_batch):
    web3 = Web3(Web3.HTTPProvider(ZKSYNC_URL))
    # Check if connected successfully
    if not web3.is_connected():
        print("Failed to connect to zkSync node.")
        raise
    
    ethweb3 = Web3(Web3.HTTPProvider(ETH_URL))
    # Check if connected successfully
    if not ethweb3.is_connected():
        print("Failed to connect to zkSync node.")
        raise
    
    print(f"\033[92m[OK]\033[0m Connected to {ZKSYNC_URL} and {ETH_URL}")
    
    l1_address = get_l1_address()
    if l1_address not in WHITELISTED_ADDRESSES:
        print(f"\033[93m[WARNING] - Assuming L1 address of the contract is {l1_address} - please verify manually - https://etherscan.io/address/{l1_address} \033[0m")


    commitTx, proveTx, executeTx = get_commit_and_prove_and_verify(l1_batch)
    if commitTx is None:
        print(f"\033[91m[FAIL] Batch {l1_batch} is not commited yet - please try later. \033[0m")
        raise 
    
    # check that commitTx is of the right type.
        # Fetch the transaction
    try:
        tx = ethweb3.eth.get_transaction(commitTx)
        raw_tx = ethweb3.eth.get_raw_transaction(commitTx)
    except Exception as e:
        print(f"An error occurred: {e}")
        raise

    
    
    try:
        receipt = ethweb3.eth.get_transaction_receipt(commitTx)
    except Exception as e:
        print(f"An error occurred: {e}")
        raise
    
    if receipt.status != 1:
        print(f"\033[91m[FAIL] L1 commit tx {commitTx} is not successful. \033[0m")
        raise Exception
    
    if receipt.to != l1_address:
        # It should be a 'fail' - but currently we are sending the transactions to validator lock and NOT to the proxy.
        if receipt.to not in WHITELISTED_ADDRESSES:
            print(f"\033[93m[WARNING] - L1 commit tx {commitTx} is being sent to a different address: - please verify manually - https://etherscan.io/address/{receipt.to} \033[0m")

    commit_call_calldata = utils.parse_commitcall_calldata(bytes(tx['input']), l1_batch)
    new_state_root = commit_call_calldata['batchStateRoot']

    if proveTx is None:
        print(f"\033[95m[WARN] Batch {l1_batch} is not proven yet. Make sure to re-run the tool later. \033[0m")
        is_proven = False
    else:

        try:
            prove_tx = ethweb3.eth.get_transaction(proveTx)
        except Exception as e:
            print(f"An error occurred: {e}")
            raise
    
        try:
            prove_receipt = ethweb3.eth.get_transaction_receipt(proveTx)
        except Exception as e:
            print(f"An error occurred: {e}")
            raise
        
        if prove_receipt.to != receipt.to:
            print(f"\033[91m[FAIL] L1 commit tx was sent to different address than prove ts {receipt.to} vs {prove_receipt.to}. \033[0m")
            raise Exception    
        
        if prove_receipt.status != 1:
            print(f"\033[91m[FAIL] L1 prove tx {proveTx} is not successful. \033[0m")
            raise Exception
        
        
    
    
        batch_hash = parse_provecall_calldata(prove_tx['input'], l1_batch)
        if batch_hash != new_state_root:
            print(f"\033[91m[FAIL] Prove hash {batch_hash} doesn't match commit hash {new_state_root}. \033[0m")
            raise Exception
        
        is_proven = True


    
    return {
        "isProven" : is_proven,
        "newStateRoot":  new_state_root,
        "commitTxHash": commitTx,
        "commitTx": tx,
        "commitRawTx": raw_tx,
    }




def prove_tx_inclusion_in_chain(tx):
    result = {"transaction_id": tx, "debug": {}}

    block_info = verify_tx_inclusion_in_block(tx)

    block_number = block_info['blockNumber']
    block_hash = block_info['blockHash']
    batch = block_info['batchNumber']


    result['transactionsInBlock'] = [x.hex() for x in block_info['transactionsInBlock']]
    result['blockNumber'] = block_info['blockNumber']
    result['parentHash'] = block_info['parentHash'].hex()
    result['blockTimestamp'] = block_info['blockTimestamp']
    result['batchNumber'] = block_info['batchNumber']

    



    storage_proof = get_storage_proof(utils.SYSTEM_CONTEXT_ADDRESS, utils.get_key_for_recent_block(block_number), batch)

    result['storageProof'] = storage_proof

    # check that the values match.
    if storage_proof['value'] != block_hash:
        # this might happen if the batch has more than 256 blocks. (then we'll need to add more code)
        print(f"\033[91m[FAIL] Block hash doesn't match entry in storage (block hash: {block_hash}) storage {storage_proof['value']}  \033[0m")
        raise Exception
    
    batch_root_data  = get_batch_root_hash(batch)
    is_proven = batch_root_data['isProven']
    roothash = batch_root_data['newStateRoot']
    print(f"Commit tx hash is {batch_root_data['commitTxHash']}")

    result['batchCommitTx'] = batch_root_data['commitRawTx'].hex()

    roothashHex = "0x" + roothash.hex()

    result['batchRoothash'] = roothashHex
    
    print(f"\033[92m[OK]\033[0m Roothash is {roothash.hex()}. Is proven: {is_proven}")

    utils.verify_storage_proof(utils.SYSTEM_CONTEXT_ADDRESS, "0x" + utils.get_key_for_recent_block(block_number), storage_proof['proof'], storage_proof['value'], storage_proof['index'],
                         roothashHex)
    
    if is_proven:
        print(f"\033[92m[OK]\033[0m Roothash is VALID and verified & proven on on L1.")
    else:
        print(f"\033[92m[OK]\033[0m Roothash is VALID and verified on L1. (but please wait for proof)")

    return result


def main():
    # Check if at least one argument is provided
    if len(sys.argv) > 1:
        transaction_id = sys.argv[1]

        file_path = "output.json"
        if len(transaction_id) != 66 or transaction_id[:2] != "0x":
            print("Please pass correct transaction id. For example 0xb07cf51bb1fb788e9ab4961af203ce1057cf40f2781007ff06e7c66b6fc814be")    
            return
        data = prove_tx_inclusion_in_chain(transaction_id)

        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)

        
    else:
        print("Please pass transaction id. For example 0xb07cf51bb1fb788e9ab4961af203ce1057cf40f2781007ff06e7c66b6fc814be")

if __name__ == "__main__":
    main()