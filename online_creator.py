import argparse
import sys
import json
from web3 import Web3
import utils
import requests
from eth_abi import decode
import rlp
from eth_utils import to_bytes, keccak, to_hex

ZKSYNC_URL = 'https://mainnet.era.zksync.io'
ETH_URL = 'https://rpc.ankr.com/eth'



def get_latest_batch_number():
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "id": 1, "method": "zks_L1BatchNumber", "params": []}
    response = requests.post(ZKSYNC_URL, headers=headers, data=json.dumps(data))
    return int(response.json()["result"], 16)


def get_last_block_for_batch(batch):
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "id": 1, "method": "zks_getL1BatchBlockRange", "params": [batch]}
    response = requests.post(ZKSYNC_URL, headers=headers, data=json.dumps(data))
    return int(response.json()["result"][1], 16)


# Fetches the storage proof for a given account, key, batch.
# In the response, you get the value + index (which is used for repeated writes), and proof (a list of siblings on merkle path).
def get_storage_proof(account:str, key:str, batch:int):
    print(f"Key is {key} batch {batch}")
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


def compute_eth_tx_hash(nonce, gas_price, gas_limit, to, value, data, v, r, s):
    # Encode the transaction
    tx = [
        nonce,
        gas_price,
        gas_limit,
        to_bytes(hexstr=to) if to else b'',
        value,
        to_bytes(hexstr=data) if data else b'',
        to_bytes(v),
        to_bytes(r),
        to_bytes(s)
    ]

    # Serialize the transaction using RLP
    serialized_tx = rlp.encode(tx)

    # Compute the transaction hash using Keccak-256
    tx_hash = keccak(serialized_tx)
    
    # Return the transaction hash in hexadecimal format
    return to_hex(tx_hash)

def compute_eth_tx_hash_wihtout_sign(nonce, gas_price, gas_limit, to, value, data):
    # Encode the transaction
    tx = [
        nonce,
        gas_price,
        gas_limit,
        to_bytes(hexstr=to) if to else b'',
        value,
        to_bytes(hexstr=data) if data else b'',
        
    ]

    # Serialize the transaction using RLP
    serialized_tx = rlp.encode(tx)

    # Compute the transaction hash using Keccak-256
    tx_hash = keccak(serialized_tx)
    
    # Return the transaction hash in hexadecimal format
    return to_hex(tx_hash)

def compute_eip1559_tx_hash_without_sign(chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list):
    # Encode the transaction
    tx = [
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to_bytes(hexstr=to) if to else b'',
        value,
        to_bytes(hexstr=data) if data else b'',
        access_list,
        
    ]

    print(tx)

    # Prepend the transaction type (0x02 for EIP-1559)
    tx_type = b'\x02'
    
    # Serialize the transaction using RLP
    serialized_tx = tx_type + rlp.encode(tx)

    # Compute the transaction hash using Keccak-256
    tx_hash = keccak(serialized_tx)
    
    # Return the transaction hash in hexadecimal format
    return to_hex(tx_hash)

def compute_eip1559_tx_hash(chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, v, r, s):
    # Encode the transaction
    tx = [
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to_bytes(hexstr=to) if to else b'',
        value,
        to_bytes(hexstr=data) if data else b'',
        access_list,
        to_bytes(b'') if v == 0 else to_bytes(v),
        to_bytes(r),
        to_bytes(s)
    ]


    # Prepend the transaction type (0x02 for EIP-1559)
    tx_type = b'\x02'
    
    # Serialize the transaction using RLP
    serialized_tx = tx_type + rlp.encode(tx)

    # Compute the transaction hash using Keccak-256
    tx_hash = keccak(serialized_tx)
    
    # Return the transaction hash in hexadecimal format
    return to_hex(tx_hash), serialized_tx
    

def get_tx_body_and_from(tx_hash):
    web3 = Web3(Web3.HTTPProvider(ZKSYNC_URL))    
    # Check if connected successfully
    if not web3.is_connected():
        print("Failed to connect to zkSync node.")
        raise
    tx = web3.eth.get_transaction(tx_hash)

    if tx.type != 2:
        raise "Only type 2 transactions are supported"


    computed_tx_hash, serialized_tx = compute_eip1559_tx_hash(tx.chainId, tx.nonce, tx.maxPriorityFeePerGas, tx.maxFeePerGas, tx.gas, tx.to, tx.value, tx.input.hex(), [],
                                 tx.v, tx.r, tx.s)
    
    if computed_tx_hash != tx_hash:
        raise "TX computation failed"


    return (serialized_tx.hex(), tx.get('from'), tx.get('to'), tx.input.hex())



def get_raw_tx_by_hash(tx_hash):
    #web3 = Web3(Web3.HTTPProvider("http://localhost:3050"))    
    web3 = Web3(Web3.HTTPProvider(ZKSYNC_URL))    
    #web3 = Web3(Web3.HTTPProvider(ETH_URL))    


    # Check if connected successfully
    if not web3.is_connected():
        print("Failed to connect to zkSync node.")
        raise
    raw_tx = web3.eth.get_transaction(tx_hash)

    print(raw_tx)

    #really_raw_tx = web3.eth.get_raw_transaction(tx_hash)


    chain_id = raw_tx.chainId
    nonce = raw_tx.nonce
    gas = raw_tx.gas


    
    #h = compute_eth_tx_hash(raw_tx.nonce, raw_tx.gasPrice, raw_tx.gas, raw_tx.to, raw_tx.value, raw_tx.input.hex(), raw_tx.v, raw_tx.r, raw_tx.s)
    #print("First hash " + h)
    #h = compute_eth_tx_hash_wihtout_sign(raw_tx.nonce, raw_tx.gasPrice, raw_tx.gas, raw_tx.to, raw_tx.value, raw_tx.input.hex())
    #print("First hash (no sign) " + h)


    h2 = compute_eip1559_tx_hash(raw_tx.chainId, raw_tx.nonce, raw_tx.maxPriorityFeePerGas, raw_tx.maxFeePerGas, raw_tx.gas, raw_tx.to, raw_tx.value, raw_tx.input.hex(), [],
                                 raw_tx.v, raw_tx.r, raw_tx.s)
    print("Second hash " + h2)

    #h2 = compute_eip1559_tx_hash_without_sign(raw_tx.chainId, raw_tx.nonce, raw_tx.maxPriorityFeePerGas, raw_tx.maxFeePerGas, raw_tx.gas, raw_tx.to, raw_tx.value, raw_tx.input.hex(), []
    #                             )
    #print("Second hash (no sigh)" + h2)



    #print(" -- RAW -- ")
    #print(really_raw_tx)


    return raw_tx



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

# Assume that 'owner' table is at position 3 - common place for openzeppelin template.
NFT_USERMAP_POSITION = 3

def prove_nft_ownership(nft_contract: bytes, user: bytes):
    result = {"type": "nft", "nftContract": nft_contract.hex(), "nftOwner": user.hex(), "debug": {}}
    batch = get_latest_batch_number() - 1
    print(f"Latest batch is {batch}")
    result["batchNumber"] = batch
    last_block = get_last_block_for_batch(batch)
    print(f"latest block: {last_block}")
    storage_proof = get_storage_proof(nft_contract.hex(), utils.get_key_for_mapping_slot(NFT_USERMAP_POSITION, user), batch)

    result["nftUsermapPosition"] =  NFT_USERMAP_POSITION
    result["readSlot"] = utils.get_key_for_mapping_slot(NFT_USERMAP_POSITION, user)


    if int(storage_proof["value"].strip("0x"),16) != 1:
        raise Exception("NFT value is 0 - does this account really own this NFT?")
    
    result['storageProof'] = storage_proof


    batch_root_data  = get_batch_root_hash(batch)
    is_proven = batch_root_data['isProven']
    roothash = batch_root_data['newStateRoot']
    print(f"Commit tx hash is {batch_root_data['commitTxHash']}")

    result['batchCommitTx'] = batch_root_data['commitRawTx'].hex()

    roothashHex = "0x" + roothash.hex()

    result['batchRoothash'] = roothashHex
    
    print(f"\033[92m[OK]\033[0m Roothash is {roothash.hex()}. Is proven: {is_proven}")

    utils.verify_storage_proof("0x" + nft_contract.hex(), "0x" + utils.get_key_for_mapping_slot(NFT_USERMAP_POSITION, user), storage_proof['proof'], storage_proof['value'], storage_proof['index'],
                         roothashHex)
    
    if is_proven:
        print(f"\033[92m[OK]\033[0m Roothash is VALID and verified & proven on on L1.")
    else:
        print(f"\033[92m[OK]\033[0m Roothash is VALID and verified on L1. (but please wait for proof)")

    return result


# Generates the JSON file with all the witness data needed to prove that
# a given TX was included in the chain.
def prove_tx_inclusion_in_chain(tx):
    result = {"type": "tx", "transaction_id": tx, "debug": {}}

    (tx_body, tx_from, tx_to, tx_calldata) = get_tx_body_and_from(tx)

    result["txBody"] =  tx_body
    result["txFrom"] = tx_from
    result["txTo"] = tx_to
    result["txCalldata"] = tx_calldata

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




def help():
    print("Please pass commands")
    print(" To generate the proof of ERC20 transfer: ./online_creator.py tx $TRANSACTION_ID")
    print(" To generate the proof of NFT posession:  ./online_creator.py nft $NFT_CONTRACT $NFT_OWNER")



def parse_address_from_hex_to_bytes(addr_hex: str):
    if len(addr_hex.strip("0x")) != 40:
        raise Exception("Invalid address length: ", addr_hex)
    
    return int(addr_hex.strip("0x"),16).to_bytes(20, 'big')

    


def main():

    parser = argparse.ArgumentParser(description='Milano - Proof witness creator')
    
    # Command subparsers
    subparsers = parser.add_subparsers(dest='command', required=True, help='Type of command')
    
    # Subparser for the "transaction" command
    parser_transaction = subparsers.add_parser('transaction', help='Prove a transaction')
    parser_transaction.add_argument('transaction_id', type=str, help='Transaction ID')
    
    # Subparser for the "NFT" command
    parser_nft = subparsers.add_parser('nft', help='Prove an NFT ownership ')
    parser_nft.add_argument('nft_address', type=str, help='NFT Address')
    parser_nft.add_argument('owner', type=str, help='Owner of the NFT')
    
    # Common argument for both commands
    parser.add_argument('output_file', type=str, help='JSON file name to write the output to')
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Handle arguments based on the command
    if args.command == 'transaction':
        print(f"Handling transaction ID: {args.transaction_id}")
        print(f"Output will be written to: {args.output_file}")
        if len(args.transaction_id) != 66 or args.transaction_id[:2] != "0x":
            print("Please pass correct transaction id. For example 0xb07cf51bb1fb788e9ab4961af203ce1057cf40f2781007ff06e7c66b6fc814be")    
            return
        data = prove_tx_inclusion_in_chain(args.transaction_id)

        with open(args.output_file, 'w') as file:
            json.dump(data, file, indent=4)
        
    elif args.command == 'nft':
        print(f"Handling NFT at address: {args.nft_address} with owner: {args.owner}")
        print(f"Output will be written to: {args.output_file}")
        nft_id = parse_address_from_hex_to_bytes(args.nft_address)
        nft_owner = parse_address_from_hex_to_bytes(args.owner)


        data = prove_nft_ownership(nft_id, nft_owner)
        with open(args.output_file, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        print(f"INVALID COMMAND - {args.command}")
        

if __name__ == "__main__":
    main()
