from web3 import Web3
import hashlib
from eth_abi import decode


SYSTEM_CONTEXT_ADDRESS = "0x000000000000000000000000000000000000800B"


def get_key_for_recent_block(block_number):
    MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT = 11
    return format(block_number % 257 + MAPPING_RECENT_BLOCK_POSITION_IN_SYSTEM_CONTRACT, "064x")


def compute_transaction_rolling_hash(transaction_hashes):
    prev = "0x" + "00" * 32

    for transaction in transaction_hashes:
        prev = Web3.solidity_keccak(['bytes32', 'bytes32'], [prev, transaction])
    return prev


def calculate_block_hash(block_number, block_timestamp, prev_block_hash, transaction_rolling_hash):
    return Web3.solidity_keccak(['uint256', 'uint256', 'bytes32', 'bytes32'], [block_number, block_timestamp, prev_block_hash, transaction_rolling_hash])


def calculate_tx_hash(raw_tx_input):
    return Web3.keccak(raw_tx_input)

# Checks if given storage proof is valid (which means that it computes into the given roothash)
# Account, key, value, roothash - should be in hex format with 0x prefix.
# index should be an integer.
# proof should be a list of strings in hex format with 0x prefix.
 
def verify_storage_proof(account, key, proof, value, index, roothash, debug=False):
    if debug:
        print(f"Proof len: {len(proof)}")
    if len(bytes.fromhex(account[2:]) ) != 20:
        print(f"Wrong account length {bytes.fromhex(account[2:]) } expected 20")
        raise Exception
    
    tree_key = bytes(12) + bytes.fromhex(account[2:]) + bytes.fromhex(key[2:])

    if len(tree_key) != 64:
        print(f"Wrong length {len(tree_key)} expected 64")
        raise Exception
    
    # this is the location in the merkle tree.
    tree_key_hash = hashlib.blake2s(tree_key).digest()
    

    empty_hash = hashlib.blake2s(bytes(40)).digest()
    
    encoded_value = index.to_bytes(8, byteorder='big') + bytes.fromhex(value[2:])
    if len(encoded_value) != 40:
        print(f"Wrong encoded value length: {len(encoded_value)} - expected 40.")
    value_hash = hashlib.blake2s(encoded_value).digest()
    

    # Now we go from the leaves all the way up to the root.
    depth = 255
    current_hash = value_hash
    for u64pos in range(0, len(tree_key_hash), 8):
        u64byte = int.from_bytes(tree_key_hash[u64pos: u64pos+8], 'little')
        # Bits are determining whether we are the left or right sibling.
        for i in range(64):
            bit = (u64byte>>(i))&1
            if len(proof) > depth:
                
                if len(proof[depth][2:]) != 64:
                    print(f"Wrong proof length {len(proof[depth][2:])} at {depth}")
                    raise Exception
                if debug:
                    print(f"Reading from depth {depth} bit is {bit}")
                other_hash = bytes.fromhex(proof[depth][2:])
            else:
                other_hash = empty_hash
            empty_hash = hashlib.blake2s(empty_hash + empty_hash).digest()
            if bit:
                if debug:
                    print(f"{depth} --> {other_hash.hex()[:6]} + {current_hash.hex()[:6]}")
                current_hash = hashlib.blake2s(other_hash + current_hash).digest()
            else:
                if debug:
                    print(f"{depth} --> {current_hash.hex()[:6]} + {other_hash.hex()[:6]}")
                current_hash = hashlib.blake2s(current_hash + other_hash).digest()
            depth -= 1

    
    if current_hash.hex() != roothash[2:]:
        print(f"Root hash doesn't match - proof is wrong - comparing {current_hash.hex()} with {roothash}")
        raise Exception
    if debug:
        print(f"Root hash is: {current_hash.hex()} - matching.")    
    



COMMIT_BATCHES_SHARED_BRIDGE = "6edd4f12"

#   function commitBatchesSharedBridge(
#        uint256,(uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32),(uint64,uint64,uint64,bytes32,uint256,bytes32,bytes32,bytes32,bytes,bytes)[])


def parse_commitcall_calldata(calldata, batch_to_find):
    selector = calldata[0:4]

    if selector.hex() != COMMIT_BATCHES_SHARED_BRIDGE:
        print(f"\033[91m[FAIL] Invalid selector {selector.hex()} - expected {COMMIT_BATCHES_SHARED_BRIDGE}. \033[0m")
        raise Exception
    
    (chain_id, last_commited_batch_data_, new_batches_data) = decode(["uint256", "(uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32)", "(uint64,uint64,uint64,bytes32,uint256,bytes32,bytes32,bytes32,bytes,bytes)[]"], calldata[4:])

    # We might be commiting multiple batches in one call - find the one that we're looking for
    selected_batch = None
    for batch in new_batches_data:
        if batch[0] == batch_to_find:
            selected_batch = batch
    
    if not selected_batch:
        print(f"\033[91m[FAIL] Could not find batch {batch_to_find} in calldata.. \033[0m")
        raise Exception
    
    (batch_number_, timestamp_, index_repeated_storage_changes_, new_state_root, num_l1_tx_, priority_op_hash_, bootloader_initial_heap_, events_queue_state_, system_logs_, total_pubdata_) = selected_batch

    return {
        'batchStateRoot': new_state_root,
        'chainId': chain_id
        }