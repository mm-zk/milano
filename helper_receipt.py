from web3 import Web3


ZKSYNC_URL = 'https://mainnet.era.zksync.io'
ETH_URL = 'https://rpc.ankr.com/eth'

web3 = Web3(Web3.HTTPProvider(ZKSYNC_URL))
# Check if connected successfully
if not web3.is_connected():
    print("Failed to connect to zkSync node.")
    raise 

print(f"\033[92m[OK]\033[0m Connected to {ZKSYNC_URL}")

block = web3.eth.get_block(41243588, full_transactions=True)


print(block)




eth_web3 = Web3(Web3.HTTPProvider(ETH_URL))

eth_block = eth_web3.eth.get_block(20548040, full_transactions=True)


print(eth_block)
