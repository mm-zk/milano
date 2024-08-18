import rlp
from eth_utils import keccak, to_hex

def decode_raw_tx(b: bytes):
    print("====")

    tx_type = b[0]

    if tx_type == 2:

        parts = rlp.decode(b[1:])
        # info from: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md

        chain_id = int.from_bytes(parts[0], 'big')
        nonce = int.from_bytes(parts[1], 'big')
        max_prio = int.from_bytes(parts[2], 'big')
        max_fee_per_gas = int.from_bytes(parts[3], 'big')
        gas_limit = int.from_bytes(parts[4], 'big')
        destination = parts[5]
        amount = int.from_bytes(parts[6], 'big')
        data = parts[7]
        access_list = parts[8]
        sig_y = parts[9]
        sig_r = parts[10]
        sig_s = parts[11]



        print(f"chain id: {chain_id}")
        print(f"nonce = {nonce}")
        print(f"max priority = {max_prio}")
        print(f"max fee = {max_fee_per_gas}")
        print(f"gas limit = {gas_limit}")
        print(f"destination = {destination}")
        print(f"amount = {amount}")

              


        print(parts)

        tx_hash = to_hex(keccak(b))

        print(f"tx hash = {tx_hash}")




        return
    print("Unsupported type: {tx_type}")


# from L1
decode_raw_tx(bytes.fromhex('02f86a092f84b2d05e0084b2d05e028252089463087ad2a29acc6e9372163bc6fcc6c89bbdbefb7b80c080a04e5c573052a62922d30893a2a83772a827e7ad276f8a76b2a39b3b9cbb9fb44ca047cc8d28723e0bdca6b313e6446834cdb949f38024af20b5d9755fde6d3aa1db'))

# from L2
decode_raw_tx(bytes.fromhex('02f86d82010e0284b2d05e0084bebc2000830276e49463087ad2a29acc6e9372163bc6fcc6c89bbdbefb7b80c001a08a8e9e83e5bfc9b305671b77c8a30343125dc2a0a54baa596469d629bdb59bc5a0499d8173fe0fc98bc8f4ac26798c0dec9f8d649cfa310d7c29ccacf5da41888f'))


# from l1 ERC20 transfer
decode_raw_tx(bytes.fromhex('02f8af093084b2d05e0084b2d05e028254389463087ad2a29acc6e9372163bc6fcc6c89bbdbefb80b844a9059cbb0000000000000000000000006aacbf3e732c830f4e06aa3e13461e005cd9ebc4000000000000000000000000000000000000000000000000000000000000007dc080a0c1275bdbe4417ab4fcf6959d13c0b8784e53ff6d4006c51ca5708eeb41cbec42a02fd9e3b46af19f39864d96a8ad495f053b9ec0a609c23e3cf8feb1315e15622a'))


# from L2 - ERC20 transfer
decode_raw_tx(bytes.fromhex('02f8b282010e0384b2d05e0084bebc200083020b429463087ad2a29acc6e9372163bc6fcc6c89bbdbefb80b844a9059cbb0000000000000000000000006aacbf3e732c830f4e06aa3e13461e005cd9ebc4000000000000000000000000000000000000000000000000000000000000007dc001a0ce526c3cde2a570c98e6b5d268c4f5de367bb3f478fc60f29f35faba7e50646ea0660328a1020b687e6d5e6826de064d258062d7e7e48ee9201bef9f2f173140ba'))


# from mainnet
decode_raw_tx(bytes.fromhex('02f8b2820144438402b275d08402b275d083023971947e8da560eb172bb2c03895cfc747733225bed93580b844095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc001a00877c30a58f040fbd1115bd720b419bf230193b6e440afc6dd6c76369f8690eaa01f1735f06e3e10887b1280ced304f7445dc7dac5d0e8e57b5568441474f3b580'))