import json

from py_ecc import bn128

#from py_ecc.bn128 import FQ, FQ2
from py_ecc.bn128.bn128_curve import G1, G2, add, multiply
import hashlib

from eth_utils import to_bytes, keccak, to_hex



# Finite field prime (bn128)
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

VK_OMEGA =  19200870435978225707111062059747084165650991997241425080699860725083300967194
VK_QL_COM_X = 20791018202796501791851109643831626010857592750396866610160202525341548104975
VK_QL_COM_Y = 5226061715293647066826628267680220853478003875325565109026897987462899458934
VK_QR_COM_X = 17704828802915832559088923039609398221401810694301345977639386873055299309953
VK_QR_COM_Y = 11505746596354645523327106298502472694854757882353990600194589846954496245852
VK_QM_COM_X = 8632375487221918401254404349520984498817891912271126365916892067491373235811
VK_QM_COM_Y = 18415064246668245762581392760606059429812772223698459476573964344262178019204
VK_QO_COM_X = 8087969089479778581426802786766605298548725543517399982902049379760156324465
VK_QO_COM_Y = 4779090953040789618776097250791090447780600065080041765846917953077650190480
VK_QK_COM_X = 10309503866905785707178640727209791380348799027238603521718690548633411043468
VK_QK_COM_Y = 2592253320469291239204015457281188297098202731734862712210951168997817663533

VK_S1_COM_X = 1691236927603889293036991293307837152105169001969876410429311940723859549214
VK_S1_COM_Y = 14671292974808286966476340691395602210499383933767336479707207228316624796067

VK_S2_COM_X = 8488985819633767661392296162379719853061350968173906335566567292000856455547
VK_S2_COM_Y = 21135097961399174006459419593931869224566225356178559833797507995994008138431

VK_S3_COM_X = 6948983180741800379137546378229012057117410422170200269119279410455497222279
VK_S3_COM_Y = 2168023664758765470467815652478171461884955470414723045130810573559142201536

VK_COSET_SHIFT = 5

VK_QCP_0_X = 15094628898981014851230294832922767350330234022809606393203152940416977514848
VK_QCP_0_Y = 3056768420174140117719575194791127678251100292295026433168587815162498899224


# Setup
def setup():
    # Generator points G1 and G2 for bn128
    return G1, G2

def hash_to_field(data):
    return int(hashlib.sha256(data).hexdigest(), 16) % PRIME


def compute_gamma(proof, public_values):
    fields = [VK_S1_COM_X, VK_S1_COM_Y, VK_S2_COM_X, VK_S2_COM_Y, VK_S3_COM_X, VK_S3_COM_Y,
              VK_QL_COM_X, VK_QL_COM_Y, VK_QR_COM_X, VK_QR_COM_Y, VK_QM_COM_X, VK_QM_COM_Y,
              VK_QO_COM_X, VK_QO_COM_Y, VK_QK_COM_X, VK_QK_COM_Y, VK_QCP_0_X, VK_QCP_0_Y]
    
    
    hash_input = ("gamma".encode("utf-8") + b''.join(x.to_bytes(32, byteorder='big') for x in fields) 
                  + public_values[0] + public_values[1]
                  + proof[:0xc0])
    
    
    #gamma = keccak(hash_input)
    gamma = hashlib.sha256(hash_input).digest()
    print("gamma ", int.from_bytes(gamma, byteorder='big'))
    return gamma



# Now entering actual verify function.
def verify_plonk(proof, public_values):

    print(f"Public values len: {len(public_values)}")
    assert len(public_values) == 2

    
    # check_input_size -- ignored for now 
    # Also not checking proof values (that they are smaller than PRIME -1)

    gamma = compute_gamma(proof, public_values)



    # Then derive the beta, gamma etc - a.k.a sha256 hashes 




    


def verify(data):
    proof_bytes = bytes.fromhex(data['proof'][2:])
    if proof_bytes[:4].hex() != "c430ff7f":
        raise "Wrong selector"
    
    proof_bytes = proof_bytes[4:]
    inputs = bytes.fromhex(data['vkey'][2:])

    
    public_values = bytes.fromhex(data['publicValues'][2:])


    public_values_hash = (int.from_bytes(hashlib.sha256(public_values).digest(), 'big') &( (1<<253) - 1)).to_bytes(32, 'big')
    
    verify_plonk(proof_bytes, [inputs, public_values_hash])

    pass


def main():
    with open("fixture.json", 'r') as file:
        data = json.load(file)
        verify(data)



if __name__ == "__main__":
    main()
