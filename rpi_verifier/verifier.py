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

VK_DOMAIN_SIZE = 33554432
VK_INV_DOMAIN_SIZE = 21888242219518804655518433051623070663413851959604507555939307129453691614729;

VK_INDEX_COMMIT_API_0 = 20988588


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


def compute_beta(gamma):
    beta = hashlib.sha256("beta".encode("utf-8") + gamma).digest()
    print("beta ", int.from_bytes(beta, byteorder='big'))
    return beta


def compute_alfa(proof, beta):
    PROOF_BSB_COMMITMENTS = 0x320
    CUSTOM_GATES = 1

    PROOF_GRAND_PRODUCT_COMMITMENT_X = 0x220
    # Bsb22Commitments
    alfa = hashlib.sha256("alpha".encode("utf-8") + beta 
                          + proof[PROOF_BSB_COMMITMENTS: PROOF_BSB_COMMITMENTS+64*CUSTOM_GATES]
                          + proof[PROOF_GRAND_PRODUCT_COMMITMENT_X: PROOF_GRAND_PRODUCT_COMMITMENT_X + 64]).digest()

    print("alfa ", int.from_bytes(alfa, byteorder='big'))
    return alfa


def compute_zeta(proof, alfa):
    PROOF_H_0_X = 0xc0
    zeta = hashlib.sha256("zeta".encode("utf-8") + alfa + proof[PROOF_H_0_X : PROOF_H_0_X  + 0xc0]).digest()
    print("zeta ", int.from_bytes(zeta, byteorder='big'))
    return zeta



def reduce_bytes(input):
    return (int.from_bytes(input, byteorder='big') % PRIME).to_bytes(32, 'big')




def expmod(x, y, z):
    result = 1
    x = x % z  # Update x if it is more than or equal to z

    if x == 0:
        return 0  # In case x is divisible by z

    while y > 0:
        # If y is odd, multiply x with the result
        if y % 2 == 1:
            result = (result * x) % z

        # y must be even now
        y = y // 2
        x = (x * x) % z  # Change x to x^2
    return result

def mod_inverse(a, z):
    # Helper function using the Extended Euclidean Algorithm
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, y = extended_gcd(a, z)

    if gcd != 1:
        raise ValueError("Modular inverse does not exist because gcd(a, z) != 1")
    else:
        # x might be negative, so we take it modulo z to make it positive
        return x % z


# Now entering actual verify function.
def verify_plonk(proof, public_values):

    print(f"Public values len: {len(public_values)}")
    assert len(public_values) == 2

    
    # check_input_size -- ignored for now 
    # Also not checking proof values (that they are smaller than PRIME -1)

    gamma_not_reduced = compute_gamma(proof, public_values)
    beta_not_reduced = compute_beta(gamma_not_reduced)
    alfa_not_reduced = compute_alfa(proof, beta_not_reduced)
    alfa_int = int.from_bytes(reduce_bytes(alfa_not_reduced), 'big')
    zeta_not_reduced = compute_zeta(proof, alfa_not_reduced)

    zeta = reduce_bytes(zeta_not_reduced)
    zeta_int = int.from_bytes(zeta, byteorder='big')
    print("zeta reduced", zeta_int)



    zeta_power_n_minus_one = (expmod(zeta_int, VK_DOMAIN_SIZE, PRIME) + (PRIME - 1)) % PRIME

    print("zeta power ", zeta_power_n_minus_one)

    # l_pi - public inputs + size
    # now compute 2 lagranges at 'zeta'

    zn = zeta_power_n_minus_one * VK_INV_DOMAIN_SIZE

    w_ = 1
    lagranges = [0]*len(public_values)

    for i in range(len(public_values)):
        lagranges[i]  = (zeta_int + PRIME - w_) % PRIME
        w_ = (w_ * VK_OMEGA) % PRIME

    for i in range(len(public_values)):
        lagranges[i] = mod_inverse(lagranges[i], PRIME)

    w_ = 1
    for i in range(len(public_values)):
        lagranges[i] = (((lagranges[i] * zn) % PRIME) * w_) % PRIME
        w_ = (w_ * VK_OMEGA) % PRIME


    # now compute the commitment. lagrange * values.
    l_pi = 0
    for i in range(len(public_values)):
        l_pi += (lagranges[i] * int.from_bytes(public_values[i], 'big')) % PRIME

    l_pi = l_pi % PRIME


    # now l_pi_commit

    PROOF_BSB_COMMITMENTS = 0x320
    bsb_x = int.from_bytes(proof[PROOF_BSB_COMMITMENTS: PROOF_BSB_COMMITMENTS+32], 'big')
    bsb_y = int.from_bytes(proof[PROOF_BSB_COMMITMENTS + 32: PROOF_BSB_COMMITMENTS + 64], 'big')

    print("bsb ", bsb_x, " ", bsb_y)
    HASH_FR_SIZE_DOMAIN = 11
    HASH_FR_LEN_IN_BYTES = 48


    hash_fr_part1 = ((b'\x00' * 64) + proof[PROOF_BSB_COMMITMENTS: PROOF_BSB_COMMITMENTS+64]  + b'\x00' + HASH_FR_LEN_IN_BYTES.to_bytes(1, 'big') + b'\x00' + "BSB22-Plonk".encode('utf-8')
            + HASH_FR_SIZE_DOMAIN.to_bytes(1, 'big'))
    
    b0 = hashlib.sha256(hash_fr_part1).digest()
    
    hash_fr_part2 = (hashlib.sha256(hash_fr_part1).digest() + b'\x01' +  "BSB22-Plonk".encode('utf-8') + HASH_FR_SIZE_DOMAIN.to_bytes(1, 'big')) 


    b1 = hashlib.sha256(hash_fr_part2).digest()
    b1_int = int.from_bytes(b1, 'big')

    print("b1 ", b1_int)

    hash_fr_part3 = ((int.from_bytes(b0, 'big')^int.from_bytes(b1, 'big')).to_bytes(32, 'big') + b'\x02' + "BSB22-Plonk".encode('utf-8') + HASH_FR_SIZE_DOMAIN.to_bytes(1, 'big'))

    b2 = hashlib.sha256(hash_fr_part3).digest()
    b2_int = int.from_bytes(b2, 'big')

    print("b2 ", b2_int)

    h_fr = ((b1_int << 128) + (b2_int >> 128)) % PRIME

    print("h_fr ", h_fr)

    #now compute i-th langrange
    ith = len(public_values) + VK_INDEX_COMMIT_API_0

    w = expmod(VK_OMEGA, ith, PRIME)
    i = (zeta_int - w) % PRIME
    w = (w * VK_INV_DOMAIN_SIZE) % PRIME
    i = expmod(i, PRIME-2, PRIME)
    w = w * i % PRIME
    res = (w * zeta_power_n_minus_one) % PRIME

    print("ith langrage ", res)

    l_pi_commit = res * h_fr % PRIME

    print("l_pi commit ", l_pi_commit)

    l_pi = (l_pi + l_pi_commit) % PRIME

    print("final l_pi ", l_pi)


    # Now alpha square langrange.

    
    
    den1 = (((expmod((zeta_int - 1)%PRIME, PRIME-2, PRIME) * VK_INV_DOMAIN_SIZE % PRIME) * zeta_power_n_minus_one) % PRIME)
    alfa_square_lagrange = ((den1 * alfa_int % PRIME) *alfa_int % PRIME)

    print("alfa square lagrange ", alfa_square_lagrange)

    






    

    


    # now compute hash to field
















    


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
