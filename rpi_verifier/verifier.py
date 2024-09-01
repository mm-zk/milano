import json

from py_ecc import bn128

from py_ecc.bn128.bn128_curve import G1, G2, add, multiply, FQ, FQ2, FQ12
import hashlib

from eth_utils import to_bytes, keccak, to_hex
import argparse
import cv2
from pyzbar.pyzbar import decode
import base64


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

G2_SRS_0_X_0 = 11559732032986387107991004021392285783925812861821192530917403151452391805634
G2_SRS_0_X_1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781
G2_SRS_0_Y_0 = 4082367875863433681332203403145435568316851327593401208105741076214120093531
G2_SRS_0_Y_1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930

G2_SRS_1_X_0 = 15805639136721018565402881920352193254830339253282065586954346329754995870280
G2_SRS_1_X_1 = 19089565590083334368588890253123139704298730990782503769911324779715431555531
G2_SRS_1_Y_0 = 9779648407879205346559610309258181044130619080926897934572699915909528404984
G2_SRS_1_Y_1 = 6779728121489434657638426458390319301070371227460768374343986326751507916979

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


def get_uint256_from_proof(proof, position):
    return int.from_bytes(proof[position: position + 32], 'big')


def get_ec_from_proof(proof, position):
    return (FQ(get_uint256_from_proof(proof, position)),
     FQ(get_uint256_from_proof(proof, position + 32)))

def mulmod(a, b):
    return (a * b) % PRIME


def compute_fold_h(proof, zeta_int): 
    zeta_power_n_plus_two = expmod(zeta_int, VK_DOMAIN_SIZE + 2, PRIME)
    zeta_power_n_minus_one = (expmod(zeta_int, VK_DOMAIN_SIZE, PRIME) + (PRIME - 1)) % PRIME



    PROOF_H_0_X = 0xc0
    PROOF_H_0_Y = 0xe0
    PROOF_H_1_X = 0x100
    PROOF_H_1_Y = 0x120

    PROOF_H_2_X = 0x140
    PROOF_H_2_Y = 0x160
    

    ## need 'ec_mul' 

    h0_x = get_uint256_from_proof(proof, PROOF_H_0_X)
    h0_y = get_uint256_from_proof(proof, PROOF_H_0_Y)
    h0_point = (FQ(h0_x), FQ(h0_y))
    h1_x = get_uint256_from_proof(proof, PROOF_H_1_X)
    h1_y = get_uint256_from_proof(proof, PROOF_H_1_Y)
    h1_point = (FQ(h1_x), FQ(h1_y))

    h2_x = get_uint256_from_proof(proof, PROOF_H_2_X)
    h2_y = get_uint256_from_proof(proof, PROOF_H_2_Y)
    h2_point = (FQ(h2_x), FQ(h2_y))

    folded_h = bn128.multiply(h2_point, zeta_power_n_plus_two)
    print("folded h", folded_h)

    folded_h_final = bn128.multiply(bn128.add(bn128.multiply(bn128.add(folded_h, h1_point), zeta_power_n_plus_two), h0_point), zeta_power_n_minus_one)

    print("folded h final ", folded_h_final)

    folded_h_final = (folded_h_final[0], -folded_h_final[1])
    print("folded h final ", folded_h_final) 

    return folded_h_final


# Now entering actual verify function.
def verify_plonk_internal(proof, public_values):

    print(f"Public values len: {len(public_values)}")
    assert len(public_values) == 2

    
    # check_input_size -- ignored for now 
    # Also not checking proof values (that they are smaller than PRIME -1)

    gamma_not_reduced = compute_gamma(proof, public_values)
    gamma_int = int.from_bytes(reduce_bytes(gamma_not_reduced), 'big')

    beta_not_reduced = compute_beta(gamma_not_reduced)
    beta_int = int.from_bytes(reduce_bytes(beta_not_reduced), 'big')

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


    # Verify opening for linearised polynomial
    PROOF_S1_AT_ZETA = 0x1e0; # Sσ1(zeta)
    PROOF_S2_AT_ZETA = 0x200; # Sσ2(zeta)
    PROOF_L_AT_ZETA = 0x180
    PROOF_R_AT_ZETA = 0x1a0
    PROOF_O_AT_ZETA = 0x1c0
    PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA = 0x260 # z(w*zeta)



    
    proof_s1 = get_uint256_from_proof(proof, PROOF_S1_AT_ZETA)
    s1 = ((proof_s1 * beta_int) % PRIME + gamma_int + get_uint256_from_proof(proof, PROOF_L_AT_ZETA)) % PRIME

    print("s1", s1)

    s2 = ((beta_int * get_uint256_from_proof(proof, PROOF_S2_AT_ZETA)) % PRIME + gamma_int + get_uint256_from_proof(proof, PROOF_R_AT_ZETA)) % PRIME

    print("s2", s2)
    o = (gamma_int + get_uint256_from_proof(proof, PROOF_O_AT_ZETA)) % PRIME
    
    

    state_open_linear_poly = (PRIME - (mulmod(mulmod(mulmod(mulmod(s1, s2), o), alfa_int), get_uint256_from_proof(proof, PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA))
     + l_pi  - alfa_square_lagrange)) % PRIME
    

    print("state open lin poly ", state_open_linear_poly)

    # Fold h

    folded_h = compute_fold_h(proof, zeta_int)
    print("folded h final ", folded_h) 

    ### Commitment linearized polynomial

    u = mulmod(get_uint256_from_proof(proof, PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA), beta_int)

    v = (mulmod(get_uint256_from_proof(proof, PROOF_S1_AT_ZETA), beta_int) + get_uint256_from_proof(proof, PROOF_L_AT_ZETA) + gamma_int) % PRIME

    w = (mulmod(beta_int, get_uint256_from_proof(proof, PROOF_S2_AT_ZETA)) + get_uint256_from_proof(proof, PROOF_R_AT_ZETA) + gamma_int) % PRIME

    print("v ", v)
    print("w ", w)

    s1 = mulmod(mulmod(mulmod(u, v), w), alfa_int)
    print("s1 ", s1)

    VK_COSET_SHIFT = 5

    u = (mulmod(beta_int, zeta_int) + get_uint256_from_proof(proof, PROOF_L_AT_ZETA) + gamma_int) % PRIME

    v = (mulmod(mulmod(beta_int, zeta_int), VK_COSET_SHIFT) + get_uint256_from_proof(proof, PROOF_R_AT_ZETA) + gamma_int) % PRIME

    w = (mulmod(mulmod(beta_int, zeta_int), VK_COSET_SHIFT*VK_COSET_SHIFT) + get_uint256_from_proof(proof, PROOF_O_AT_ZETA) + gamma_int) % PRIME

    s2 = (mulmod(-mulmod(mulmod(u, v), w), alfa_int) + alfa_square_lagrange) % PRIME

    print("s2 ", s2)

    # and now the actual EC work
    state_lin_pol = bn128.multiply((FQ(VK_QL_COM_X), FQ(VK_QL_COM_Y)), get_uint256_from_proof(proof, PROOF_L_AT_ZETA))

    foo = bn128.multiply((FQ(VK_QR_COM_X), FQ(VK_QR_COM_Y)), get_uint256_from_proof(proof, PROOF_R_AT_ZETA))

    rl = mulmod(get_uint256_from_proof(proof, PROOF_L_AT_ZETA), get_uint256_from_proof(proof, PROOF_R_AT_ZETA))

    foo2 = bn128.multiply((FQ(VK_QM_COM_X), FQ(VK_QM_COM_Y)), rl)

    foo3 = bn128.multiply((FQ(VK_QO_COM_X), FQ(VK_QO_COM_Y)), get_uint256_from_proof(proof, PROOF_O_AT_ZETA))

    res = bn128.add(bn128.add(bn128.add(state_lin_pol, foo), foo2), foo3)
    res = bn128.add((FQ(VK_QK_COM_X), FQ(VK_QK_COM_Y)), res)
    print("res ", res)


    PROOF_GRAND_PRODUCT_COMMITMENT_X = 0x220
    PROOF_GRAND_PRODUCT_COMMITMENT_Y = 0x240

    PROOF_OPENING_QCP_AT_ZETA = 0x300
    PROOF_BSB_COMMITMENTS = 0x320
    # VK_CUSTOM_GATES is 1.

    res = bn128.add(res, bn128.multiply((FQ(bsb_x), FQ(bsb_y)), get_uint256_from_proof(proof, PROOF_OPENING_QCP_AT_ZETA)))


    foo8 = bn128.multiply((FQ(VK_S3_COM_X), FQ(VK_S3_COM_Y)), s1)
    foo9 = bn128.multiply((FQ(get_uint256_from_proof(proof, PROOF_GRAND_PRODUCT_COMMITMENT_X)),
                           FQ(get_uint256_from_proof(proof, PROOF_GRAND_PRODUCT_COMMITMENT_Y))
                           ), s2)
    
    lin_poly_x = bn128.add(bn128.add(bn128.add(res, foo8), foo9), folded_h)

    print("lin poly x", lin_poly_x)

    
    PROOF_L_COM_X = 0x0
    PROOF_L_COM_Y = 0x20
    PROOF_R_COM_X = 0x40
    PROOF_R_COM_Y = 0x60
    PROOF_O_COM_X = 0x80
    PROOF_O_COM_Y = 0xa0
    

    ## Gamma KZG now (fiat shamir challenge)

    kzg_gamma_challenge = ("gamma".encode('utf-8') + zeta 
                           + int(lin_poly_x[0]).to_bytes(32, 'big')
                           + int(lin_poly_x[1]).to_bytes(32, 'big')
                           + proof[PROOF_L_COM_X: PROOF_L_COM_X+0xc0]
                           + VK_S1_COM_X.to_bytes(32, 'big')
                           + VK_S1_COM_Y.to_bytes(32, 'big')
                           + VK_S2_COM_X.to_bytes(32, 'big')
                           + VK_S2_COM_Y.to_bytes(32, 'big')
                           + VK_QCP_0_X.to_bytes(32, 'big')
                           + VK_QCP_0_Y.to_bytes(32, 'big')
                           + state_open_linear_poly.to_bytes(32, 'big')
                           + proof[PROOF_L_AT_ZETA: PROOF_L_AT_ZETA + 32]
                           + proof[PROOF_R_AT_ZETA: PROOF_R_AT_ZETA + 32]
                           + proof[PROOF_O_AT_ZETA: PROOF_O_AT_ZETA + 32]
                           + proof[PROOF_S1_AT_ZETA: PROOF_S1_AT_ZETA + 32]
                           + proof[PROOF_S2_AT_ZETA: PROOF_S2_AT_ZETA + 32]
                           + proof[PROOF_OPENING_QCP_AT_ZETA: PROOF_OPENING_QCP_AT_ZETA + 32]
                           + proof[PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA: PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA + 32]
                           )

    gamma_kzg = int.from_bytes(hashlib.sha256(kzg_gamma_challenge).digest(), 'big') % PRIME
    print('gamma kzg ', gamma_kzg)

    ### Fold state

    folded_digests = bn128.add(lin_poly_x,
                               bn128.multiply((FQ(get_uint256_from_proof(proof, PROOF_L_COM_X)),
                                              FQ(get_uint256_from_proof(proof, PROOF_L_COM_Y))),
                                                gamma_kzg))
    
    acc_gamma = gamma_kzg                             
    claimed_values = state_open_linear_poly + mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_L_AT_ZETA))
    acc_gamma = mulmod(acc_gamma, gamma_kzg)
     

    folded_digests = bn128.add(folded_digests,
                               bn128.multiply((FQ(get_uint256_from_proof(proof, PROOF_R_COM_X)),
                                                FQ(get_uint256_from_proof(proof, PROOF_R_COM_Y))),
                                                acc_gamma))

    claimed_values = (claimed_values +  mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_R_AT_ZETA))) % PRIME

    acc_gamma = mulmod(acc_gamma, gamma_kzg)
    
    folded_digests = bn128.add(folded_digests,
                               bn128.multiply((FQ(get_uint256_from_proof(proof, PROOF_O_COM_X)),
                                                FQ(get_uint256_from_proof(proof, PROOF_O_COM_Y))),
                                                acc_gamma))
    claimed_values = (claimed_values +  mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_O_AT_ZETA))) % PRIME
    acc_gamma = mulmod(acc_gamma, gamma_kzg)




    folded_digests = bn128.add(folded_digests, bn128.multiply((FQ(VK_S1_COM_X), FQ(VK_S1_COM_Y)), acc_gamma))
    claimed_values = (claimed_values +  mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_S1_AT_ZETA))) % PRIME
    acc_gamma = mulmod(acc_gamma, gamma_kzg)


    folded_digests = bn128.add(folded_digests, bn128.multiply((FQ(VK_S2_COM_X), FQ(VK_S2_COM_Y)), acc_gamma))
    claimed_values = (claimed_values +  mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_S2_AT_ZETA))) % PRIME
    acc_gamma = mulmod(acc_gamma, gamma_kzg)


    folded_digests = bn128.add(folded_digests, bn128.multiply((FQ(VK_QCP_0_X), FQ(VK_QCP_0_Y)), acc_gamma))
    claimed_values = (claimed_values +  mulmod(acc_gamma, get_uint256_from_proof(proof, PROOF_OPENING_QCP_AT_ZETA))) % PRIME
    
    print("acc gamma", acc_gamma)

    print("claimed vals ", claimed_values)
    print("folded dig", folded_digests)                               


    # Grande finale - verify multipoint

    PROOF_BATCH_OPENING_AT_ZETA_X = 0x280
    PROOF_BATCH_OPENING_AT_ZETA_Y = 0x2a0
    PROOF_OPENING_AT_ZETA_OMEGA_X = 0x2c0
    PROOF_OPENING_AT_ZETA_OMEGA_Y = 0x2e0

    batch_verify_random_input = (int(folded_digests[0]).to_bytes(32, 'big')
                                + int(folded_digests[1]).to_bytes(32, 'big')
                                + proof[PROOF_BATCH_OPENING_AT_ZETA_X: PROOF_BATCH_OPENING_AT_ZETA_X+32]
                                + proof[PROOF_BATCH_OPENING_AT_ZETA_Y: PROOF_BATCH_OPENING_AT_ZETA_Y+32]
                                + proof[PROOF_GRAND_PRODUCT_COMMITMENT_X: PROOF_GRAND_PRODUCT_COMMITMENT_X+32]
                                + proof[PROOF_GRAND_PRODUCT_COMMITMENT_Y: PROOF_GRAND_PRODUCT_COMMITMENT_Y+32]
                                + proof[PROOF_OPENING_AT_ZETA_OMEGA_X: PROOF_OPENING_AT_ZETA_OMEGA_X+32]
                                + proof[PROOF_OPENING_AT_ZETA_OMEGA_Y: PROOF_OPENING_AT_ZETA_OMEGA_Y+32]
                                + zeta
                                + gamma_kzg.to_bytes(32, 'big')        
                                )
    batch_verify_random = int.from_bytes(hashlib.sha256(batch_verify_random_input).digest(), 'big') % PRIME

    print("batch ver random", batch_verify_random)

    
    folded_quotients = get_ec_from_proof(proof, PROOF_BATCH_OPENING_AT_ZETA_X)

    folded_quotients = bn128.add(folded_quotients,
                                 bn128.multiply(get_ec_from_proof(proof, PROOF_OPENING_AT_ZETA_OMEGA_X),                                     
                                     batch_verify_random
                                 ))
    
    folded_digests = bn128.add(folded_digests, bn128.multiply(get_ec_from_proof(proof, PROOF_GRAND_PRODUCT_COMMITMENT_X), batch_verify_random))

    # a.k.a folded evals
    claimed_values = (claimed_values + (get_uint256_from_proof(proof, PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA) * batch_verify_random)) % PRIME

    print("claimed vals", claimed_values)

    G1_SRS_X = 14312776538779914388377568895031746459131577658076416373430523308756343304251
    G1_SRS_Y = 11763105256161367503191792604679297387056316997144156930871823008787082098465

    folded_evals_commit = bn128.multiply((FQ(G1_SRS_X), FQ(G1_SRS_Y)), claimed_values)

    print("Folded evals commit ", folded_evals_commit)
    P_MOD = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    folded_evals_commit = (folded_evals_commit[0], P_MOD - folded_evals_commit[1])

    folded_digests = bn128.add(folded_digests, folded_evals_commit)

    folded_points_quotients = bn128.multiply(get_ec_from_proof(proof, PROOF_BATCH_OPENING_AT_ZETA_X), zeta_int)
    zeta_omega = mulmod(zeta_int, VK_OMEGA)
    batch_verify_random = mulmod(batch_verify_random, zeta_omega)
    folded_points_quotients = bn128.add(folded_points_quotients,
        bn128.multiply(
            get_ec_from_proof(proof, PROOF_OPENING_AT_ZETA_OMEGA_X),
            batch_verify_random
        )
    )
    folded_digests = bn128.add(folded_digests, folded_points_quotients)

    folded_quotients = (folded_quotients[0], P_MOD - folded_quotients[1])

    print("folded digests", folded_digests)
    print("folded quot", folded_quotients)


    G2_SRS0 = (FQ2([G2_SRS_0_X_1, G2_SRS_0_X_0]), FQ2([G2_SRS_0_Y_1, G2_SRS_0_Y_0]))
    G2_SRS1 = (FQ2([G2_SRS_1_X_1, G2_SRS_1_X_0]), FQ2([G2_SRS_1_Y_1, G2_SRS_1_Y_0]))


    first_pairing = bn128.pairing(G2_SRS0, folded_digests)    
    second_pairing = bn128.pairing(G2_SRS1, folded_quotients)
    pairing_product = FQ12.one()
    pairing_product *= first_pairing
    pairing_product *= second_pairing

    print("*** IS VALID --- ", pairing_product == FQ12.one())

    return pairing_product == FQ12.one()


# Verifies plonk proof, given proof, verification key and public inputs.
def verify_plonk(proof_bytes, vkey_bytes, public_values_bytes):
    print(f"proof: {len(proof_bytes)}, vk: {len(vkey_bytes)} pv: {len(public_values_bytes)}")
    public_values_hash = (int.from_bytes(hashlib.sha256(public_values_bytes).digest(), 'big') &( (1<<253) - 1)).to_bytes(32, 'big')
    proof_valid = verify_plonk_internal(proof_bytes, [vkey_bytes, public_values_hash])
    if not proof_valid:
        raise Exception("Proof is not valid")
    return proof_valid


def verify(data):
    proof_bytes = bytes.fromhex(data['proof'][2:])
    if proof_bytes[:4].hex() != "c430ff7f":
        raise "Wrong selector"
    
    proof_bytes = proof_bytes[4:]

    public_values = bytes.fromhex(data['publicValues'][2:])

    # check that public values are matching other entries in json
    struct_type = int(data["structType"]).to_bytes(32, 'big')
    sender = bytes.fromhex(data['sender'][2:]).rjust(32, b'\x00')
    receiver = bytes.fromhex(data['receiver'][2:]).rjust(32, b'\x00')
    token = bytes.fromhex(data['token'][2:]).rjust(32, b'\x00')
    
    amount = int(data["amount"]).to_bytes(32, 'big')
    tx_id = bytes.fromhex(data['txId'][2:]).rjust(32, b'\x00')


    nft = bytes.fromhex(data['nft'][2:]).rjust(32, b'\x00')
    owner = bytes.fromhex(data['owner'][2:]).rjust(32, b'\x00')
    batch_number = int(data["batchNumber"]).to_bytes(32, 'big')
    slot_position = int(data["slotPosition"]).to_bytes(32, 'big')

    computed_public_values = b"".join([struct_type, sender, receiver, token, amount, tx_id, nft, owner, batch_number, slot_position])

    if public_values != computed_public_values:
        raise Exception("Public values are not correct")


    proof_valid = verify_plonk(proof_bytes, bytes.fromhex(data['vkey'][2:]), public_values)
    if not proof_valid:
        raise Exception("Proof is not valid")



def decode_qr_code(image_path):
    # Load the image using OpenCV
    image = cv2.imread(image_path)
    # Decode the QR code
    decoded_objects = decode(image)
    return decoded_objects[0].data.decode()
    


# This VK will change every time there is a change to the program that SP1 verifies.
VERIFICATION_KEY = "00238ded04e76b8ba857754a53926a85650366a0ccfdd71a1430dc6cccdf1c28"

def unpack_qr_code(data):
    public_input_len = int.from_bytes(data[:4], 'big')
    public_inputs = data[4:4+public_input_len]
    proof = data[4+public_input_len:]
    return (public_inputs, proof)



def main():
    parser = argparse.ArgumentParser(description='Milano - Proof verifier')
    
    # Command subparsers
    subparsers = parser.add_subparsers(dest='command', required=True, help='Type of command')
    
    # Subparser for the "transaction" command
    parser_transaction = subparsers.add_parser('json', help='Verify proof from JSON file')
    
    # Subparser for the "NFT" command
    parser_nft = subparsers.add_parser('qr', help='Verify proof from QR code')
    
    # Common argument for both commands
    parser.add_argument('input_file', type=str, help='JSON file name to write the output to')
    
    # Parse the arguments
    args = parser.parse_args()


    if args.command == 'json':
        with open(args.input_file, 'r') as file:
            data = json.load(file)
            verify(data)
    elif args.command == 'qr':
        data = decode_qr_code(args.input_file)
        # Data travels as b64 encoding in QR codes.
        data = base64.b64decode(data)
        (public_inputs, proof) = unpack_qr_code(data)
        vkey = bytes.fromhex(VERIFICATION_KEY)

        verify_plonk(proof[4:], vkey, public_inputs)
        
    else:
        raise Exception("Invalid command - only json or QR are supported")
     



if __name__ == "__main__":
    main()


