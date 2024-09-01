from verifier import VERIFICATION_KEY, unpack_qr_code, verify_plonk
from pyzbar.pyzbar import decode
from time import sleep
import base64
import cv2


## Hardcoded things - we should open the doors only if:
REQUIRED_NFT = "1f13941d0995e111675124af4b0f9bdcc70390c3"
REQUIRED_SLOT = 3

RECENT_BATCH = 490000



def fetch_camera_image():
    # TODO - fetch fresh image from camera.
    return cv2.imread("../examples/proof_nft_qr.jpg")
    


def public_input_slot(public_input, slot):
    return public_input[slot * 32 : (slot+1) * 32]

def check_nft_info(public_inputs):
    nft = public_input_slot(public_inputs, 6).hex()
    owner = public_input_slot(public_inputs, 7).hex()
    batch_number = int.from_bytes(public_input_slot(public_inputs, 8), 'big')
    slot_position = int.from_bytes(public_input_slot(public_inputs, 9), 'big')
    if bytes.fromhex(REQUIRED_NFT.rjust(64, '0')).hex() != nft:
        raise Exception("Invalid NFT")
    
    if slot_position != REQUIRED_SLOT:
        raise Exception("Invalid NFT slot")
    
    if batch_number < RECENT_BATCH:
        raise Exception("Too old batch")
    
    # TODO - figure out how to 'know' the recent batch info (maybe some timestamp in the batch itself?)
    # TODO - the QR code should also have an owner signature.


def open_the_doors():
    # TODO - add door opening here.
    print("DOORS ARE OPEN")



def main():
    while True:
        image = fetch_camera_image()
        decoded_objects = decode(image)
        if len(decoded_objects) > 0:
            data = base64.b64decode(decoded_objects[0].data.decode())
            (public_inputs, proof) = unpack_qr_code(data)
            # Check if public inputs make sense for us (correct NFT etc)
            check_nft_info(public_inputs)
            
            vkey = bytes.fromhex(VERIFICATION_KEY)
            if verify_plonk(proof[4:], vkey, public_inputs):
                open_the_doors()
        
        # Wait - and then query camera again.
        sleep(5)


if __name__ == "__main__":
    main()