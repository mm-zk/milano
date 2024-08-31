use alloy_primitives::U256;
use alloy_sol_types::sol;
use tiny_keccak::{Hasher, Keccak};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint256 struct_type;
        // if structu type is 0:
        address sender;
        address receiver;
        address token;
        uint256 amount;
        bytes32 tx_id;
        // If struct type is 1:
        address nft;
        address owner;
        uint256 batch_number;
        uint256 slot_position;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

pub fn other_stuff() -> U256 {
    U256::from_be_bytes(compute_keccak(&[0]))

    //U256::from(15)
}

fn compute_keccak(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}
