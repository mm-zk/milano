use alloy_sol_types::sol;

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
