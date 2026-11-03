//!
//! SP1 Add Proof Verifier for Stylus
//!
//! This contract verifies SP1 Groth16 proofs for the Add program and maintains a running root state.
//! It's equivalent to the Solidity Add.sol contract but uses the sp1-verifier crate directly.
//!

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

// Use our local bn module
mod bn;

// Use our local groth16 module instead of sp1-verifier
mod groth16;
use groth16::Groth16Verifier;

/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{
    alloy_primitives::{FixedBytes, U256},
    prelude::*,
};

// Define some persistent storage using the Solidity ABI.
// `AddVerifier` will be the entrypoint.
sol_storage! {
    #[entrypoint]
    pub struct AddVerifier {
        /// The current root state
        uint256 root;
    }
}


/// Declare that `AddVerifier` is a contract with the following external methods.
#[public]
impl AddVerifier {
    /// The entrypoint for verifying the proof and updating the root.
    /// @param vkey The verification key as 32 bytes
    /// @param public_values The encoded public values (old_root, new_root)
    /// @param proof_bytes The encoded proof
    pub fn verify_proof(
        &mut self,
        vkey: FixedBytes<32>,
        public_values: Vec<u8>,
        proof_bytes: Vec<u8>,
    ) -> (U256, U256) {
        // Public values should be 64 bytes (2 * 32 bytes for old_root and new_root)
        if public_values.len() != 64 {
            panic!(
                "Invalid public inputs length: expected 64, got {}",
                public_values.len()
            );
        }

        // Get the verification key as hex string (with 0x prefix as expected by sp1-verifier)
        let vkey_bytes: [u8; 32] = vkey.0;
        let vkey_hex = format!("0x{}", groth16::hex_utils::encode(&vkey_bytes));

        // Perform real Groth16 verification
        let verification_result = Groth16Verifier::verify(
            &proof_bytes,
            &public_values,
            &vkey_hex,
            groth16::GROTH16_VK_BYTES,
        );

        match verification_result {
            Ok(()) => {
                // Decode public values (old_root and new_root)
                let mut old_root_bytes = [0u8; 32];
                let mut new_root_bytes = [0u8; 32];
                old_root_bytes.copy_from_slice(&public_values[0..32]);
                new_root_bytes.copy_from_slice(&public_values[32..64]);

                let old_root = U256::from_be_bytes(old_root_bytes);
                let new_root = U256::from_be_bytes(new_root_bytes);

                // Update the root state
                let _previous_root = self.root.get();
                self.root.set(new_root);

                (old_root, new_root)
            }
            Err(e) => {
                // Panic with error message (will revert the transaction)
                panic!("Groth16 proof verification failed: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_groth16_verifier_directly() {
        // Test the Groth16 verifier directly without the contract wrapper
        
        // Test vkey from groth16-fixture.json
        let vkey_hex = "0x00bee99e7cb561bd60cb0bb43002e9ae74ff8769c756fd82e6a4b18d990f7680";
        
        // Real proof from groth16-fixture.json (with 4-byte prefix)
        let proof_hex = "a4594c59190926c25c1da65ec069f86f9d205203d249dcf211b9674b901fd5dc5165936a0f62e609d1af19766aebd0900357965a7ed53607facfcee606a58ad73f8846b2213e496e696f8a13903d748970599fd0e3ea9bdfec6548498dd7f3460085420a2934c19367d053967cdeea7b372c80f8b52c81c12ba954ac51e8347b02d3b39a0e8e4c1fe5ec8b58f1f3e7d18e06af37ca2128c743b18620a446a8438fad8c04166e733790a0628fcbc2159094d464efaf614d0c8befe2d0e87c44718dded3162da793e0a132bbb2cba9abd24f8216e255a80308d3fc529ef0f639606eebc508072e9b77d98bb2dd79e0d5941d4146b9eaa149097ff6a14b5159d402354da6d4";
        let proof_bytes = hex::decode(proof_hex).expect("Invalid proof hex");

        // Real public values from groth16-fixture.json
        let public_values_hex = "3f9e50079e612eda9707a092d8fc870367bf8cb1562615d908c672cc8f20d16b91faebc9b7829b6c13f1302ab311d1d55be2a85e0b63c233294acea4da4d7526";
        let public_values = hex::decode(public_values_hex).expect("Invalid public values hex");

        // Verify using the Groth16 verifier directly
        let result = groth16::Groth16Verifier::verify(
            &proof_bytes,
            &public_values,
            vkey_hex,
            groth16::GROTH16_VK_BYTES,
        );

        // The verification should succeed
        assert!(result.is_ok(), "Groth16 verification failed: {:?}", result);
    }

    #[test]
    fn test_public_values_parsing() {
        // Test that we can correctly parse public values
        let public_values_hex = "3f9e50079e612eda9707a092d8fc870367bf8cb1562615d908c672cc8f20d16b91faebc9b7829b6c13f1302ab311d1d55be2a85e0b63c233294acea4da4d7526";
        let public_values = hex::decode(public_values_hex).expect("Invalid public values hex");
        
        assert_eq!(public_values.len(), 64, "Public values should be 64 bytes");
        
        // Parse old_root and new_root
        let mut old_root_bytes = [0u8; 32];
        let mut new_root_bytes = [0u8; 32];
        old_root_bytes.copy_from_slice(&public_values[0..32]);
        new_root_bytes.copy_from_slice(&public_values[32..64]);
        
        let old_root = U256::from_be_bytes(old_root_bytes);
        let new_root = U256::from_be_bytes(new_root_bytes);
        
        // Check expected values
        let expected_old_root = U256::from_be_bytes([
            0x3f, 0x9e, 0x50, 0x07, 0x9e, 0x61, 0x2e, 0xda, 0x97, 0x07, 0xa0, 0x92, 0xd8, 0xfc, 0x87, 0x03,
            0x67, 0xbf, 0x8c, 0xb1, 0x56, 0x26, 0x15, 0xd9, 0x08, 0xc6, 0x72, 0xcc, 0x8f, 0x20, 0xd1, 0x6b,
        ]);
        let expected_new_root = U256::from_be_bytes([
            0x91, 0xfa, 0xeb, 0xc9, 0xb7, 0x82, 0x9b, 0x6c, 0x13, 0xf1, 0x30, 0x2a, 0xb3, 0x11, 0xd1, 0xd5,
            0x5b, 0xe2, 0xa8, 0x5e, 0x0b, 0x63, 0xc2, 0x33, 0x29, 0x4a, 0xce, 0xa4, 0xda, 0x4d, 0x75, 0x26,
        ]);
        
        assert_eq!(old_root, expected_old_root);
        assert_eq!(new_root, expected_new_root);
    }
}
#[cfg(test)]
mod test_basic {
    use crate::bn::fields::{const_fq, Fq, FieldElement};
    
    #[test]
    fn test_fq_basic() {
        // Test that 1 * 2 = 2
        let one = Fq::one();
        let two = const_fq([2, 0, 0, 0]);
        let result = one * two;
        assert_eq!(result, two, "1 * 2 should equal 2");
        
        // Test that 2 + 3 = 5
        let three = const_fq([3, 0, 0, 0]);
        let five = const_fq([5, 0, 0, 0]);
        let sum = two + three;
        assert_eq!(sum, five, "2 + 3 should equal 5");
    }
    #[test]
    fn test_g1_generator() {
        use crate::bn::groups::{G1, AffineG1};
        use crate::bn::groups::GroupElement;
        
        // Get the generator
        let g = G1::one();
        let g_affine = g.to_affine().unwrap();
        
        // The BN254 G1 generator should be (1, 2)
        let expected_x = Fq::one();
        let expected_y = const_fq([2, 0, 0, 0]);
        
        assert_eq!(*g_affine.x(), expected_x, "G1 generator x should be 1");
        assert_eq!(*g_affine.y(), expected_y, "G1 generator y should be 2");
        
        // Test that it's on the curve: y^2 = x^3 + 3
        let y_squared = g_affine.y().squared();
        let x_cubed = g_affine.x().squared() * *g_affine.x();
        let b = const_fq([3, 0, 0, 0]);
        let rhs = x_cubed + b;
        
        assert_eq!(y_squared, rhs, "Generator should be on curve");
    }
}