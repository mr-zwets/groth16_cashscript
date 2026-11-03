# Provenance of the vendored upstream files

Every file in this directory is a byte-identical copy of the file at the pinned commit. The blob column is the git
blob id (`git hash-object <file>` here equals `git rev-parse <commit>:<path>` upstream). Re-check with
`git -C <clone> rev-parse <commit>:<path>` against `git hash-object upstream/<file>`.

## SP1 v5 (succinctlabs/sp1-contracts @ 512b5e029abc27f6e46a3c7eba220dac83ecc306)

| file | upstream path | git blob |
|---|---|---|
| sp1-v5.0.0-Groth16Verifier.sol | contracts/src/v5.0.0/Groth16Verifier.sol | c27683d3ca594e25d6e461fa6f724f476826cc0d |
| sp1-v5.0.0-SP1VerifierGroth16.sol | contracts/src/v5.0.0/SP1VerifierGroth16.sol | d7f1cf6331d76203b69499b16ea6c1374e9a4a93 |

The SP1VerifierGroth16.sol copy before the Track 11 fix round matched later sp1-contracts commits (for example
db9ed47), not 512b5e02. The difference was whitespace only: `hashPublicValues` on one line, and a trailing newline. The
selector `a4594c59` and the 253-bit mask were the same. The file now holds the 512b5e02 bytes.

## SP1 v5 proofs (third-party, carrying the v5 selector a4594c59)

| file | repo @ commit | path | git blob |
|---|---|---|---|
| sp1-fixture-silvana-lib.rs | SilvanaOne/zk-tests @ c2ec296b580ff54df71c7f81970cd329358edeec | packages/sp1/add/arbitrum/src/lib.rs | 14782f2754697898fe41eec92fecdd8ba577df9d |
| sp1-fixture-sparsity-gcp_proof.json | sparsity-xyz/zkp-tee-tutorial @ 33117da00d8cbfbab5df3ebac1df3ffeb73354c7 | modules/02-tdx-gcp/gcp_proof.json | d7862b2b1968bc84ccee007ef34d43bed35044a2 |
| sp1-fixture-pessina-TransferForm.tsx | Pessina/hackathon @ d5f08571088dec1f4c4cfee2182e322e6a736f26 | zk-solana-aa-client/components/TransferForm.tsx | d0b8e60450b01821d4c9dd0401410c9626c7f22d |

These were fetched from GitHub raw at the pinned commits. The Track 11 review re-fetched them and found them
byte-identical. `extract.mjs` checks each proof with noble against the SP1 v5 VK.

## RISC Zero (risc0/risc0-ethereum @ fe5adc304262eec32986246a29e46c9a250cd7e9)

| file | upstream path | git blob | used for |
|---|---|---|---|
| risc0-Groth16Verifier.sol | contracts/src/groth16/Groth16Verifier.sol | 0023123c5cfa70c21db1a103a7bd811b889a4211 | VK (snarkjs export, 5 public inputs) |
| risc0-ControlID.sol | contracts/src/groth16/ControlID.sol | 7317a770b08c733455b209df90f046b26ea85bf2 | CONTROL_ROOT, BN254_CONTROL_ID (file last changed in 0dd148c3) |
| risc0-RiscZeroGroth16Verifier.sol | contracts/src/groth16/RiscZeroGroth16Verifier.sol | 310d45bf7426255456be8a844d67a5233789f596 | splitDigest; input order [CR0, CR1, claim0, claim1, BN254_CONTROL_ID]; VERSION 5.0.0-rc.1 |
| risc0-IRiscZeroVerifier.sol | contracts/src/IRiscZeroVerifier.sol | b8d21d3bb2e91587d958c9342ca2469fdf78852c | ReceiptClaimLib.ok / digest, SystemState and Output digests |
| risc0-TestReceiptV5_0.sol | contracts/test/TestReceiptV5_0.sol | 66ecf46a95ebd3df7ee74875f275cd82ef65ad3f | fixture 0 (verifies under the pinned control root) |
| risc0-TestReceiptV3_0.sol | contracts/test/TestReceiptV3_0.sol | 1a670c1159eaabade8ab3a124d7101e70b1fc7e8 | wrong-version negative (valid under 274eccaf's control root) |
| risc0-TestReceiptV2_2.sol | contracts/test/TestReceiptV2_2.sol | 4139b9cf57359eeecfc176ccf1b62be00517e1cf | wrong-version negative (6c4fb313) |
| risc0-TestReceiptV2_1.sol | contracts/test/TestReceiptV2_1.sol | e7b07c65667ce94dfe5ba272597c85ce5802d6eb | wrong-version negative (dc9d181c) |
| risc0-TestReceiptV2_0.sol | contracts/test/TestReceiptV2_0.sol | c253af2d42cdb0af3aad264c71c68ef4c5c942ae | wrong-version negative (90877d9a) |

`RiscZeroGroth16Verifier.sol` and `IRiscZeroVerifier.sol` were added in the fix round. `extract.mjs` pins the
statements that `claims.mjs` and `covenant.mjs` implement as text checks against these two files: the splitDigest
body, the input order, the `ReceiptClaimLib.ok(...).digest()` call, the three tag strings, and the `<< 8` length
words. If one of these statements is no longer in the files, the extractor aborts.
