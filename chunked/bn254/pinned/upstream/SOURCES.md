# Vendored upstream files (Track 12)

Byte-identical copies, fetched with the GitHub contents API on 2026-11-03. `git hash-object <file>` reproduces each blob id.

| file | repo | ref (commit) | path | git blob |
|---|---|---|---|---|
| risc0-ethereum-v3.0.1-ControlID.sol | risc0/risc0-ethereum | v3.0.1 (365e7b2db4f620fa256580c27558d2623362b9ae) | contracts/src/groth16/ControlID.sol | 022efda6f04561dbe5f4fd243c3e4c15aa9dc883 |
| risc0-v3.0.6-control_id.rs | risc0/risc0 | v3.0.6 (1cc70cf05033a79ebc90f07c679cb4bd1cd301b9) | risc0/circuit/recursion/src/control_id.rs | cb50b4b4716a4e0bc78661e2b750256db8f94ec3 |

Also checked (not vendored, the same file as Track 11's pin): risc0-ethereum v3.0.1 `contracts/src/groth16/Groth16Verifier.sol`
has git blob 0023123c5cfa70c21db1a103a7bd811b889a4211, equal to `../../real-keys/upstream/risc0-Groth16Verifier.sol`
(risc0-ethereum fe5adc30). So the released RISC Zero Groth16 VK is the one Track 11 pinned; only the control root differs.
