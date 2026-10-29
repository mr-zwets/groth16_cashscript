# PROGRESS (wip/plonk-kzg-prover; this file stays off main)

## Done (2026-10-29)
- Go module pinned: gnark v0.16.4, gnark-crypto v0.21.1-0.20260913224755-1409fe592052 (gnark's own requirement).
- Circuits: mul2 (2 public: n0, n1; a*b=n0, a+b=n1) and merkle16 (3 public: root, nullifierHash, context;
  MiMC depth-16 membership with nullifier). No BSB22 commitments (asserted).
- Test SRS: unsafekzg.WithToxicSeed, tau = SHA256(seed) mod r; both circuits share [1]_1, [1]_2, [tau]_2 (asserted).
- FORMAT.md (768-byte proof = MarshalSolidity layout; 944-byte VK), vectors/{mul2,merkle16}.json:
  5 valid + 76/78 tampered each; gnark Verify rejects all 75 struct-representable tampers.
- verify.mjs: independent BigInt + @noble/curves 2.2.0 verifier; 164/164 verdicts; r0 == gnark ClaimedValues[0].
- PROTOCOL.md: step-by-step verifier and operation counts (19 G1 muls, 1 Fr inv, 6 SHA-256 / 37 blocks, 2 pairings fixed G2).

## Open (for the Verifier phase)
- u derivation follows gnark's Solidity template but is not pinned by any vector (verdict independent of u).
- Ceremony SRS loading not exercised.
- CashVM cost of 19 GLV G1 muls + fixed-G2 2-pairing: to be built and measured.
