# plonk-kzg prover: gnark PLONK (KZG, BN254, SHA-256) proofs for a CashVM verifier

Track 6, Prover phase. This is research, not a leaderboard entry.

This module produces gnark PLONK proofs in a form a CashVM verifier can check. It also contains an independent
JS reference verifier, which is the spec the on-chain verifier will follow.
- Prover: gnark **v0.16.4** with gnark-crypto **v0.21.1-0.20260913224755-1409fe592052**. This is the exact
  pseudo-version gnark v0.16.4 requires; both are pinned in `go.mod`.
- Backend: PLONK over BN254 with KZG commitments, `plonk.Setup / Prove / Verify`, default options.
- Fiat-Shamir: gnark's defaults, `ChallengeHash = KZGFoldingHash = sha256`. Every hash is a plain padded
  SHA-256 of a byte string, so `OP_SHA256` computes all of them.
- BSB22 / `Commit` custom-gate commitments (Track 7): `mul2` and `merkle16` have none. `range64` and `merkle16rc`
  use gnark's `std/rangecheck`, which calls `api.Commit` once, so they have exactly one. `main.go` asserts the
  expected count per circuit. The verifier delta is PROTOCOL.md "BSB22 commitments" and the layout FORMAT.md
  "BSB22 commitments" (format `v2-bsb22`).

Files:
- The byte format is in [FORMAT.md](FORMAT.md).
- The verifier, step by step, with operation counts, is in [PROTOCOL.md](PROTOCOL.md).
- The reference verifier is [verify.mjs](verify.mjs).

## Result in one paragraph

gnark's stock PLONK verifier, with its SHA-256 transcript, is reproduced exactly by an independent BigInt
verifier.

Checked on 164 cases:
- **All 10 valid proofs are accepted** (5 per circuit). On each one, the recomputed linearised opening equals
  gnark's own `ClaimedValues[0]`.
- **All 154 tampered variants are rejected**.
- gnark's own `Verify` also rejects all 75 tampered variants its structs can represent.

Shape of the verifier:
- A proof is **768 bytes**: 9 G1 points and 6 scalars, in gnark's `MarshalSolidity` layout.
- One verification costs **19 G1 scalar multiplications** (8 with fixed bases), **1 Fr inversion**,
  **6 SHA-256 calls** (37 blocks) and **one 2-pairing product whose G2 points are both fixed SRS constants**.
- This is the same for both circuits (n = 2^3 and n = 2^14), so the cost is essentially independent of
  circuit size.

Universality:
- The two circuits share one SRS.
- The verifier needs only `[1]_1`, `[1]_2` and `[τ]_2` from it. Everything else in a VK is derived from the
  circuit by `plonk.Setup`, which uses no secret.

## BSB22 commitments (Track 7)

Two circuits with one commitment each (`std/rangecheck`, 64-bit check). Since the Track 7 integration
(`wip/plonk-usable-verifier`) they are built on the same Aztec Ignition SRS as `mul2` and `merkle16`
(`-srs ... -circuits range64,merkle16rc`); the counts below are that run's.


| name | public inputs | statement | constraints | n | VK | proof | valid | tampered (gnark-checked) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| `range64` | `n0` | `a·a = n0`, `0 ≤ a < 2^64` | 129 | 2^8 | 1,024 B | 864 B | 5 | 86 (44) |
| `merkle16rc` | `root, nullifierHash, context` | merkle16 with a private 64-bit amount in the leaf | 15,680 | 2^14 | 1,024 B | 864 B | 5 | 91 (47) |

- `verify.mjs` accepts all 10 valid proofs and rejects all 177 tampered ones. On every valid proof the recomputed
  `r0` equals gnark's `ClaimedValues[0]`, and the JS hash-to-field equals the value gnark-crypto's
  `hash_to_field` gives in Go (`bsb22Hash`).
- gnark's own `Verify` rejects all 91 tampered variants its structs can represent (it panics the generator
  otherwise).
- Cost of one commitment: +2 G1 scalar multiplications (one fixed base Qcp, one proof base Bsb22), +1 on-curve
  check, +3 SHA-256 calls (8 blocks: the hash-to-field 5, the larger γ, α and v 3), one more Lagrange
  denominator in the same batched inversion, +96 proof bytes.
- `-circuits range64,merkle16rc` builds only these; each circuit then has its own witness stream, while
  `mul2,merkle16` (the default) keep the v1 shared stream so their keys regenerate byte for byte.

## Circuits

| name | public inputs | statement | constraints | n | prove (4 threads) |
|---|---|---|---:|---:|---:|
| `mul2` | `n0, n1` | knows a, b with `a·b = n0` and `a+b = n1` | 4 | 2^3 | ~2 ms |
| `merkle16` | `root, nullifierHash, context` | `nullifierHash = MiMC(nullifier)`; the leaf `MiMC(nullifier, trapdoor)` is in the depth-16 MiMC Merkle tree with root `root`; `context` is bound as a public input | 15,110 | 2^14 | ~205 ms |

**mul2 and the Groth16 fixtures.** The bench's Groth16 fixtures prove no circuit:
- Their VK is built from known scalars, and each proof is solved in the exponent
  (`zk-verifier-bench/docs/proof-generality.md`, `src/checkpoints/gen-pairing-vectors.ts`).
- They only fix the interface: two public inputs `n0, n1`, any values.
- `mul2` is the closest real statement with that interface. The two public inputs are arbitrary field
  elements, and the statement holds because the prover knows a and b.
- What matters for the verifier is the shape (k = 2 public inputs, a tiny circuit), and that is the same.
- A Groth16 VK from the bench cannot be reused: PLONK keys are a different object.

**merkle16** is the application-shaped circuit:
- It is Semaphore/Tornado-shaped membership with a nullifier, using gnark's `std/hash/mimc` (MiMC-BN254,
  Miyaguchi-Preneel) as the SNARK-friendly hash.
- A covenant would keep `root` in its state and record `nullifierHash` to prevent double use.
- It would set `context` to a hash of the spending transaction's outputs, reduced mod r, so that a proof cannot
  be replayed in another transaction.
- `context` has no constraint of its own. In PLONK a public input is bound by the PI(X) term of the gate
  identity, and the `pi.2.*` tampered vectors confirm the binding.

## SRS

The vectors use the **Aztec Ignition** ceremony (176 participants, then sealed by Aztec), not a test SRS
(Track 7, branch `wip/plonk-usable-srs`). Details, URLs and hashes are in FORMAT.md "SRS".
- `ceremony/main.go` downloads only byte ranges (about 13 MB for `n ≤ 2^16`), and verifies:
  - the pinned `[x]_2`: the manifest's `crs.t2`, which is also barretenberg's hardcoded G2 point;
  - the first-power chain over all 176 contributions and the seal;
  - the pairing consistency of every G1 power it uses, as one random linear combination.
- It writes a gnark-crypto `kzg.SRS` with 65,539 points (sha256 `ee63bf8e…edbb85`). `main.go -srs FILE` builds the
  keys from it.
- **Circuit-size cap**: `n ≤ 2^16` with the committed settings, `n ≤ 2^22` with `-log 22` (one transcript file is
  read), and `n ≤ 2^26` for the whole ceremony.
- The verifier's SRS constants (`[1]_1`, `[1]_2`, `[x]_2`, and the `[x]_2` Miller-chain slopes the scripts bake)
  are checked against the ceremony by `../verifier/srs-check.mjs`.
- The old test SRS (public toxic value) is still available as `go run . -unsafe-test-srs`.

## Vectors

| | mul2 | merkle16 |
|---|---:|---:|
| VK bytes | 944 | 944 |
| proof bytes | 768 | 768 |
| public input bytes | 64 | 96 |
| valid proofs | 5 | 5 |
| tampered | 76 | 78 |
| tampered also checked by gnark Verify | 37 | 38 |

- Files: `vectors/mul2.json` and `vectors/merkle16.json`.
- The tamper classes cover every proof point (another valid point, its negation, the identity, off curve,
  `x+p`, `y+p`), every scalar (`+1`, `+r`), every public input (`+1`, `+r`, swapped), mix-and-match proofs, and
  wrong lengths. FORMAT.md lists them.
- How `verify.mjs` rejected them, for both circuits together:
  - 57 by the pairing check
  - 18 identity points
  - 18 off-curve points
  - 36 non-canonical coordinates
  - 17 values ≥ r
  - 8 by size

## Build and regenerate

```
./gen-vectors.sh            # ceremony download+checks, go run . -srs ... (both runs), node verify.mjs (SRS_CACHE=dir)
GOMAXPROCS=4 nice go run . -srs srs-cache/ignition_bn254_65539.srs -circuits range64,merkle16rc -out vectors   # the BSB22 vectors only
npm install                 # once: @noble/curves 2.2.0 for verify.mjs
node verify.mjs             # check all vectors: OK: 351 cases, 0 unexpected (164 v1 + 187 BSB22)
node verify.mjs --counts    # operation counts of one verification per circuit
node verify.mjs --trace mul2 0   # challenges and intermediate values
```

- The VKs are byte-identical across runs.
- The proofs differ, because gnark blinds with `crypto/rand`.
- The whole run takes a few seconds with 4 threads.

## Limitations and open points

- **u is not pinned by the vectors.** The multi-point batching challenge follows gnark's Solidity template.
  gnark's Go verifier uses a random u, and the verdict on a valid proof does not depend on u. The derivation
  was taken from the template text and not executed against an EVM. A CashVM verifier is free to choose any
  binding derivation of u. γ, β, α, ζ and v, by contrast, are pinned: a wrong value rejects the valid vectors.
- **Deviations from gnark's Go verifier** (PROTOCOL.md): proof points equal to the identity are rejected, and
  encodings are strict.
- **Ceremony SRS, partly verified.** Only the parts the verifier relies on were checked: the final `[x]_2` chain and
  the powers used. The full 100.8M-point transcripts, their checksums and the participants' signatures were not.
- **Soundness rests on PLONK and KZG** under the q-SDH/AGM assumptions, with gnark's transcript. This track
  only claims that `verify.mjs` reproduces gnark's verifier and rejects the tampered set.
- **snarkjs** PLONK uses Keccak. Emulating Keccak on CashVM was not measured; see the end of PROTOCOL.md.
