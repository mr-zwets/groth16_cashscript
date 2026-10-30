# plonk-kzg-bn254/v1: byte format of the PLONK vectors

Format of the verifying key, proofs and public inputs in `vectors/*.json`. The proofs come from gnark
v0.16.4 PLONK over BN254 with KZG, with gnark-crypto v0.21.1-0.20260913224755-1409fe592052.

Conventions:
- Every field element and every coordinate is 32 bytes, big-endian.
- `p` is the BN254 base field modulus and `r` the scalar field modulus.
- A G1 point is `x ‖ y` (64 bytes), exactly gnark-crypto's `G1Affine.RawBytes()`. For a BN254 point the
  two flag bits of `RawBytes` are zero, so the bytes are the plain coordinates.
- The point at infinity is 64 zero bytes. Proofs may not contain it; VK commitments may (see below).
- These are the same bytes gnark's Fiat-Shamir transcript hashes. A strict decoder therefore lets the verifier
  hash the input bytes as they are, with no re-encoding.

## Proof (768 bytes)

This is gnark's `Proof.MarshalSolidity()` layout with no BSB22 commitments, so it is the input of gnark's own
exported Solidity verifier.

| offset | size | field | gnark struct |
|---:|---:|---|---|
| 0 | 64 | `[L]` wire commitment | `LRO[0]` |
| 64 | 64 | `[R]` | `LRO[1]` |
| 128 | 64 | `[O]` | `LRO[2]` |
| 192 | 64 | `[H0]` quotient, low part | `H[0]` |
| 256 | 64 | `[H1]` | `H[1]` |
| 320 | 64 | `[H2]` | `H[2]` |
| 384 | 32 | `l(ζ)` | `BatchedProof.ClaimedValues[1]` |
| 416 | 32 | `r(ζ)` | `ClaimedValues[2]` |
| 448 | 32 | `o(ζ)` | `ClaimedValues[3]` |
| 480 | 32 | `s1(ζ)` (Sσ1) | `ClaimedValues[4]` |
| 512 | 32 | `s2(ζ)` (Sσ2) | `ClaimedValues[5]` |
| 544 | 64 | `[Z]` permutation grand product | `Z` |
| 608 | 32 | `z(ζω)` | `ZShiftedOpening.ClaimedValue` |
| 640 | 64 | `[Wζ]` batched opening proof at ζ | `BatchedProof.H` |
| 704 | 64 | `[Wζω]` opening proof of Z at ζω | `ZShiftedOpening.H` |

So a proof holds 9 G1 points and 6 scalars: 9·64 + 6·32 = 768 bytes.

`ClaimedValues[0]` is not in the proof. It is the opening of the linearised polynomial at ζ, and the verifier
recomputes it as `r0`. The JSON keeps it as `linOpening` for cross-checking only, and `verify.mjs` checks that
`r0` equals it on every valid proof.

The decoder must check all of the following, or reject:
1. The length is exactly 768.
2. Every scalar is `< r`.
3. Every coordinate is `< p`.
4. No point is `(0,0)`.
5. Every point satisfies `y² = x³ + 3`. BN254 G1 has cofactor 1, so this is also the subgroup check.

## Public inputs

Public inputs are `nbPublic` words of 32 bytes each, big-endian, each `< r`. They are in the circuit's
declaration order, which is gnark's public witness order:

| circuit | inputs |
|---|---|
| `mul2` | `n0, n1` |
| `merkle16` | `root, nullifierHash, context` |

The count must equal the VK's `nbPublic`.

`nbPublic` ≥ 1 is required by the CashVM verifier (`verifier/plonk.mjs` `parseVK` rejects 0): it reads α²·L_1(ζ) from the
first entry of the batched Lagrange denominators, which is ζ − ω⁰ only when public input 0 exists. With no public input
and a BSB22 commitment that entry would be the commitment's ζ − ω^cci (gnark computes L_1 separately). `verify.mjs`
has the same requirement. All vectors have k ≥ 1 (`range64` k = 1).

## Verifying key (944 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `n`, the domain size (u64 BE, a power of 2) |
| 8 | 8 | `nbPublic` (u64 BE) |
| 16 | 32 | `ω`, the generator of the order-n subgroup (`vk.Generator`) |
| 48 | 32 | `n⁻¹ mod r` (`vk.SizeInv`) |
| 80 | 32 | `k`, the coset shift (`vk.CosetShift`; the wiring identities are `X`, `kX`, `k²X`) |
| 112 | 64·8 | `[S1] [S2] [S3] [Ql] [Qr] [Qm] [Qo] [Qk]`, in this order |
| 624 | 64 | `[1]_1`, the SRS G1 generator (`vk.Kzg.G1`) |
| 688 | 128 | `[1]_2` (`vk.Kzg.G2[0]`) |
| 816 | 128 | `[x]_2 = [τ]_2` (`vk.Kzg.G2[1]`) |

- A G2 point is `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0` (gnark-crypto `G2Affine.RawBytes()`, imaginary part first, as in
  EIP-197).
- VK commitments may be the identity. `mul2` has no constant term, so its `Qk` is 64 zero bytes. The
  transcript hashes those 64 zero bytes, and the linearisation adds the identity, which an on-chain build drops
  at build time.
- The VK is a constant baked into the verifier: the CashVM verifier never parses it at run time.
- The JSON also gives every VK field in decimal (`vk.fields`).

Only the last three entries (`[1]_1`, `[1]_2`, `[τ]_2`) come from the SRS. They are the same for every
circuit that uses the same SRS. The rest is derived from the circuit and the SRS by `plonk.Setup`, which uses
no secret, so anyone can recompute a circuit's VK.

## SRS

The vectors use the **Aztec Ignition** powers-of-tau ceremony (`MAIN IGNITION`), loaded and verified by
`ceremony/main.go`. Track 6's first vectors used gnark's unsafe test SRS (`τ = SHA256(seed) mod r`, seed
`"verifier.cash plonk-kzg TEST SRS v1 (unsafe, toxic value is public)"`); `go run . -unsafe-test-srs` still builds
those, for comparison only.

### Why Ignition

- **Participants.** 176 contributions from 2019-10-25 to 2019-12-17 (`manifest.json` lists them; 21 more timed out
  and were dropped), followed by Aztec's sealing step (`sealed/`). The setup is safe if any one of them destroyed
  their secret.
- **Verification.** Aztec published every participant's transcript, a transcript spec and a verifier
  (`AztecProtocol/ignition-verification`); `github.com/consensys/gnark-ignition-verifier` (v0.1.0) re-implements
  the check for gnark-crypto. The final `[x]_2` is hardcoded in Aztec's barretenberg Solidity verifiers and in
  several independent ports (zkVerify, garaga), so it is a widely pinned value.
- **Size.** 100.8M G1 powers (+ `[1]_1`), one `[x]_2`. With gnark's `n + 3` rule that caps a circuit at
  `n ≤ 2^26` (67,108,864 rows); BN254's 2-adicity alone would allow 2^28.
- **Format.** Raw uncompressed points with a 28-byte header, so a byte range of one file is enough. The
  alternative, the perpetual powers of tau `ptau` files (snarkjs, up to 2^28, 54+ contributions and a beacon),
  needs a snarkjs-format parser and whole-file downloads (about 18 MB for the 2^14 file; not tried here).
  Ignition's range access keeps the download at about 13 MB for `n ≤ 2^16`.

### What `ceremony/main.go` downloads (HTTP ranges, cached, not committed)

Base URL `https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/`. With `-log L` the SRS holds `N = 2^L + 3`
points `[x^0..x^{N-1}]_1`; the committed vectors use `L = 16` (`N = 65,539`). For `L = 16`:

| file | bytes | sha256 |
|---|---|---|
| `manifest.json` | all (43,011) | `d231a1defd9804721ded32c75dd6f956efbf61c254b3ebcec4bb6596ba9941b8` |
| `sealed/transcript00.dat` | 28–4,194,459 (G1 powers x^1..x^65538) | `abc459a671ae1f2772b95ff1cb1ba19cae3f1dc59a937ea1163ee3e78c046401` |
| `monomial/transcript00.dat` | 0–4,194,523 (cross-check) | `5f0ebea024e05ff6481a9d4e734138c76b231276d84d0b7c5001fc067c4d08b5` |
| `flat/g1.dat` | 0–4,194,495 (cross-check) | `ed09422444eb9b3aad10863ae1bd747ba7f8320ce0a3878543a20f3a74b382cb` |
| 176 × `NNN_0x…/transcript00.dat` + `sealed/transcript00.dat` | 0–91 and 322,560,028–322,560,283 each | sha256 of all, in order: `b64d6570be125e95d8237d35036d677379d43948697be4bdb8c0d1fbc2972982` |

The derived file `ignition_bn254_65539.srs` (gnark-crypto `kzg.SRS.WriteTo`, 2,131,204 B) has sha256
`ee63bf8e2f8d4c9d55eb2ceb716da116e99b170cdb51ce39b279b1b555edbb85`; it is byte-identical across runs.
`srs/ignition_bn254_65539.json` is the tool's record of all of this.

### What is verified

1. The manifest's sha256, and its `crs.t2` equals the pinned `[x]_2`, which is also the "G2 point from VK" in
   barretenberg `sol/src/honk/utils.sol` (aztec-packages commit `f2f4ecab`).
2. Every transcript header (transcript 0 of 20, 100.8M points, 5.04M per file, 2 G2 points, start 0); every point
   canonical, on the curve and in the prime-order subgroup.
3. **The chain of the first power over all 176 contributions and the seal**:
   `e([x_k]_1, [1]_2) = e([1]_1, [x_k]_2)` and `e([x_k]_1, [1]_2) = e([x_{k-1}]_1, [z_k]_2)` with `x_0 = 1`, where
   `[z_k]_2` is contribution k's published update. So the final `x` is the product of every participant's `z_k`
   and the seal's.
4. The sealed `[x]_2` equals the pinned value.
5. **The powers used**: with `P = ([1]_1, sealed x^1..x^{N-1})` and random `r_i` from `crypto/rand`,
   `e(Σ r_i P[i], [x]_2) = e(Σ r_i P[i+1], [1]_2)` over `i < N−1`. Since `P[0] = [1]_1`, this gives `P[i] = [x^i]_1`
   for every i, except with probability at most `1/r` over the `r_i`. A control (`[1]_2` in place of `[x]_2`) must fail, and does.
6. The same N points are in `monomial/transcript00.dat` and `flat/g1.dat` (the files barretenberg loads).

Not verified, because it would need the full ~1.1 TB of transcripts: the consistency of all 100.8M powers of every
participant, the BLAKE2b checksums of the full files, and the participants' signatures. Points 3 and 5 cover what
this verifier relies on: the final `[x]_2` comes from the published contribution chain, and the powers the prover
uses are powers of that `x`.

### Setup from the SRS

`main.go -srs FILE` (see `srs.go`) re-checks `[1]_1`, `[1]_2`, the pinned `[x]_2` and `G1[0] = [1]_1`, and the file's
sha256 against the value pinned for its point count (65,539 points: `ee63bf8e…bb85`, the record in `srs/`; it panics on a
mismatch; a file of another size is not pinned). Then per circuit it re-runs the random-linear-combination power check of
`ceremony/main.go` step 5 on the `n + 3` points it uses (`checkPowers`: `e(Σ r_i P_i, [x]_2) = e(Σ r_i P_{i+1}, [1]_2)`,
with a control that must fail), so the G1 powers are checked on load, not only trusted from the file. It then
takes the first `n + 3` points as gnark's canonical SRS, computes the Lagrange SRS of size `n` with
gnark-crypto `kzg.ToLagrangeG1`, and calls `plonk.Setup`. Setup uses no secret, so the VK is reproducible: rerun
`go run . -srs FILE -out DIR` and compare `vk.hex` (only the proofs differ, gnark blinds with `crypto/rand`).

The **verifier needs only three SRS points**: `[1]_1`, `[1]_2` and `[x]_2`. The other VK points
(`S1..S3, Ql..Qk`) are commitments to the circuit's selector and permutation polynomials, so they changed with
the SRS too; `n`, `ω`, `n⁻¹` and `k` did not.

Circuit-size limit:
- `n` is a power of two with `n + 3 ≤ N` (the SRS file's points). The committed file has `N = 2^16 + 3`, so
  `n ≤ 2^16`; `ceremony/main.go -log L` builds a larger one (L ≤ 22 reads only the first transcript file, about
  `3 · 2^L · 64` bytes; beyond that the tool would need to read further transcript files, not implemented).
- The ceremony caps `n ≤ 2^26`; the field caps `n ≤ 2^28`.
- `merkle16` uses `n = 2^14` (16,387 points) and `mul2` uses `n = 2^3` (11 points).

## JSON vector files

`vectors/<circuit>.json`:

```
format, gnark, gnarkCrypto
circuit  { name, statement, nbConstraints, nbPublic, domainSize, bsb22Commitments (0 in v1) }
srs      { unsafe: false, ceremony, tau2Raw, srsFileSha, srsPoints, g1Points, note }   (old: { unsafe: true, toxicSeed, note, g1Points })
vk       { hex (944 B, v2-bsb22: 944 + 8 + 72 m), bytes, fields{...decimal...} }
valid    [ { publicInputs[hex32], proof (hex, 768 B, v2-bsb22: 768 + 96 m), linOpening (hex32), bsb22Hash[hex32] (v2-bsb22), proveMillis } ]
tampered [ { name, class, base, publicInputs, proof, expect: "reject", gnark: "reject" | "n/a" } ]
notes    { ... }
```

`tampered[].gnark` is the verdict of gnark's own `plonk.Verify` on the same tampered proof struct. It is `n/a`
for byte-level encodings that gnark's structs cannot hold (non-canonical values, off-curve points, wrong
lengths).

The tamper classes, all built from `valid[0]`:

| class | variants (per circuit) | gnark checked |
|---|---|---|
| `point-value` | each of the 9 points replaced by `P+G` and by `−P` (18) | yes |
| `point-infinity` | each point replaced by the identity (9) | yes |
| `scalar-value` | each of the 6 scalars `+1` (6) | yes |
| `public-input` | each public input `+1`, plus swapping inputs 0 and 1 (k+1) | yes |
| `mix` | `valid[1]`'s proof with `valid[0]`'s public inputs (1) | yes |
| `point-encoding` | each point with `y+1` (off curve), `x+p`, `y+p` (27) | n/a |
| `scalar-encoding` | each scalar `+r` (6) | n/a |
| `public-input-encoding` | each public input `+r` (k) | n/a |
| `size` | proof 767 and 769 bytes, one public input too few, one too many (4) | n/a |

That is 76 tampered proofs for `mul2` (k=2) and 78 for `merkle16` (k=3).

The prover blinds with `crypto/rand`, so regenerating gives different valid proofs. The witnesses are seeded,
and the VKs are byte-identical across runs.

## BSB22 commitments (format `plonk-kzg-bn254/v2-bsb22`)

Circuits that call gnark's `api.Commit`, directly or through a gadget (`std/rangecheck`, `std/lookup/logderivlookup`,
the log-derivative argument in general), get BSB22 commitments: m ≥ 1 extra G1 points in the proof and m extra
selector commitments in the VK. Their vectors use format `plonk-kzg-bn254/v2-bsb22`. Keys and proofs without
commitments keep the v1 layout byte for byte, so `mul2.json` and `merkle16.json` are unchanged.

**Verifying key** (944 + 8 + 72 m bytes): the 944 v1 bytes, then

| offset | size | field |
|---:|---:|---|
| 944 | 8 | `m`, the number of commitments (u64 BE, ≥ 1) |
| 952 + 72 j | 8 | `CommitmentConstraintIndexes[j]` (u64 BE): the commitment's row, counted after the public-input rows |
| 960 + 72 j | 64 | `[Qcp_j]`, the commitment selector (`vk.Qcp[j]`, raw x ‖ y) |

**Proof** (768 + 96 m bytes): gnark's `MarshalSolidity` appends, after the 768 v1 bytes,

| offset | size | field | gnark struct |
|---:|---:|---|---|
| 768 + 32 j | 32 | `qcp_j(ζ)`, the opening of the selector Qcp_j at ζ | `BatchedProof.ClaimedValues[6 + j]` |
| 768 + 32 m + 64 j | 64 | `[Bsb22_j]`, the commitment to the committed wires | `Bsb22Commitments[j]` |

The decoder adds: every `qcp_j(ζ)` is `< r`; every `Bsb22_j` is canonical, not `(0,0)`, and on the curve. gnark's
own `Verify` accepts the identity for `Bsb22_j` (its subgroup check does); this verifier rejects it. An honest
`Bsb22_j` is never the identity in practice: gnark's prover puts a random value at the commitment row (whose
`qcp` is 0) before committing, so the point is uniformly distributed.

**JSON**: `circuit.bsb22Commitments` is m; `vk.fields` adds `Qcp` (decimal points) and
`commitmentConstraintIndexes`; every valid proof adds `bsb22Hash`, gnark's hash-to-field of each commitment
computed in Go with gnark-crypto's `hash_to_field.New([]byte("BSB22-Plonk"))`, so the JS hash can be cross-checked.

**Circuits** (one commitment each, from `std/rangecheck`):

| name | public inputs | statement | constraints | n | commitment row (cci) |
|---|---|---|---:|---:|---:|
| `range64` | `n0` | knows a with `a·a = n0` and `0 ≤ a < 2^64` | 129 | 2^8 | 49 |
| `merkle16rc` | `root, nullifierHash, context` | merkle16 with leaf `MiMC(nullifier, trapdoor, amount)` and `0 ≤ amount < 2^64` | 15,680 | 2^14 | 15,600 |

Both use the same Aztec Ignition SRS as v1 (`verify.mjs` asserts one `[1]_1, [1]_2, [τ]_2` across all vector files).

**Tamper classes** added for commitments (on top of the v1 classes, which now also cover `Bsb22_j` as a 10th
point and `qcp_j(ζ)` as a 7th scalar):

| class | variants | gnark checked |
|---|---|---|
| `commitment` | `Bsb22_0` taken from `valid[1]`; `Bsb22_0` and `qcp_0(ζ)` both taken from `valid[1]`; `2·Bsb22_0`; `Bsb22_0 − G`; `qcp_0(ζ) = 0` (5) | yes |

That is 86 tampered proofs for `range64` (k = 1) and 91 for `merkle16rc` (k = 3).
