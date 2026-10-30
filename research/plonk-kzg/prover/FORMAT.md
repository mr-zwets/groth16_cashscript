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

The vectors use a **test SRS that is not safe**:
- It is `unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed(seed))`.
- `τ = SHA256(seed) mod r`, with seed `"verifier.cash plonk-kzg TEST SRS v1 (unsafe, toxic value is public)"`.
- Since τ is public, anyone can forge proofs under these VKs. They are test vectors only.
- A one-off check with @noble/curves confirmed `[τ]_2 = τ·[1]_2` for this τ.
- Both circuits are set up from the same τ. `main.go` asserts that `[1]_1`, `[1]_2` and `[τ]_2` are identical
  across the two VKs. That shared triple is the "universal" part of the setup.

### Using a public ceremony SRS instead

A deployment would replace the test SRS with a public ceremony, for example:
- Aztec Ignition: 100.8M G1 powers.
- The perpetual powers of tau: the PSE/Hermez `ptau` files, up to 2^28.

The procedure:
1. Take the ceremony's G1 powers `[τ^i]_1` for `i < n+3`. gnark's `plonk.Setup` requires `len(srs.Pk.G1) ≥ n+3`,
   because of the blinding of the opened polynomials.
2. Take `[1]_2` and `[τ]_2` from the ceremony.
3. Build gnark's `kzg.SRS` from those points.
4. Compute the Lagrange-form SRS of size `n`, for example with gnark-crypto's `kzg.ToLagrangeG1`.
5. Call `plonk.Setup(ccs, srs, srsLagrange)`. This step is deterministic and needs no trust.

The **verifier needs only three SRS points**: `[1]_1` (the G1 generator), `[1]_2` (the G2 generator) and
`[τ]_2`. The large G1 table is used only by the prover and by setup. This was not exercised here: no ceremony
file was downloaded or converted.

Circuit-size limit:
- `n` is a power of two with `n + 3 ≤ #G1 powers`.
- BN254's scalar field has 2-adicity 28, so the radix-2 domain caps `n ≤ 2^28` regardless of the SRS.
- With Ignition's 100.8M powers the limit is `n ≤ 2^26` (67,108,864 rows), because 2^27 + 3 is more than 100.8M.
- A 2^28 `ptau` file holds 2^29 − 1 G1 powers in the snarkjs layout (not checked here), so the limit there is
  the field cap of 2^28.
- `merkle16` uses `n = 2^14` and `mul2` uses `n = 2^3`.

## JSON vector files

`vectors/<circuit>.json`:

```
format, gnark, gnarkCrypto
circuit  { name, statement, nbConstraints, nbPublic, domainSize, bsb22Commitments (0 in v1) }
srs      { unsafe: true, toxicSeed, note, g1Points }
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

Both use the same test SRS as v1 (`verify.mjs` asserts one `[1]_1, [1]_2, [τ]_2` across all vector files).

**Tamper classes** added for commitments (on top of the v1 classes, which now also cover `Bsb22_j` as a 10th
point and `qcp_j(ζ)` as a 7th scalar):

| class | variants | gnark checked |
|---|---|---|
| `commitment` | `Bsb22_0` taken from `valid[1]`; `Bsb22_0` and `qcp_0(ζ)` both taken from `valid[1]`; `2·Bsb22_0`; `Bsb22_0 − G`; `qcp_0(ζ) = 0` (5) | yes |

That is 86 tampered proofs for `range64` (k = 1) and 91 for `merkle16rc` (k = 3).
