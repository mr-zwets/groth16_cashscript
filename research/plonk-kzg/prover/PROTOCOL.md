# gnark v0.16.4 PLONK verifier, step by step (BN254, KZG, SHA-256, no BSB22)

This is the verifier that `verify.mjs` implements. The byte format is in [FORMAT.md](FORMAT.md). The operation
counts below were printed by `node verify.mjs --counts`, which counts operations during one real verification.

Sources replicated:
- gnark v0.16.4 `backend/plonk/bn254/verify.go` (Verify, bindPublicData, deriveRandomness).
- The Solidity template in `backend/plonk/bn254/solidity.go` (the proof layout and the derivation of u).
- gnark-crypto `fiat-shamir/transcript.go`.
- gnark-crypto `ecc/bn254/kzg/kzg.go` (FoldProof, deriveGamma, BatchVerifyMultiPoints).

Notation: k = nbPublic, n = domain size. The fixed VK values are ω, n⁻¹, the coset shift k_c, the
commitments [S1] [S2] [S3] [Ql] [Qr] [Qm] [Qo] [Qk], and the SRS points [1]_1, [1]_2, [τ]_2. All arithmetic
is mod r unless it is on curve points.

## Steps

**0. Decode** (FORMAT.md):
- Check the lengths (768-byte proof, k public inputs).
- Check that the 6 scalars and the k public inputs are `< r`.
- Check the 9 points: canonical coordinates, not (0,0), on the curve.
- Cost: 9 on-curve checks. There are no G2 inputs, so no G2 subgroup check.

**1. Fiat-Shamir** (gnark `fiatshamir.Transcript`, SHA-256). Each challenge is
`SHA256(name ‖ previous challenge digest ‖ bindings)`. The value is the 32-byte digest read big-endian and
reduced mod r. The next challenge hashes the raw digest, not the reduced value.

| challenge | SHA-256 input | bytes |
|---|---|---|
| γ | `"gamma" ‖ S1 S2 S3 Ql Qr Qm Qo Qk ‖ pub_0..pub_{k−1} ‖ L R O` | 5 + 512 + 32k + 192 = 709 + 32k |
| β | `"beta" ‖ γ_digest` | 36 |
| α | `"alpha" ‖ β_digest ‖ Z` | 101 |
| ζ | `"zeta" ‖ α_digest ‖ H0 H1 H2` | 228 |

Each point is its 64 raw bytes. The VK prefix of γ (517 bytes) is constant, but CashVM has no SHA-256
midstate, so it is hashed every time.

**2. Vanishing polynomial and public inputs:**
- Compute `ζⁿ` (log2 n squarings) and `Zh = ζⁿ − 1`.
- Form the k denominators `ζ − ωⁱ` and invert them with **one** batched Fr inversion (Montgomery's trick). On
  chain this can be a supplied inverse checked by one multiplication.
- `PI = Σᵢ pubᵢ · ωⁱ · n⁻¹ · Zh / (ζ − ωⁱ)`.
- `L1 = n⁻¹ · Zh / (ζ − 1)`. This is the i = 0 term, so it shares the inversion.
- `α²L1 = α² · L1`.
- Rejection rule, which gnark does not have: reject if `ζ` is one of the ωⁱ. The probability is negligible.

**3. Recompute the linearised opening:**
- `t1 = l + β·s1 + γ`, `t2 = r + β·s2 + γ`.
- `r0 = −(PI − α²L1 + α·t1·t2·(o + γ)·z(ζω))`.
- `r0` equals gnark's `ClaimedValues[0]`. gnark's Go verifier checks the equality; the Solidity verifier just
  uses `r0`.

**4. Linearised commitment** `[Lin]`, with `ζⁿ⁺² = ζⁿ·ζ²`:

```
s1c = α·β·t1·t2·z(ζω)
s2c = −α·(l + βζ + γ)(r + β·k_c·ζ + γ)(o + β·k_c²·ζ + γ) + α²L1
[Lin] = l[Ql] + r[Qr] + (l·r)[Qm] + o[Qo] + [Qk] + s1c[S3] + s2c[Z]
        − Zh·[H0] − Zh·ζⁿ⁺²·[H1] − Zh·ζ²⁽ⁿ⁺²⁾·[H2]
```

This takes 9 scalar multiplications: 5 with fixed bases (Ql, Qr, Qm, Qo, S3) and 4 with proof bases (Z, H0,
H1, H2). The Solidity verifier folds the H terms by Horner instead, which is 3 multiplications either way.
`[Lin]` must be **affine**, because its coordinates are hashed in step 5. That is one Fp normalisation.

**5. KZG folding challenge v** (gnark-crypto `kzg.deriveGamma`, a fresh one-challenge transcript named "gamma"):

```
v = SHA256("gamma" ‖ ζ ‖ Lin L R O S1 S2 ‖ r0 l r o s1 s2 ‖ z(ζω)) mod r          (645 bytes)
[D] = [Lin] + v[L] + v²[R] + v³[O] + v⁴[S1] + v⁵[S2]
e   = r0 + v·l + v²·r + v³·o + v⁴·s1 + v⁵·s2
```

This takes 5 scalar multiplications: 3 with proof bases (L, R, O) and 2 with fixed bases (S1, S2). `[D]` must be
affine, because it is hashed in step 6. That is one more Fp normalisation.

**6. Multi-point batching challenge u:**
- gnark's Go `kzg.BatchVerifyMultiPoints` draws `u` from `crypto/rand`.
- gnark's Solidity verifier, which is the on-chain form, derives it as below. `verify.mjs` does the same:

```
u = SHA256(D ‖ Wζ ‖ Z ‖ Wζω ‖ ζ ‖ v) mod r          (320 bytes, no domain prefix)
```

The prover never sees `u`. A CashVM verifier may therefore derive it any other way that binds these inputs
without losing compatibility with gnark proofs. The verdict on valid proofs does not depend on `u`, so the
vectors do not pin this derivation. It follows the template text and was not executed against an EVM.

By contrast, `γ, β, α, ζ, v` must be **bit-exact**. The prover's commitments and opening proofs depend on
them, so a wrong value rejects the valid vectors. All 10 valid proofs accept in `verify.mjs`.

**7. Final check**, a 2-pairing product with **both G2 points fixed**:

```
[F] = [D] + u[Z] − (e + u·z(ζω))[1]_1 + ζ[Wζ] + (u·ζ·ω)[Wζω]
[Q] = [Wζ] + u[Wζω]
accept  iff  e([F], [1]_2) · e(−[Q], [τ]_2) == 1
```

This takes 5 scalar multiplications: 4 for F (u·Z, a multiple of [1]_1, ζ·Wζ, uζω·Wζω) and 1 for Q (u·Wζω).
The only fixed base is [1]_1. Then 2 Miller loops and 1 final exponentiation.

## Operation counts (one verification)

| | mul2 (k=2, n=2^3) | merkle16 (k=3, n=2^14) | notes |
|---|---:|---:|---|
| G1 scalar multiplications | **19** | **19** | independent of n and k |
| – with a fixed (VK/SRS) base | 8 | 8 | Ql Qr Qm Qo S3 (Lin); S1 S2 (D); [1]_1 (F) |
| – with a proof base | 11 | 11 | Z H0 H1 H2 (Lin); L R O (D); Z Wζ Wζω (F); Wζω (Q) |
| G1 additions (incl. +[Qk]) | 19 | 19 | |
| G1 on-curve checks | 9 | 9 | no subgroup check needed (cofactor 1) |
| affine normalisations (Fp inversions) | 4 | 4 | Lin and D (hashed), F and Q (pairing inputs) |
| Fr inversions | **1** | **1** | batched over the k denominators; witness-checkable |
| Fr multiplications (incl. ζⁿ) | 61 | 80 | ζⁿ: log2 n squarings |
| SHA-256 calls | **6** | **6** | γ β α ζ v u |
| SHA-256 message bytes | 773, 36, 101, 228, 645, 320 | 805, 36, 101, 228, 645, 320 | γ grows 32 B per public input |
| SHA-256 compression blocks | 37 | 37 | γ 13, β 1, α 2, ζ 4, v 11, u 6 |
| pairings | **2** (one product, 1 final exp.) | 2 | G2 points [1]_2 and [τ]_2, both fixed |
| public-input cost | k Lagrange terms (Fr only) | | no G1 MSM over public inputs, unlike Groth16 |

Both circuits give the same curve and hash counts. Only `log2 n`, k and the γ length change. The verifier cost
is essentially independent of circuit size.

## What this means for a CashVM verifier

These notes are for the Verifier phase and are not measured here.

- **No G2 arithmetic at all.** Both pairing G2 arguments are SRS constants. Every Miller-loop line can
  therefore be baked, as the fixed δ chain is in `chunked/bn254/sound-si-gls` (88 baked slopes). In
  sound-si-gls the variable-B walk (doublings 9.31M plus additions 4.26M of the 23.3M op-cost) is the largest
  item, and PLONK has no counterpart to it. With both G2 points fixed, the final check can also reuse the
  SI-GLS residue and torus techniques.
- **The price is 19 G1 scalar multiplications** of full 254-bit scalars, against 2 for Groth16 with
  2 public inputs. All 19 can use the BN254 GLV endomorphism, and 8 have fixed bases, so tables can be
  precomputed for them.
- **Four affine normalisations**: Lin and D are needed in affine form because gnark hashes their coordinates.
  On chain each can be a supplied inverse checked by one Fp multiplication.
- **Transcript cost is negligible.** 37 SHA-256 blocks is 37 × 192 = 7,104 standard op-cost
  (37 × 64 consensus), plus 6 × 100 base.
- **Proof size**: 768 bytes, against 256 for an uncompressed Groth16 proof (A, B, C = 64 + 128 + 64). Public
  inputs are 32 bytes each in both systems.
- **Per-circuit constants**: 8 G1 commitments (512 bytes) plus n, ω, n⁻¹, k_c. Shared across circuits:
  [1]_1, [1]_2, [τ]_2.

## Where this verifier differs from gnark's Go verifier

All of these are deliberate and safe for a verifier:
1. Proof points equal to the identity are rejected. gnark's Go verifier accepts them if the equations hold.
   None of the 10 honest proofs contains one.
2. Strict canonical byte decoding. gnark's Go verifier works on structs, so encoding questions don't arise
   there. The Solidity verifier checks `< r` on scalars and public inputs.
3. `u` follows the Solidity template rather than gnark's random sampling.
4. ζ in the domain is rejected.

## Alternative: snarkjs PLONK (not done here)

snarkjs PLONK uses a Keccak-256 transcript. CashVM has no Keccak opcode, so every challenge would need
Keccak-f[1600] emulated in Script:
- That means 24 rounds over 25 64-bit lanes, with rotations built from shifts and ORs.
- For about 2 KB of transcript at a 136-byte rate, that is about 17 permutations.
- This was not measured. A rough estimate, at the CashVM base cost of 100 per opcode, puts it two to three
  orders of magnitude above the 7,104 op-cost of the SHA-256 transcript. It would also add redeem bytes for the
  permutation code.

gnark's SHA-256 transcript avoids all of that, which is why this track uses gnark.
