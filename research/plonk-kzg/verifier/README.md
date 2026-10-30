# Track 6: a CashVM verifier for gnark PLONK/KZG proofs (BN254, SHA-256 transcript)

Date: 2026-10-29. Status: **research, built and measured; not a leaderboard entry.** Nothing in REGISTRY, results.json,
score-history.json or the website changed. Not independently reviewed.

Proofs come from gnark **v0.16.4** with gnark-crypto **v0.21.1-0.20260913224755-1409fe592052** (prover track,
`wip/plonk-kzg-prover`). The design is `zk-verifier-bench` `research/plonk-kzg/DESIGN.md` (`wip/plonk-kzg-design`). This
directory builds the **simpler variant**: plan B (witnessed linearised commitment), **no GT folding**. Everything runs on the
real libauth 3.1.0-next.8 VMs, in consensus and standard mode.

## Results

Two circuits: **mul2** (2 public inputs, n = 2^3) and **merkle16** (3 public inputs, depth-16 MiMC Merkle membership,
n = 2^14). The proof is always 768 B and the public inputs are 32 B each. The verifying key is baked into the script, as in the
Groth16 entries.

**Score** follows the bench convention: unlocking + 35 B P2SH32 locking per input + tx overhead (63 B, plus 43 B per further
input). Ranges are over the 5 valid proofs. Op-cost is libauth standard mode. **BCHN-adjusted** adds the body bytes of every
OP_DEFINE an input executes.

| circuit / regime | inputs (txs) | score (B) | op-cost (libauth std) | BCHN-adjusted | worst margin |
|---|--:|--:|--:|--:|--:|
| mul2 / bch-spec | 1 (1) | 66,290–66,549 | 58.04–58.34M | +1,405 | 4.35% |
| mul2 / 100 KB input (TXv5, base 41, padded) | 1 (1) | 69,757–69,919 | 55.40–55.70M | +1,405 | pad sized per proof |
| mul2 / today, standard (multi-input) | 10 (1) | 92,845–93,095 (tx 92.5–92.7 KB) | 70.65–71.00M | +21,686 per input | 0.14% per input (filler sized per proof) |
| merkle16 / bch-spec | 1 (1) | 68,494–68,655 | 60.42–60.72M | +1,405 | 3.3% |
| merkle16 / 100 KB input | 1 (1) | 72,188–72,438 | 57.60–57.85M | +1,405 | pad sized per proof |
| merkle16 / today, standard | 10 (1) | 95,637–95,985 (tx 95.6–96.0 KB) | 73.17–73.49M | +21,686 per input | 0.14% per input |

Consensus op-cost is about 0.1% below standard; both are in `results/summary.json`.

**Tests** (`results/test-*.json`, `results/chain-*.json`):

| | bch-spec | 100 KB | today |
|---|---|---|---|
| valid proofs accepted (consensus and standard) | 10/10 | 10/10 | 10/10 |
| tampered vectors of the prover track rejected | 154/154 | 154/154 | 154/154 |
| witness manipulations rejected | 56/56 | 56/56 | 42/42 |

- **Verdicts match the JS reference** (`plonk.mjs` + `si.mjs`) on every vector. They also match the prover track's
  `verify.mjs` and gnark: all valid proofs accept, all tampered ones reject.
- **Tampered vectors** that still decode are re-witnessed **adaptively**: consistent slopes, Λ', inverses, SI states and
  floor quotients. The script therefore runs to its last check. The others (non-canonical, off-curve, infinity, wrong sizes)
  reuse the valid witness with the tampered bytes.
- **Manipulations**, single input:
  - slope bit flip, slope + p alias;
  - swapped, dropped, extra, empty and 31-byte slope pieces;
  - Λ' changed;
  - Fr inverse + r alias, inverse × 2, Jacobian zi × 2;
  - residue root and state flips, state + p alias, WS truncated;
  - WQ flip, leading-zero word, extra word, empty WQ;
  - swapped pushes, extra push, tampered redeem;
  - adaptive (fully re-witnessed): Λ' = 2Λ, Λ + G and −Λ; proof 1 with proof 0's public inputs.
- **Manipulations**, chain:
  - hand-over word + 1, hand-over + p alias, SI hand-over flip;
  - TV, TF and DS bit flips; WS, WQ and G0 flips;
  - both code blobs;
  - swapped inputs, nonzero FILL;
  - an extra same-locking input, a foreign input, a dropped input;
  - adaptive Λ' and statement swaps.

### Comparison with Groth16 and with the design model

| regime | PLONK/KZG (this build) | Groth16 | ratio | design model (no GT fold) |
|---|--:|--:|--:|--:|
| bch-spec | 66.3–68.7 KB | 21.9 KB (sound-si-gls) | 3.0–3.1× | 61.9 KB |
| 100 KB input | 69.8–72.4 KB | 29.3 KB (si-gls TXv5 padded) | 2.4–2.5× | 67.4 KB |
| today | 92.8–96.0 KB, 10 inputs | 27.6 KB, 3 inputs (sound-native) | 3.4–3.5× | 71.3 KB, 8 inputs |

- **The single-input builds land about 4–7% above the model**, which is inside its stated ±10%.
- **The today regime is about 22–25 KB above the model.** That is the largest negative finding:
  - The MSM tables are 576–608 stack items, so they cannot be handed between inputs. They must be **published**: the
    variable-base entries (9.6 KB) are checked by chord/tangent equations in their host input, and the fixed-base entries
    (7.7 / 8.6 KB) are a hash-checked VK constant.
  - Every MSM input then reloads them, about 1.5M op of fixed overhead per MSM input.
  - So the verifier fits a standard 100 KB transaction, but only just: 95.6–96.0 KB for merkle16.
  - A circuit with a few more fixed bases or public inputs would need an 11th input and could exceed 100,000 B.

## What is built

Protocol (`plonk.mjs`, `PROTOCOL.md` of the prover track):

1. **Decode.** The 9 proof points and Λ' are checked canonical (< p) and on the curve; the curve check also rejects the
   all-zero encoding of infinity. The 6 scalars and the public inputs are checked < r.
2. **gnark transcript** γ, β, α, ζ (SHA-256, byte-exact), then Fr block 1:
   - ζⁿ;
   - one witnessed batch inverse, checked by `Π(ζ − ωⁱ)·inv ≡ 1`;
   - PI(ζ), and r0 = lin, which is recomputed and hashed;
   - s1c, s2c, Zh, ζⁿ⁺².
3. **v** from gnark's `kzg.FoldProof` transcript (it hashes the witnessed Λ'). Then **our** challenge
   `uRaw = SHA256("u" ‖ v_raw ‖ W_ζ ‖ W_ζω)`:
   - `u = u1 + λ_GLV·u2`, where u1, u2 are LE u64;
   - `t'` = LE u128.
4. **One MSM** gives `P* = rest + (1 + t')·Λ' − t'·Λ_MSM = P_left + (1 + t')(Λ' − Λ)`. It has 18 bases (19 for merkle16,
   which has Qk); mul2's Qk is the point at infinity and is dropped.
5. **P_right** = −(W_ζ + u1·W_ζω + u2·φ(W_ζω)), over 14 windows.
6. **Pairing check** e(P*, [1]_2)·e(P_right, [x]_2) = 1, using the SI method:
   - **both G2 arguments fixed**: two baked slope chains of 88 steps, interleaved, 2 × 5,632 B;
   - one residue root and 33 monic states;
   - an odd quotient of at most 60 words.
   - There is no G2 walk and no final exponentiation.

The MSM (`script.mjs`) has five parts:
- **Digits.** Signed base-32 windows (d ∈ [−16, 15]), with zero digits skipped. The digits are **extracted on-chain with
  `OP_RSHIFTNUM`** from `s' = s + Σ 16·32^i`, which gives `d_i = ((s' >> 5i) & 31) − 16`. There is no recoding loop and no
  digit witness, which saved 3.9M op.
- **Tables.** 16 affine multiples per base, built with witnessed slopes. The φ(W_ζω) table is derived by β·x.
- **Coordinates.** The first J windows run in Jacobian (no bytes, about 0.52M op per window more). One witnessed `zi`,
  checked by `Z·zi ≡ 1`, switches to affine. The remaining windows are affine with witnessed slopes: 32 B each, fixed by
  `λ(x2 − x1) ≡ y2 − y1` with `x2 ≠ x1`, or by `2yλ ≡ 3x²`. J = 13 on bch-spec and 8 at 100 KB.
- **Exceptional cases.** Exceptional Jacobian steps fall into an absorbing Z = 0, which the conversion rejects. Affine
  exceptions are rejected by `x2 ≠ x1`. The accumulator starts at a hash-to-curve offset point, and a constant correction is
  added at the end.
- **The slope stream** sits on the altstack above an empty sentinel. Reading past its end fails, and leftovers are rejected.

**The 100 KB regime** uses the same script with a pad slot (`DROP` of the top push; the chunked/txv5-pad pattern). The pad is
sized per proof to the minimum.

**Today's regime** (`multi.mjs`, `chain.mjs`) follows the SI-MX3 pattern of `chunked/bn254/bn-native-sound`:
- **Shared redeem.** One 102-byte redeem R is used by every input. It loads two code blobs by `OP_INPUTBYTECODE`: C0
  (7,329 B, input 0) and C1 (3,609 B, last input). It checks both SHA-256 hashes, then `OP_DEFINE`s and runs them. C0
  dispatches on `OP_INPUTINDEX`.
- **Graph pin.** `TXINPUTCOUNT == 10`, and every `UTXOBYTECODE` equals the own one.
- **Remote reads.** Data that another input reads sits in fixed-size pushes at the start of an unlocking, and the push
  header is checked.
- **Hand-overs** are byte-exact: canonical 32-byte LE words compared with the successor's HAND push. The successor decodes
  them, and checks each word < p, as its start state.
- **FILL** pushes are all-zero (checked) and sized per proof.

| input | role | content | op (mul2, proof 0) |
|---|---|---|--:|
| 0 | MJ: MSM windows 50–46 (Jacobian) | C0, fill | 7.18M |
| 1 | ST: statement, transcript, Fr, scalars, P_right; publishes G0 = uRaw ‖ s' ‖ P_right | G0, X, PI, proof, WS | 4.90M |
| 2 | MJ window 45, host and check of TV (variable-base tables) | TV 9.6 KB | 6.99M |
| 3 | MJ windows 44–40, host of TF (fixed-base tables, SHA-256-checked) | TF 7.7 / 8.6 KB, fill | 7.19M |
| 4–7 | MA: affine windows 39–30, 29–20, 19–10, 9–0 (the first converts with zi; the last adds the correction and gives P*) | slopes, fill | 7.23–7.56M |
| 8 | SI events 0–33 | WQ (fixed 60 words), chain-slope slice, fill | 7.55M |
| 9 | SI events 34–64, terminal, quotient, final identity | chain-slope slice, C1 | 7.59M |

## Per-phase op-cost (bch-spec, proof 0, standard; `node profile.mjs <circuit> 13`)

| phase | mul2 | merkle16 |
|---|--:|--:|
| decode + curve checks (incl. moving the slope stream) | 0.44M | 0.46M |
| gnark transcript (γ..ζ) | 0.03M | 0.03M |
| Fr / public inputs (block 1) | 0.14M | 0.21M |
| v, u, t', MSM scalars | 0.17M | 0.18M |
| MSM tables (270 / 285 slope-witnessed additions) | 6.09M | 6.42M |
| P_right MSM (14 windows, affine) | 2.16M | 2.18M |
| P* MSM (51 windows, 13 Jacobian) | 36.84M | 38.77M |
| SI setup (transcript, z powers, line environments) | 0.34M | 0.34M |
| Miller events (65 events, two fixed chains) + 33 state boundaries | 11.04M | 11.04M |
| terminal (Frobenius steps, residue factors), quotient, final identity | 0.95M | 0.96M |

**The MSM is 75% of the op-cost**: tables plus P* plus P_right is 45.1M of 58.2M. The fixed-G2 pairing, which needs no final
exponentiation, is 12.3M. The transcript and the Fr work are negligible.

## Circuit-specific vs generic (mul2 bch-spec redeem, 18,016 B)

| part | bytes | scope |
|---|--:|---|
| `[1]_2` chain slopes | 5,632 | universal (any SRS, any circuit) |
| `[x]_2` chain slopes | 5,632 | per SRS ceremony, shared by every circuit on it |
| VK raw points + "gamma" tag (hashed into γ, and the fixed bases) | 517 | per circuit |
| Fr constants (ωⁱ, n⁻¹, coset shift k, ω, log2 n squarings), base list | a few hundred | per circuit |
| code | about 5.9 KB | generic |

- **Witness** (mul2, J = 13): slopes about 38.6 KB, WS 6,528, WQ 1,920, X 128, proof 768, PI 64.
- **Today's regime** adds the TF blob (7,680 / 8,640 B), a per-circuit constant.
- **Proving key (SRS).** Since Track 7 (`wip/plonk-usable-srs`) the vectors use the Aztec Ignition ceremony (prover
  FORMAT.md "SRS"). So the baked `[x]_2` and its 88 chain slopes are Ignition's, shared by every circuit on it.
  `srs-check.mjs` checks every VK's `[1]_1`, `[1]_2` and `[x]_2` against the ceremony value. It also checks that the
  slope pieces derived from that value are in each single-input redeem, and that the SI slice hashes are in the chain
  scripts, with a control point that must be absent. Only the values of the per-circuit VK points changed; the sizes
  did not.

## Deviations from the design, and honest negatives

- **GT folding of the fixed bases was not built.** The design's recommended variant, worth about 6 KB, is open.
- **t' is a plain 128-bit value, not t1 + λt2.** Λ' gets the small scalar `1 + t'`, and the lin terms get `−t'`. The t'-fold
  argument: if Λ' ≠ Λ, then `P* = P_left + (1+t')(Λ'−Λ)` passes for at most one t' mod r, an error of 2^-128 per hash query.
  - The written argument for both is [SOUNDNESS.md](SOUNDNESS.md) (Lemmas 1–2; the lattice numbers are checked by
    `soundness/lattice.mjs`). It also covers the chain (Lemma 3) and gives the total bound. It is not independently
    reviewed.
  - Both substitutions are verifier-side only. Valid gnark proofs are accepted, and every tampered vector is rejected.
- **No GLV in the main MSM.** With 18–19 bases, GLV saves only the 127 doublings and doubles the tables, which would exceed
  the 1,000-item stack. GLV is used only for u.
- **WQ is fixed at 60 words in the chain**, with leading zeros allowed, so that offsets are fixed. Single input keeps SI-GLS's
  canonical length.
- **Margins are thin by construction.**
  - bch-spec: 3.3–4.4% at J = 13. A 6th proof could need J = 12; the build should pick J per circuit from a sweep.
  - 100 KB and today: the pad and FILL are sized per proof.
  - **Liveness is tested on 5 proofs per circuit only.** No large sweep was run, to keep heavy jobs low; the prover can mint
    more.
- **Known malleability**, with no soundness impact:
  - how the slope stream is cut into pieces;
  - FILL / pad length;
  - in the chain, an input's own unlocking size is not pinned beyond push sizes and DEPTH.
- **Not verified:**
  - formula correctness is tested, not proved;
  - the soundness argument ([SOUNDNESS.md](SOUNDNESS.md)) is a paper proof that assumes formula correctness. Its
    bound is ε_PLONK + Q·2^-128 + Q·2^-246 + Q²·2^-252 for Q hash queries. It found no unenforced step. Three remote reads skip
    the push-header check: ST's read of the Wζω slice of TV (`multi.mjs:372-373`), and the two hash-checked C0/C1 loads
    of the redeem (`:301`). The argument does not need header checks (SOUNDNESS.md §7);
  - no BCHN node run;
  - BCHN-adjusted figures are computed by adding DEFINE body bytes. In the chain this is +21.7k per input, which the 64 B
    FILL slack (51k op) covers.
- **The SI degree argument is SI-GLS's with two fixed chains**: event degree 18 or 42, 2-event chunks, NQ_MAX = 60, derived
  in `si.mjs`.
- **Assembler changes.** One assembler bug was fixed here (`roll()` across a sized pile used the wrong symbolic index;
  SI-GLS never hit it). A mod-r kernel node and `invokeBytes` were added. The reviewed `chunked/bn254/sound-si-gls/asm.mjs`
  is unchanged.
- **snarkjs (Keccak transcript)** was not built. The design's unmeasured estimate stands: about 24M op more.

## Reproduce

```sh
# node_modules: symlink to a zk-verifier-bench pnpm install (@bitauth/libauth 3.1.0-next.8, @noble/curves 2.2.0)
# vectors/ is a copy of the prover track's vectors (wip/plonk-kzg-prover research/plonk-kzg/prover/vectors)
node single.mjs mul2 spec 13            # one spend, bch-spec (J = 13 Jacobian windows)
node single.mjs merkle16 txv5 8         # 100 KB input regime, minimal pad
node chain.mjs merkle16                 # today's rules: 10-input transaction, per-input op / budget
node profile.mjs mul2 13                # per-phase op-cost
nice node test.mjs mul2 spec 13         # -> results/test-mul2-spec.json  (also: merkle16, txv5 8)
nice node chaintest.mjs mul2            # -> results/chain-mul2.json      (about 25 min per circuit)
node summary.mjs                        # -> results/summary.json
SRS_CACHE=dir node srs-check.mjs        # baked SRS constants = Aztec Ignition ([x]_2 from the pinned/downloaded manifest)
node soundness/lattice.mjs              # numbers behind SOUNDNESS.md (GLV lattice, ranges, bound)
```

## Files

| file | content |
|---|---|
| `math.mjs` | fields, tower map, fixed-G2 chain constants (asserted against noble), GLV, MSM offset |
| `plonk.mjs` | VK parsing, the value-level verifier (gnark transcript + our substitutions), MSM schedule and witness |
| `si.mjs` | SI prover for the 2-pairing product with fixed G2 |
| `asm.mjs` | assembler (fork of SI-GLS's; fixes listed above) |
| `script.mjs`, `witness.mjs`, `single.mjs` | single-input program, honest witness, spend runner |
| `multi.mjs`, `chain.mjs` | today's multi-input chain: plan, roles, witness, FILL sizing |
| `test.mjs`, `chaintest.mjs`, `profile.mjs`, `summary.mjs`, `vm.mjs` | tests, profile, summary, VM runners |
| `results/` | test-*.json, chain-*.json, summary.json |
| `SOUNDNESS.md`, `soundness/lattice.mjs` | soundness argument for the t'-fold, the u batching and the chain; its numeric checks |
