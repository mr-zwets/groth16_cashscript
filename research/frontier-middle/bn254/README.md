# Track 2 (frontier middle), BN254 research builds: T1 sigls-dproj and T2 rolled-residue

**Research artifacts. These are not ranked entries.** Neither design is registered in the bench, results.json or the
registry, and neither has had an independent review. Both compose techniques that are already reviewed (see each
soundness section). Sources are on branch `wip/frontier-middle-build-bn254` of groth16_cashscript. The bench
measurement glue is on the same branch name in zk-verifier-bench, under `research/frontier-middle/bn254/`
(`measure.ts`, the vector files and `results.json`). It runs the harness's own `benchmark()` on Implementation objects
that are never added to `REGISTRY`.

## Results (bench harness, libauth 3.1.0-next.8)

Bytes are the harness score: locking + unlocking + tx overhead. Op-cost comes from the harness's loosened BCH 2026 VM.
"BCHN" adds the executed OP_DEFINE body bytes, which BCHN charges and libauth does not (Track 1). The worst case is the
bench's dense-input proof. E_k = max(bytes, op/(800k) − 41·inputs), computed on the worst proof with BCHN-adjusted op-cost.

| design | bytes | op (committed) | BCHN-adj. | worst proof (BCHN) | in | gates | k_min bch-2026 / bch-spec |
|---|--:|--:|--:|--:|--:|---|--:|
| **T1** sigls-dproj (shared kernels, default) | **16,571** | 33,317,244 | 33,318,543 | 33,334,850 | 1 | 4/4 valid, 15/15 invalid, 0/9 forged inputs | 2.56 / 1.57 |
| T1 inline variant (`DPROJ_SHARED=0`) | 17,203 | 32,021,353 | 32,022,832 | 32,039,485 | 1 | 4/4, 15/15, 0/9 | 2.36 / 1.48 |
| **T2** rolled-residue (default) | **9,776** | 130,300,611 | 130,303,393 | 139,083,823 | 1 | 4/4, 6/6, 0/9 | 17.9 / 8.8 |
| T2 byte-lean variant (`T2_SQR=mulc`) | 9,116 | 147,416,156 | 147,419,350 | 156,206,071 | 1 | 4/4, 6/6, 0/9 | 21.6 / 10.3 |

Effective size E_k in KB. "Today" is the best reviewed BN254 entry at each k, from the model.

| k | 1 | 2 | 5 | 10 | 25 | 50 | 100 |
|---|--:|--:|--:|--:|--:|--:|--:|
| today | 27.6 | 21.9 | 21.9 | 21.9 | 21.9 | 19.2 | 9.6 |
| T1 | 41.6 | 20.8 | **16.6** | **16.6** | 16.6 | 16.6 | 16.6 |
| T1 inline | 40.0 | **20.0** | 17.2 | 17.2 | 17.2 | 17.2 | 17.2 |
| T2 | 173.8 | 86.9 | 34.7 | 17.3 | 9.8 | 9.8 | 9.8 |
| T2 mulc | 195.2 | 97.6 | 39.0 | 19.5 | **9.1** | **9.1** | **9.1** |
| best new vs today | +45% | −9% | −24% | −24% | −58% | −53% | −5% |

At k = 10 on the committed proof, T2's E10 is 16.2 KB (−26%). On the dense worst-case proof it is 17.3 KB, so T1 is
the better design at k = 10.

**Gap to the model** (`work/frontier-middle/model`, 4601c4a):

| design | bytes: predicted → measured | op: predicted → measured | |
|---|---|---|---|
| T1 | 16,453 → 16,571 (+0.7%) | 31.9M → 33.32M (+4.4%) | The inline variant comes to 17,203 / 32.02M. Sharing one kernel between B and δ costs +1.3M of call overhead and saves 632 B. |
| T2 | 8,235 → 9,776 (+18.7%) | 117.5M → 130.3M (+10.9%) | Worst proof: 130.9M → 139.1M (+6.3%). This T2 is not the model's T2 architecture (see "Deviations"). |

T2's op gap is mostly vk_x: a non-GLV Jacobian Straus costs 13.0M, against the model's 1.9M for GLV-Jacobian. The
measured per-call units are:
- line multiplication: 202k (model 175k);
- projective doubling + line: 136k (model 180k);
- addition + line: 176k (model 200k);
- squaring: 231k (model 176k).

The byte gap comes from three places: the two 72-product multipliers (about 830 B each, scheduled for op-cost, not
bytes), the exact residue terminal (1.8 KB), and 8 baked vk_x table words.

Both targets meet their accept bars: T1 ≤ 17.0 KB and ≤ 36M; T2 ≤ 10.0 KB and ≤ 150M. Neither hits a kill criterion.

## T1: sigls-dproj (`sigls-dproj/`)

**Design.** This is a fork of the reviewed BN254 `chunked/bn254/sound-si-gls` (bench `bch-groth16-sound-si-gls-single`)
with one change: the 88-slope baked δ pile (5,665 B) and its DSTEP function (187 B) are replaced by an on-chain
projective walk of the baked δ point.
- The walk uses the reviewed projective doubling and mixed-addition formulas, with lines evaluated at ±z at P = C:
  - doubling: (2YZ, −3X², Y² − 3b′Z²);
  - addition: (λ′, −θ, θx_q − λ′y_q).
- Additions use d_e·δ = (x_δ, d_e·y_δ).
- The two terminal Frobenius lines come from projective additions of ψ(δ) and −ψ²(δ).
- In the default build, one local OP_DEFINE doubling kernel and one addition kernel serve both walks. Operands are
  passed on the stack under the kernel's own names.
  - For δ, the c factor is 1.
  - For B, F is squared before the doubling call.

Everything else is byte-for-byte the reviewed design: the transcript, 2-event chunks, 33 monic states, GT-GLS vk_x,
residue root, endpoint check and layout pins. **The witness WS is identical to the reviewed entry's for the same proof**
(checked for fixture 0), and n_q is unchanged.

Redeem: 5,838 B (reviewed: 11,182 B). The unlocking for fixture 0 is 16,473 B.

**Soundness (composition of the reviewed SI-GLS argument; see `chunked/bn254/sound-si-gls/README.md`).**
1. The chunk identity already allows line factors that are "computed on-chain (B) or baked (δ)".
   - The projective δ lines are Fp2 multiples of the affine lines. Their scale factors are 2YZ or λ′, which lie in
     Fp2* ⊂ Fp6*, so the classes [P_k] in G = Fp12*/Fp6* are unchanged.
   - The honest monic states are therefore identical, which the prover asserts by producing the same WS.
   - [f′] = [c]^λ, the residue argument and the GT-GLS binding carry over verbatim.
2. δ is a baked VK constant, so its trajectory is deterministic.
   - `math.mjs` replaces the slope-pile assertion with a build-time check of all 88 steps against noble.
   - For every step it checks:
     - (X/Z, Y/Z) is the true point;
     - Z ≠ 0;
     - the leading line coefficient is ≠ 0;
     - the projective line is exactly that coefficient times the affine tangent or chord line.
   - It also checks the endpoint (6x+2)δ + ψ(δ) − ψ²(δ) = −ψ³(δ).
   - So the "nonzero line factors" rule holds by construction.
3. No new witness is introduced. Every D_k is still fixed by WS and on-chain computation before ρ and z.
   - The projective δ lines still have degree 9, the same as the affine ones, so the degree bookkeeping is unchanged:
     NQ_MAX = 132 is re-derived and asserted in `build.mjs`.
   - ε ≤ 1.134·(33 + 275)/p ≈ 2^−245.15, unchanged.
4. The B walk, the endpoint check (X:Y:Z) == −ψ³(B), Z_T ≠ 0, the transcript and the layout pins are untouched.
5. Sharing one kernel changes only which stack items feed the same arithmetic.
   - Multiplying by the constant c = 1 is the identity.
   - Squaring F before the B doubling gives the same F²·L_B.
   - The value-level verifier `verifyValues` (now on projective δ lines) accepts.

**Checks:**
- `node build.mjs` (deterministic, twice);
- `node sweep.mjs` with SWEEP_N=40 and SWEEP_SPARSE=4: 59 cases accepted in both modes on the budget-loosened bch-spec
  VM. The cases cover the 5 fixtures, special inputs, the max-degree witness (max op 33.53M), the min-degree witness,
  the liveness extreme, the lowest-n_q statements, a lattice-shifted GLS witness and 40 random proofs;
- in the bench: 4/4 proofs, the existing 15 invalid classes rejected, and the public-input gate rejecting 9/9.

The strict bch-spec VM rejects T1 only for op-cost density (k ≥ 1.57 needed). `redteam.mjs` is the unchanged reviewed
suite. It was not run: this task only allowed the existing invalid vectors.

## T2: rolled-residue (`rolled-residue/`)

**Design.** A rolled, single-input singleton with a real Fp12 accumulator and no Miller hints. It runs under BCH 2026
script rules: redeem 9,128 B, unlocking 9,678 B. Both are under the 10,000 B caps, so the only strict-VM failure is
op-cost density.

- **Witness.** One push W of 17 words (544 B): A, B, C, n0, n1, the residue root as a monic class rep s^c (6 words),
  and zInv.
- **Field and parsing.** Fp12 = Fp[X]/M with M = X¹² − 18X⁶ + 82. This is the SI-GLS polynomial basis, used here
  exactly.
  - Every word is range-checked: < p, and n < r.
  - A and C are on the curve and B is on the twist.
- **vk_x.** vk_x = IC0 + n0·IC1 + n1·IC2, computed by a joint left-to-right double-and-add over 254 bits in Jacobian
  coordinates.
  - The accumulator starts at the baked Q0 = 2^−254·IC0 (build-asserted).
  - A 3-point baked table holds IC1, IC2 and IC1+IC2.
  - Z·zInv ≡ 1 is checked, then the result is converted to affine.
- **Miller loop.** One rolled OP_BEGIN loop runs over the 65 NAF events of 6x+2, with F starting at S_c(−X). Each event:
  - squares F;
  - doubles each of the three projective G2 walks: B with P = −A, γ with P = vk_x, δ with P = C;
  - multiplies F by each line polynomial (6 nonzero coefficients);
  - at each of the 21 addition events, adds ±Q on every walk and folds S_c(∓X).
- **Shared code.** One OP_DEFINE kernel each serves all three walks: doubling, addition, line multiplication, monic
  multiplication and ψ.
- **Terminal.**
  - The Frobenius additions with ψ(Q) and −ψ²(Q) on all three walks.
  - The B endpoint check (X:Y:Z) == −ψ³(B) with Z ≠ 0, taken verbatim from SI-GLS.
  - F ·= m_αβ (a baked monic class rep of the Miller value of (α, β)) · S_c(ηX).
  - Then the exact class identity: the odd part of F·Fr1(−X)·Fr1(−ηX) must be zero, with Fr1 = Frob(S_c), i.e.
    [F·c^(p²)] = [c^p·c^(p³)].

Variant `T2_SQR=mulc` computes F² as F·(A + X⁶B) through the shared monic multiplier plus a shared GLUE function.
It saves 660 B and costs 17M.

**Soundness (composition of reviewed pieces; no Fiat–Shamir, no Schwartz–Zippel, no Miller hints).**
1. **Exact class identity.** The terminal tests, exactly over Fp12, that P·σ(W) ∈ Fp6, where:
   - P is the product of all factors;
   - W = Fr1(X)·Fr1(ηX);
   - σ is X ↦ −X; M is even, so reduction commutes with σ.

   With W ≠ 0 this is [P] = [W] in G. That is the SI-GLS terminal identity with all 33 chunk identities collapsed into
   the exactly computed F, so it yields [f′] = [c]^λ for f′ = Miller(−A,B)·Miller(vk_x,γ)·Miller(C,δ)·m_αβ. The
   reviewed SI-GLS residue argument (also minop's quotient-torus terminal) then gives FE(f′) = 1, which is the Groth16
   equation. The check is deterministic, so no error term is added.
2. **P ≠ 0.** This matters because an all-zero P would pass, so every factor is shown nonzero in the field Fp12:
   - S_c(±X), S_c(ηX) and m_αβ are monic of degree 6;
   - each line polynomial has constant/X⁶ part y_P·Φ(ℓ0), with ℓ0 ≠ 0 and y_P ≠ 0;
   - for B, ℓ0 ≠ 0 follows from the SI-GLS rule: Z = 0 is absorbing and Z_T ≠ 0 is checked;
   - for γ and δ, `math.mjs` asserts every step of the walk against noble at build time;
   - y_P ≠ 0 holds because G1 has odd order. A and C are curve-checked, and vk_x is a correct curve point (item 4).
   - W ≠ 0 because it is a product of Frobenius images of a nonzero monic polynomial.
3. **B ∈ G2.** The B trajectory is computed on-chain from the twist-checked B, then the endpoint and Z ≠ 0 are checked.
   This is the SI-GLS "B binding" argument verbatim.
4. **vk_x and public-input binding.** n0 and n1 are canonical (< r < 2²⁵⁴), and their bits drive the on-chain MSM.
   - Every exceptional Jacobian step (equal, opposite or infinity) forces Z = 0, which is absorbing in both formulas.
     Then Z·zInv ≡ 1 fails. So an accepted vk_x is exactly IC0 + n0·IC1 + n1·IC2.
   - This is the BLS minop GLV-Jacobian pattern with a witnessed zInv, used here without GLV.
   - Exceptional inputs can only cause rejection, never a wrong vk_x. For honest statements they are negligible, and
     every swept special input was accepted.
5. **Canonical encoding.** DEPTH == 1, SIZE(W) == 544, unsigned 32-byte LE words, and a consensus clean stack.

**Arithmetic correctness (tested, not machine-proved).** The new kernels are the sparse and monic polynomial
multipliers mod M, the squaring, the line-coefficient extraction and the Jacobian G1 formulas.
- `debug2.mjs` and `debug3.mjs` check them against a noble Fp12 mirror: all 12 coefficients of F after the loop, all
  three walk states, and F at the terminal stages, matched exactly.
- Every value is reduced into (−p, p) before it feeds a product, so the largest intermediate is about 70 B, far below
  the 10,000 B VM number limit.
- Acceptance and rejection:
  - in the bench: 4/4 existing proofs and 6/6 existing invalid statements;
  - `sweep.mjs`: 18 minted proofs accepted in both modes, including (0,0), (1,0), (0,1), (r−1,r−1) and dense inputs,
    with max op 139.0M;
  - the public-input gate rejects 9/9.

**Deviations from the model's T2.**
1. The polynomial basis (SI-GLS M(X)) replaces minop's lazy signed tower.
2. An exact class check replaces minop's cross-multiplied terminal. The algebra is equivalent, and it needs no
   [0:0] rejection because P ≠ 0 is proven.
3. vk_x is a non-GLV Straus. This saves bytes (no GLV table or decomposition) and costs about 11M of op.
4. There is no recompiler outlining pass, and no δ-slope-pile flag.

## Reproduce

Run with this repository's dependencies. `VERIFIER_DIR` points at a zk-verifier-bench checkout; the default is the
sibling `../bench` worktree.

```sh
cd sigls-dproj && node build.mjs && node export.mjs vectors.json && node profile.mjs && SWEEP_N=40 SWEEP_SPARSE=4 node sweep.mjs sweep.json
DPROJ_SHARED=0 node build.mjs     # inline variant (restore with node build.mjs)
cd ../rolled-residue && node build.mjs && node export.mjs vectors.json && node profile.mjs && node sweep.mjs sweep.json
T2_SQR=mulc node build.mjs        # byte-lean variant (restore with node build.mjs)
# bench worktree: copy the vectors to research/frontier-middle/bn254/<id>-vectors.json, then
pnpm exec tsx research/frontier-middle/bn254/measure.ts
```

Redeem sha256: T1 `980482d4…1125` (5,838 B), T2 `95297900…758f` (9,128 B). Both builds are deterministic.
