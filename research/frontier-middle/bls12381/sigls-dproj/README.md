# BLS12-381 SI-GLS with an on-chain projective δ walk (research design T1, "dproj")

**Bench entry `bch-groth16-bls12381-sound-si-gls-dproj`** (vmTarget bch-spec). It had two Track 2 reviews (soundness;
measurement reproduction), both pass with minor findings only, handled in the 2026-10-28 fix round (see "Review
follow-ups"). It needs an op budget about 1.65× looser than bch-spec gives (k ≥ 1.65 on the bch-spec base, k ≥ 2.50
on the bch-2026 base, over the sweep), so it is not valid on any VM that exists or is proposed today; the bench grades
it on bch-spec as "not BCH-compatible: op-cost". It is a Track 2 (the empty middle of the bytes vs op-cost frontier)
design.

This is a fork of the reviewed `chunked/bls12-381/sound-si-gls`, bench id `bch-groth16-bls12381-sound-si-gls-single`,
independently reviewed 2026-10-26 (verifiers.md line 102). It makes exactly two changes:

1. **δ walk on-chain.** The 68 baked affine δ slopes (the 6,579 B pile in the redeem) and the on-chain x/c recursion
   are removed. δ is now walked from (x_δ : y_δ : 1) with the same homogeneous projective doubling and mixed-addition
   formulas as B. The kernels are the reviewed ones, parameterised by role in `script.mjs` (`ROLE.B` / `ROLE.D`); for
   δ the line is evaluated at P = C and F is not squared.
2. **E_A = 0.** The witnessed affine B segment is dropped (10 doublings and 3 additions, 13 slopes, 1,248 B of WS), so
   the whole B walk is projective from (x_B : y_B : 1).

Everything else is unchanged: the 32 states (288 B each), the GT-GLS digits and tables, the residue root, the
endpoint ψ check, the transcript structure, the chunking, the RD range checks and the quotient Horner loop. The tag
prefix is `SIGLS-BLS/P` instead of `SIGLS-BLS/1` (still 43 B), so the transcripts of the two programs are
domain-separated.

## Results (libauth 3.1.0-next.8, bench harness `benchmark()`, fixture `committed`)

| | |
|---|---|
| score (scripts + tx overhead) | **18,892 B** = 35 locking + 18,794 unlocking + 63 |
| unlocking | 18,794 = redeem 6,401 + WS 10,080 + WQ 2,304 (48 words) + push headers |
| redeem 6,401 | field constants and p 1,813 · other data 192 (includes the 4 δ coordinates) · code 4,396 (prologue 2,490; PROJDBL 436, PROJADD 608, DDBL 431, DADD 579) |
| op cost, committed | 36,894,701 libauth consensus / 36,933,101 standard; **BCHN-adjusted 36,897,147** (+2,446 B of OP_DEFINE bodies, each defined once in the prologue) |
| op cost, bench worst-case vector | 37,863,895 libauth (n_q 51); BCHN-adjusted 37,866,341. This is the bench's worst-case proof vector, not the binding case (see the sweep rows) |
| maximum over the sweep | 38,946,559 standard (a random statement with n_q around 100; the budget grows with n_q) |
| op budget needed | **k_min ≈ 1.65 on the bch-spec base, ≈ 2.50 on the bch-2026 base**: the maximum over the sweep and the bench vectors (the binding case is the forced n_q 54 pattern, lowest margin 17.59% standard / 17.67% consensus at k = 2: (38,309,072 + 2,446) / (46,531,200 / 2) = 1.647). Over the bench vectors alone it is 1.64 / 2.49 (bench worst-case vector). The bch-2026-base figure is a density number only: the unlocking (18,794 B) and the WS push (10,080 B) are over the bch-2026 10,000 B caps, so T1 needs bch-spec size limits at any k, like today's SI-GLS single |
| op profile | B doublings 14.69M (63), δ doublings 13.73M (63), B additions 1.66M, δ additions 1.57M, GT-GLS 0.91M, state boundaries 1.84M, the rest ~2.5M |
| liveness sweep (k = 2) | 87 cases (6 fixtures, forced extremes n_q 48..80, the n_q 54 extreme with 10 proof samples, special statements, 40 random proofs): all accepted in both modes. Minimum standard margin 17.6% at the forced n_q 54 pattern |
| rejection | bench vectors 15/15 rejected; the public-input gate 9/9 mutations rejected; `redteam.mjs` 82/82 rejected: the reviewed suite minus the 5 slope classes (no slopes exist), with the reviewed order-13 B case kept as a projective-degeneracy run (rejected at the endpoint guard Z_T ≠ 0, see soundness item 3) |
| degree bound | max deg P 246, deg D 251, NQ_MAX 120 (was 118); ε ≤ (32 + 251)/2^256 ≈ **2^−247.86** per random-oracle query |

**Model prediction vs measured.** The prediction was 18,661 B (band 18,541–18,841) at 37.3M (band 34.7–40.6M); the
measurement is 18,892 B at 36.9M. Bytes come out 231 B (1.2%) over the prediction, 51 B above the top of the band. The
reason is that the δ kernels are separate bound functions (+1,010 B), where the model assumed the kernels would be
reused at +300 B. Op-cost is 0.4M below the prediction, inside the band. The δ section costs 15.3M; the model said 15.4M.

**Effective size** E_k = max(bytes, op/(800k) − 41) (bch-2026 density, BCHN-adjusted op). Today's best reviewed BLS
value is in parentheses:

| k | 2 | 5 | 10 | 25 | 50 | 100 |
|---|--:|--:|--:|--:|--:|--:|
| committed | 23.0 KB (26.5, −13%) | 18.9 (26.5, −29%) | 18.9 (−29%) | 18.9 (−29%) | 18.9 (24.8, −24%) | 18.9 (12.4, +52%) |
| worst-case proof | 23.6 (−11%) | 18.9 (−29%) | 18.9 (−29%) | 18.9 (−29%) | 18.9 (−24%) | 18.9 (+52%) |

It meets the acceptance bar (≤ 19.5 KB and ≤ 42M) and beats today's best for every k in [2, 50].

## Soundness argument (constructive)

The argument is the reviewed SI-GLS argument (`chunked/bls12-381/sound-si-gls/README.md`), with these changes:

1. **δ lines.** Each δ line is now the projective line (ℓ0, ℓ2, ℓ3) of the deterministic walk: (Y² − 3b′Z², −3X², 2YZ)
   for a doubling, (θx_δ − λ′y_δ, −θ, λ′) for an addition. At load time `protocol.mjs` (`DPROJ`) checks all 68 steps
   against noble:
   - the walk point equals noble's [k]δ at every step;
   - Z ≠ 0 and ℓ3 ≠ 0 at every step;
   - each line equals ℓ3 · (c_j, −λ_j, 1), where (c_j, −λ_j, 1) is the baked affine line of the reviewed design.
     λ_j is still asserted in `math.mjs` against noble's `millerTrace`.

   So every δ line is an Fp2* multiple of the reviewed line. The README of the reviewed design already defines f′ only
   "up to Fp2 line scalings (which lie in Fp6)", so the classes [P_k] and the honest states are those of the reviewed
   design with the same digits. The δ walk is a constant of the VK, with no prover input, so this is an exact
   statement about one fixed sequence.
2. **Nonzero lines.** The reviewed argument used "δ lines have ℓ3 = 1". It now uses ℓ3 ≠ 0, which is asserted for all
   68 deterministic steps. With y_C ≠ 0 (E(Fp) has odd order) the X³/X⁹ coefficients y_C(ℓ3.c0 − ℓ3.c1), y_C·ℓ3.c1
   are not both zero, so every δ line is a nonzero polynomial, as for the projective B lines.
3. **E_A = 0.** This is a value of the reviewed design's own parameter. The README's rules apply unchanged: "the
   projective walk enters at Z = 1 with no witness"; Z = 0 is absorbing; Z_T ≠ 0 is checked at the endpoint. The B
   walk is therefore exact from event 0, and B ∈ G2 follows from the same ψ endpoint argument. With no affine
   segment, the witnessed-slope equations and the x ≠ x_B guard simply do not occur. What makes this work is the
   following lemma, which **replaces both the affine slope equations and the x ≠ x_B guard**:

   **Lemma (exactness of the projective walk).** Let the walk start at (x_B : y_B : 1) and let every step be the
   homogeneous doubling (Z3 = 4BH = 8Y³Z) or the mixed addition with ±B (Z3 = Z·λ′³, λ′ = X − x_q Z). If the final
   Z_T ≠ 0, then every step was an exact group operation on affine points and every line had ℓ3 ≠ 0.
   - Z = 0 is absorbing: both formulas have Z3 divisible by Z. So Z_T ≠ 0 implies Z ≠ 0 before and after every step.
   - Doubling: Z3 = 8Y³Z ≠ 0 implies Y ≠ 0 (and Z ≠ 0), so T is not 2-torsion and the tangent formula is the true
     doubling; ℓ3 = H = 2YZ ≠ 0.
   - Mixed addition: Z3 = Z·λ′³ ≠ 0 implies λ′ ≠ 0, i.e. x(T) ≠ x_q, so T ≠ ±Q and the chord formula is the true
     addition; ℓ3 = λ′ ≠ 0.
   - Hence each projective line is ℓ3 · (affine line) with ℓ3 ∈ Fp2*, which the nonzero-line step (item 2) needs, and
     the endpoint compares the true [|x|]B.

   The degenerate cases this rules out (T = ±B at an addition, or Y = 0 at a doubling) make Z = 0 and, for T = B,
   a zero line, after which every chunk identity holds trivially as 0 = 0; only the endpoint guard Z_T ≠ 0 then
   rejects. `redteam.mjs` keeps the reviewed suite's order-13 B vector as exactly this case (the walk reaches T = B at
   a projective addition), and it is rejected at the endpoint guard.
4. **Degrees and cap.** A δ line has degree 9 instead of 8. `protocol.mjs` re-derives the bound from the schedule
   (`LINE_DEG_D = 9`), and `build.mjs` re-asserts it. The worst chunk is 2(12 + 66) + 90 = 246, deg D ≤ 251, so
   NQ_MAX = 120. That is the on-chain cap (48 ≤ SIZE(WQ) ≤ 48·120). The Schwartz–Zippel bound becomes
   (32 + 251)/2^256.
5. **No new witness and no new challenge.** WS loses the slope field (exact size 10,080, pinned). The transcript is
   the same construction, with h0 over the fixed-width WS, ρ, and z after WQ.

The G1 cofactor argument, GT-GLS binding, residue argument and completeness are the reviewed ones, word for word. The
same caveat applies: formula correctness is tested, not machine-proved. Here it is tested by exact divisibility of
every honest identity in the prover, the value-level mirror verifier (`verifyValues`), the δ assertions above, every
accepted sweep proof, and a value-level trace test of the on-chain kernels (`dkerneltest.mjs`, output in
`dkerneltest.log`):
- **δ (ROLE.D).** The δ walk does not depend on the input; its only input-dependent use is the evaluation of each line
  at P = C and ±z. The test compiles DDBL / DADD (`kProjDbl(ROLE.D)`, `kProjAdd(ROLE.D)`) alone with the redeem's
  assembler, and runs them on the VM at all 68 steps, fed the DPROJ point before the step and the script's ±z
  environment for a fixture C at a uniform random z, with uniform random F±. At every step the output point equals
  DPROJ's next point coordinate for coordinate, and F± out equals F± · L_j(±z) for L_j the DPROJ line (4 trials, 272
  steps). So the on-chain δ section reproduces DPROJ.lines and DPROJ's walk points at the value level.
- **B (ROLE.B).** With SL removed from the kernel I/O, the ROLE.B kernels give the same outputs as the reviewed
  `chunked/bls12-381/sound-si-gls` kProjDbl / kProjAdd (SL aside) and as the projDbl / projAdd + line reference, at
  32 independent uniform random inputs.

## Files

These are the reviewed design's files with the changes above. `script.mjs` has the role-parameterised kernels, no δ
pile, no affine branch, and a δ state DX0..DZ1 in the loop. `protocol.mjs` has the `DPROJ` walk and assertions,
E_A = 0, the δ line degree and NQ_MAX. `vm.mjs` evaluates on bch-spec with `operationCostBudgetPerByte = 800·OPK`
(default OPK = 2; OPK = 1 is stock bch-spec, where the spend fails on op-cost only). `export.mjs`, `redteam.mjs` and
`worst.mjs` drop the slope classes; `redteam.mjs` keeps the order-13 case as a projective-degeneracy run (the forge
prover commits X^6 states when the B walk degenerates to zero lines). `test.mjs` is the reviewed cross-check (it
passes). `dkerneltest.mjs` is the δ / B kernel trace test above.

## Reproduce

```sh
node test.mjs
node build.mjs                                   # redeem 6,401 B sha256 bd3fe6eb…d30c
node export.mjs vectors.json                     # bench vectors (worst case: n_q 51)
node redteam.mjs vectors.json redteam.json redteam-report.json    # 82 runs, all rejected
node dkerneltest.mjs 4                           # delta kernels vs DPROJ (68 steps), ROLE.B vs the reviewed kernels
WORST_PROOFS=10 node worst.mjs; SWEEP_N=40 WORST_PROOFS=10 node sweep.mjs sweep.json
UNLIMITED=1 node --stack-size=60000 profile.mjs
```

Bench: `pnpm benchmark bls12381-sound-si-gls-dproj` (vectors `src/bch/groth16-bls12381-sound-si-gls-dproj-vectors.json`,
byte-identical to `export.mjs`). The Track 2 measurement glue is zk-verifier-bench `research/frontier-middle/bls12381/run.ts`.

## Review follow-ups (fix round, 2026-10-28)

- Value-level trace test of the on-chain δ kernels against DPROJ, plus ROLE.B against the reviewed kernels:
  `dkerneltest.mjs` (`DPROJ` now also returns its walk points).
- The order-13 vector is kept as a projective-degeneracy rejection (`redteam.mjs`, 82/82 rejected, this one at the
  endpoint guard).
- The E_A = 0 exactness lemma is stated (soundness item 3).
- k_min is the maximum over the sweep and the bench vectors (≈ 1.65 / 2.50); 37.87M is labelled the bench
  worst-case vector; the bch-2026-base k is marked as a density figure (T1 needs bch-spec size limits).

## Not done

- **Stage 2** (port to `bls-native-sound`, bch-2026 sizes over 4 inputs, ~21.2 KB / 40.2M predicted) was not built.
- **Kernel sharing.** The point arithmetic could be one LOCAL function shared by both roles, with only the line
  evaluation per role. That should save about 0.8 KB (to about 18.1 KB) for about +0.4M op. Not built.
