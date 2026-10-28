# BLS12-381 rolled minop (research design T2)

**Research artifact, not a ranked entry.** It is not in the bench registry and it is not reviewed. It fits the
bch-2026 per-input script and standard unlocking caps when packaged as P2SH32: redeem 7,840 B, unlocking 8,590 B.
Its op-cost, though, needs a budget about 28–31× looser than bch-2026. Track 2 (the empty middle of the bytes vs
op-cost frontier) uses it as a data point.

It is a rolled version of the reviewed `singleton/bls12-381/groth16_minop.cash`, bench id
`bch-groth16-bls12381-singleton-minop`, which had two independent reviews on 2026-10-27 (verifiers.md line 117). The
generator `gen_minop_rolled.mjs` is a copy of `gen_singleton_minop.mjs`. Only the Miller section emitter differs:

1. **One loop.** The unrolled SSA schedule (471 call sites) becomes one CashScript `for` loop over the 64 NAF digits
   of |x|, baked as a 64-byte digit string (0, 1, and 2 for −1). Each iteration does:
   - fp12Sqr;
   - pointDouble + line for each of (−A, B), (vk_x, γ), (C, δ);
   - at a nonzero digit, the c^∓1 torus fold (fp12MulTorus with ν or u), then pointAdd + line for each pair, with
     ±Q by digit sign.
2. **γ and δ walked on-chain.** The 828 baked γ/δ line coefficients are gone. γ and δ are walked from (x : y : 1) with
   the same `pointDouble` / `pointAdd` / `line` library bodies used for B. Only their 8 affine coordinates are baked,
   each pushed once.

These parts are unchanged, emitted by the same code: input validation, GLV-Jacobian vk_x with the witnessed zInv, the
e(α, β) torus constant, the fused ψ endpoint check (with R_B Z ≠ 0), and the quotient-torus residue terminal. The
spend() interface is unchanged as well, so the reviewed minop's existing bench vectors run against this program as
they are.

## Results (libauth 3.1.0-next.8, bench harness `benchmark()`)

| | P2SH32 (policy-relevant) | bare locking (as the reviewed minop) |
|---|--:|--:|
| score (scripts + tx overhead) | **8,712 B** (35 + 8,590 + 87) | 8,674 B (7,840 + 747 + 87) |
| program (redeem / locking) | 7,840 B, of which OP_DEFINE bodies 2,267 B (26 library functions) | same |
| op cost, committed | **192,759,049** libauth; **BCHN-adjusted 192,761,316** (+2,267) | 192,742,808 |
| op cost, dense worst-case proof | 218,289,447; BCHN-adjusted 218,291,714 | 218,273,206 |
| op budget needed (bch-2026 base, BCHN-adjusted) | k_min 27.9 committed, 31.2 worst case | 306 (the budget does not count a bare locking) |
| harness gates | valid accepted; 4/4 proofs runtime-general; worst case accepted; invalid 5/5 rejected; public-input gate 9/9 rejected; secure packaging | same |

`measure.mjs` gives the same verdicts on the full existing vector set:
- 5/5 valid accepted: committed, 3 multiproof proofs, the dense worst case;
- 10/10 invalid rejected: invalidUnlocking, 4 range-invalid, 5 multiproof invalid.

For comparison, the reviewed unrolled minop measured the same way is 58,007 B locking and 145.6M committed / 171.1M
worst. The rolled loop plus the on-chain γ/δ walks cost +47.2M (+47.2M worst) and save 50,167 B.

**Model prediction vs measured.** The prediction was 8,189 B (band 7,919–8,639) at 189.3M (band 187.3–193.5M); the
worst-case proof was predicted at 214.9M. Measured: 8,712 B (P2SH32) / 8,674 B (bare) at 192.8M, worst case 218.3M.
The model calibrates on the results.json score of the bare minop (58,841 = locking + unlocking + 87), so the like-for-like
comparison is the bare score: 8,674 B, which is 485 B (5.9%) over the prediction and 35 B above the band. The excess is
in the rolled loop body. The model budgeted 900 B for it. The CashScript loop (6 dbl/add call sites, 6 line call
sites, the reassignment of 30 loop variables per branch, digit decode) compiles to more than that. Op-cost is inside
the band.
The first build pushed each γ/δ coordinate at every use (9,121 B score); pushing each one once saved 471 B for +0.17M.

**Effective size** E_k = max(bytes, op/(800k) − 41) (bch-2026 density, BCHN-adjusted op, P2SH32 score). Today's
best reviewed BLS value is in parentheses:

| k | 5 | 10 | 25 | 50 | 100 |
|---|--:|--:|--:|--:|--:|
| committed | 48.2 KB (26.5, +82%) | 24.1 (26.5, **−9%**) | **9.6** (26.5, **−64%**) | 8.7 (24.8, −65%) | 8.7 (12.4, −30%) |
| dense worst-case proof | 54.5 | 27.2 (+3%) | 10.9 (−59%) | 8.7 (−65%) | 8.7 (−30%) |

Acceptance bar: bytes ≤ 9.5 KB (8.71 KB, met), op ≤ 205M (192.8M, met), E25 ≤ 10.2 KB (9.60 KB, met; 10.87 KB with
the dense worst-case proof). Kill bar: op > 230M (not reached; worst case 218.3M).

## Soundness argument (constructive)

The mathematics is the reviewed minop's; see `singleton/bls12-381/README.md` and its two reviews (inputs < r,
complete jacAddG1, B ∈ G2 by ψ(B) = [x]B with R_B Z ≠ 0, r | (p + |x|) quotient-torus residue). The variant changes
only where the γ/δ line coefficients come from and the control flow.

1. **γ/δ coefficients.** The reviewed minop's baked coefficients were produced off-chain by `C.millerBatchOps`. It
   uses the projective `pointDouble`/`pointAdd` formulas, starts from (x : y : 1), and follows the NAF op order.
   On-chain, the library bodies of the same formulas run from the same start in the same per-pair order. So each
   coefficient is congruent mod p to the baked one. `line` is linear in the coefficients mod p, so F is unchanged.
   `assertFixedWalks()` checks this at generation time against noble and the baked values, for every one of the 69
   steps per pair:
   - each coefficient equals the baked one;
   - Z ≠ 0;
   - the y-slot coefficient c2 ≠ 0;
   - the homogeneous point equals noble's [m]Q;
   - the walk ends at [|x|]Q.

   The walks are VK constants and independent of the proof.
2. **Rolling.** The loop changes control flow and stack scheduling only. Within one digit the line products are
   reordered (all doublings, then the fold and the additions). Fp12 multiplication is commutative, so F is equal mod p.
3. **Differential test** (`difftest.mjs`):
   - Each contract gets a debug copy that takes 12 extra arguments and requires tF_i == expF_i right after the
     terminal canonicalises F. Nothing else changes.
   - expF is computed in JS by replaying the reviewed contract's exact op order with noble's Fp12. A JS replay of the
     rolled order gives the same value.
   - Result: on all 5 existing vectors (committed, 3 multiproof proofs, the dense worst case), both debug contracts
     accept the same expF and both reject expF + 1 in one limb. **F_rolled == F_unrolled on every vector.**
4. **No new kernel.** pointDouble, pointAdd, line, fp12Sqr and fp12MulTorus are the reviewed library bodies
   (`singleton/bls12-381/lib/lazy/`), imported unchanged.

The terminal accepts iff [F] = [frob(c, 1)] in the quotient torus, exactly as in the reviewed minop. F is the same
value, so acceptance is the same predicate on the same inputs.

## Files and reproduce

```sh
node gen_minop_rolled.mjs                      # asserts the gamma/delta walks; writes groth16_minop_rolled.cash
node --stack-size=60000 measure.mjs groth16_minop_rolled.cash measure-rolled.json   # existing minop vectors
node --stack-size=60000 difftest.mjs           # F differential test vs the reviewed unrolled minop
HOIST=0 node gen_minop_rolled.mjs              # variant with gamma/delta literals inlined at every use (+471 B)
```

`BENCH_DIR` points at a zk-verifier-bench checkout. The default is the sibling `bench` worktree of this research
workspace. Bench measurement: zk-verifier-bench branch `wip/frontier-middle-build-bls12381`,
`research/frontier-middle/bls12381/run.ts`.

## Not done

The optional recompiler/outliner pass (predicted 7.1 KB / 195M) was not run.
