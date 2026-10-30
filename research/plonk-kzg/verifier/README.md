# Tracks 6 and 7: a CashVM verifier for gnark PLONK/KZG proofs (BN254, SHA-256 transcript)

Status: **research, built and measured; not a leaderboard entry.** Nothing in REGISTRY, results.json,
score-history.json or the website changed. Not independently reviewed.

- **Track 7, integrated** (2026-10-30, branch `wip/plonk-usable-verifier`): the three Track 7 branches combined into
  one verifier, the default build: the Aztec Ignition ceremony SRS for every vector (`-srs`), BSB22 commitments in
  both the single input and the today's-rules chain, and the GT fold with the new hand-overs. See the next section.
- **Track 7 branches** (2026-10-30), kept below as history; their numbers are per branch:
  - `wip/plonk-usable-msm`: chain hand-over redesign plus GT folding of the fixed MSM bases (measured on the test SRS);
  - `wip/plonk-usable-bsb22`: BSB22 commitments, unfolded, test SRS; its chain did not fit one transaction;
  - `wip/plonk-usable-srs`: the Ignition ceremony SRS (its re-run is in the Track 6 section).
- **Track 6** (2026-10-29): the first build, without GT folding. It is still built with `FOLD=0`. Its text follows
  further below, unchanged; its numbers are for that build.

## Track 7, integrated: ceremony SRS, BSB22 commitments, GT fold (default build)

Branch `wip/plonk-usable-verifier`: `wip/plonk-usable-msm`, `-srs` and `-bsb22` merged onto origin/main, then the
pieces they did not cover were built (below). Research, not a leaderboard entry.

**Review fixes (2026-10-30).** A measurement review found that the mul2 chain rejected an honest fresh proof (n_q =
264 quotient words: the GT binding in ST, `bindST`, left ST about 30 words of headroom). Fixing it showed two more caps:
WQa ‖ WQb exceeded the 10,000-byte stack item limit in ST from n_q = 310, and input 9 (the WQb host) capped n_q at
about 340, below the honest tail of the BSB22 circuits (1M sampled proofs: max 345 / 351; 5 and 2 per million above
340, 0.4% above 308). Changes:
- mul2 plan without `bindST` (the binding is in the last SI role in every plan);
- the chain quotient is three pieces WQa (4,096 B, input 8) ‖ WQb (input 9) ‖ WQc (input 4, an MA role with spare
  op-funded bytes), never concatenated; z = H(h0 ‖ ρRaw ‖ H(WQa) ‖ H(WQb) ‖ H(WQc)) (SOUNDNESS §0, §1);
- `liveness.mjs` and a `chaintest.mjs` case check that a proof with the **structural maximum** n_q (348 / 384 / 420
  / 420) fits the chain (every input ≤ 10,000 B and within its BCHN-adjusted budget, tx ≤ 100,000 B). So no honest
  proof fails on its quotient size any more; the previous caps were about 260 (mul2) and 340 (all four).
- `parseVK` rejects k = 0 (L_1(ζ) is read from the ω⁰ denominator; with k = 0 and a commitment it would be wrong).
- Smaller items: the SRS file sha256 is pinned and the G1 powers re-checked in `srs.go`; `srs-check.mjs` also checks
  the pushed x, y of [x]_2 and x of ψ([x]_2); `summary.mjs` takes ranges over accepted proofs only; chain results
  record BCHN op-cost per input; `PROVER_DIR` defaults to `../prover/`; `test.mjs` requires J; `package.json`.

Cost of the fixes (chain only; the single-input redeems and witnesses are byte-identical, so their results stand):
mul2 +0.2 to +1.1 KB (most of it from dropping bindST), merkle16 +0.2 KB, BSB22 circuits +0.06 KB.

### Results (score = unlocking + 35 B locking per input + tx overhead; ranges over 5 valid proofs per circuit)

Every vector is on the Aztec Ignition SRS. `range64` and `merkle16rc` carry one BSB22 commitment (`std/rangecheck`).
Op-cost is libauth standard; BCHN-adjusted adds the OP_DEFINE body bytes (single input +2,539 to +2,635 per spend;
chain +34.4k to +38.6k per input, now also written per input in `chain-*.json`). `results/summary.json` has every value.

| circuit / regime | inputs / tx | score (B) | tx bytes | op-cost (M) | BCHN-adj. (M) | worst margin (BCHN) |
|---|--:|--:|--:|--:|--:|--:|
| mul2 / bch-spec, J = 23 | 1 / 1 | 59,291–60,669 | | 53.41–53.84 | 53.41–53.85 | 3.21% |
| mul2 / one 100 KB input, J = 14 | 1 / 1 | 63,276–64,622 | | 50.50–50.90 | 50.50–50.91 | pad per proof |
| mul2 / today, standard | 10 / 1 | 82,679–83,001 | 82,329–82,651 | 64.04–64.46 | 64.38–64.80 | 0.23% (FILL per proof) |
| merkle16 / bch-spec, J = 23 | 1 / 1 | 60,567–61,306 | | 54.49–54.94 | 54.50–54.94 | 3.33% |
| merkle16 / one 100 KB input, J = 14 | 1 / 1 | 64,631–65,355 | | 51.61–51.97 | 51.61–51.97 | pad per proof |
| merkle16 / today, standard | 10 / 1 | 84,588–84,783 | 84,238–84,433 | 65.66–65.98 | 66.02–66.34 | 0.05% |
| range64 (BSB22) / bch-spec, J = 21 | 1 / 1 | 64,510–65,311 | | 57.49–58.02 | 57.49–58.02 | 3.43% |
| range64 (BSB22) / one 100 KB input, J = 14 | 1 / 1 | 68,985–69,553 | | 55.09–55.55 | 55.09–55.55 | pad per proof |
| range64 (BSB22) / today, standard | 10 / 1 | 89,620–89,962 | 89,270–89,612 | 69.81–70.16 | 70.19–70.54 | 0.33% |
| merkle16rc (BSB22) / bch-spec, J = 21 | 1 / 1 | 64,957–65,760 | | 57.36–57.86 | 57.36–57.86 | 3.87% |
| merkle16rc (BSB22) / one 100 KB input, J = 14 | 1 / 1 | 68,764–69,363 | | 54.91–55.39 | 54.92–55.40 | pad per proof |
| merkle16rc (BSB22) / today, standard | 10 / 1 | 89,868–90,312 | 89,518–89,962 | 69.62–70.09 | 70.01–70.47 | 0.65% |

**Tests** (`results/test-*.json`, `results/chain-*.json`), consensus and standard mode, every verdict as `verify.mjs`
(the JS reference) gives it:

| | mul2 | merkle16 | range64 | merkle16rc |
|---|---|---|---|---|
| valid accepted (each regime) | 5/5 | 5/5 | 5/5 | 5/5 |
| tampered rejected (each regime) | 76/76 | 78/78 | 86/86 | 91/91 (13 commitment cases) |
| manipulations, single input (each regime) | 33/33 | 33/33 | 34/34 | 34/34 |
| manipulations, chain | 36/36 | 36/36 | 38/38 | 38/38 |
| chain liveness: structural max n_q fits | 348 | 384 | 420 | 420 |
| honest n_q (5 vectors; 1M sampled: max) | 219–258; 294 | 234–255; 315 | 258–279; 345 | 264–282; 351 |

- The BSB22 circuits add an adaptive manipulation (the folded Qcp_0's nibbles encode s + 1, SI re-witnessed) and,
  in the chain, a TV2 entry flip. The review fixes add three chain manipulations (WQc word flipped, WQc wrong size,
  128 B moved from WQb to WQc) and, for mul2, the G0 s_0 flip (its binding is no longer in ST).
- All 20 fresh proofs of the measurement review (5 per circuit, n_q 231–294; `cache/review-fresh-vectors/`, not
  committed) are accepted by the chain, including the mul2 proof with n_q = 264 that the earlier build rejected.
- `srs-check.mjs` passes for all four circuits: VK [1]_1, [1]_2, [x]_2 against the pinned and downloaded ceremony
  value; every [x]_2 slope piece in each single-input redeem and every SI slice hash in each chain; the six number
  pushes x, y of [x]_2 and x of ψ([x]_2) in both builds; a control G2 point's constants absent.
- Prover side: `verify.mjs` 351/351 cases (all four circuits on Ignition); gnark's own `Verify` rejects every
  tampered case it can represent (37 + 38 + 44 + 47).

### Comparison

| | Track 6 (main: test SRS, no fold, no BSB22) | Track 7 branch | integrated | change vs Track 6 / branch |
|---|--:|--:|--:|--:|
| mul2 bch-spec | 66,290–66,549 | msm 59,480–59,995 | 59,291–60,669 | −8.8% (max) |
| mul2 100 KB input | 69,757–69,919 | msm 63,497–63,948 | 63,276–64,622 | −7.6% |
| mul2 today | 92,845–93,095 | msm 81,882–82,035 | 82,679–83,001 | −10.8% |
| merkle16 bch-spec | 68,494–68,655 | msm 60,790–61,785 | 60,567–61,306 | −10.7% |
| merkle16 100 KB input | 72,188–72,438 | msm 64,896–65,801 | 64,631–65,355 | −9.8% |
| merkle16 today | 95,637–95,985 | msm 84,476–84,754 | 84,588–84,783 | −11.7% |
| merkle16rc bch-spec | (unsupported) | bsb22 72,404–72,760 (J = 13) | 64,957–65,760 | −9.6% vs bsb22 |
| merkle16rc 100 KB input | (unsupported) | bsb22 77,402–77,720 (J = 8) | 68,764–69,363 | −10.8% vs bsb22 |
| merkle16rc today | (unsupported) | bsb22: **does not fit** (≥ 103.7 KB, relaxed VM only) | **89,868–90,312, 10 inputs, 1 standard tx** | fits |

- mul2 and merkle16 moved only within the proof-to-proof spread against the msm branch; the SRS change does not
  change sizes. The bch-spec margins moved to 3.21% / 3.33% (msm branch: 3.53% / 3.26%) with the Ignition proofs.
- Track 6's op-cost: 58.0–58.3M (mul2 bch-spec) and 70.6–71.0M (mul2 today); the integrated build needs 53.4–53.8M
  and 64.0–64.5M.
- **Cost of one commitment** in the integrated build (merkle16rc against merkle16, same k and n): +4.4 KB at bch-spec
  (J = 21 against 23, for the margin; at J = 23 it is +3.4 KB with a 1.4% margin), +4.0 KB in the 100 KB input,
  +5.4–5.6 KB in the chain. Against the bsb22 branch's +3.9–4.1 KB, the commitment costs about the same: Bsb22_0
  is one more variable base (≈ 1.6 KB of slopes, 2.1M op), and Qcp_0 one more folded base (65 nibble bytes, about
  10.8k op per event, about +25 honest quotient words) instead of a G1 MSM base.

### What the integration built (beyond the three branches)

1. **Fixed and variable bases with BSB22.** `fixedNames` = Ql, Qr, Qm, Qo, Qk, S3, S1, S2, Qcp_j, [1]_1 (GT-folded);
   `baseNames` adds Bsb22_j to the variable bases (L, R, O, Z, H0, H1, H2, Bsb22_j, Wz, Λ', Wzw, φ(Wzw)). Qcp_j's R
   constants come from `gtConsts` like every VK point. FOLD=0 keeps the bsb22 branch's order.
2. **TV/TV2 split (chain).** 11 variable bases make TV 10,560 B, over the 10,000 B push limit (the bsb22 branch's
   blocker). `makePlan({tv2: [host, n1]})` puts the first n1 bases in TV (input 2) and the rest in TV2, a fixed
   push in an MSM role (input 3, the first MA). Each host checks its own entries; LOADT reads both; ST reads Wζω's
   table from TV2. Builds with ≤ 10 variable bases are unchanged.
3. **BSB22 chain plans** (`plans.json`): MJ(50..42, C0) · ST · MJ(41..38, TV) · MA(37..25 + TV2, 24..12, 11..0) ·
   SI(0–16 + GZ + C1, 16–36 + C2, 36–52 + WQa, 52–65 + WQb), with WQc in the second MA role (review fix). C0 had grown
   to 10,684 B, so C2 takes more code (blob targets 4,100 / 5,600 since the review fix; 3,900 / 5,600 before) and
   input 0 one window less. Per-input data and need are within 10,000 B
   (`node plan.mjs merkle16rc`).
4. **BSB22 vectors regenerated on Ignition** (`go run . -srs ... -circuits range64,merkle16rc`), and
   `gen-vectors.sh` runs both prover passes with `-srs`.
5. **J for BSB22 at bch-spec is 21.** The extra folded base costs op: J = 23 leaves 0.9% (range64) / 1.4% (merkle16rc)
   BCHN-adjusted margin; J = 21 gives 3.4% / 3.9% for +0.9 KB (`sweep.mjs`).
6. **Soundness** (SOUNDNESS.md): scope now covers Ignition, BSB22 in both builds and the TV split (Lemma 3
   "integration delta", §8); A6 with 10 folded bases: max deg 852, NQ = 420, SI error 2^-243.63
   (`soundness/lattice.mjs` lists m_f = 8..11); total bound unchanged (≈ 2^-64 beyond ε_PLONK+BSB22). Stale line
   references were replaced by function names.

### Open / honest negatives (integrated build)

- **Liveness.** The quotient size is no longer a liveness limit: a proof with the structural maximum n_q fits (above).
  What remains per proof is the op-cost spread of the MSM roles (digit patterns): the most loaded op-bound input seen
  is input 2 (MJ, TV host) at 9,859 B (BSB22) and 9,959 B (mul2, fresh proof 0), i.e. 41 B under the limit for mul2.
  That input's maximum is reached when all its digits are nonzero (about a quarter of proofs), so the observed values
  should be close to its worst case, but this was not proved or stress-tested. 10 real proofs per circuit went through
  the chain (5 committed, 5 fresh), plus the n_q stress witnesses.
- **Margins:** single-input bch-spec 3.2–3.9%; the 100 KB pad and the chain FILL are sized per proof (0.05–0.65%
  worst per input, by construction).
- **Still above the design model** (66 KB): the chain is 82.7–90.3 KB.
- **m ≥ 2 commitments** are built by the same code but not tested (SOUNDNESS §8: γ/v length condition for m ≥ 3).
- **k = 0** (no public input) is rejected at build time (`parseVK`); supporting it needs the ω⁰ denominator as an extra
  batch-inverse entry.
- **SRS:** Ignition is verified as far as the verifier relies on it; the full transcripts (about 1.1 TB) and the
  participants' signatures were not checked (prover FORMAT.md "SRS").
- No BCHN node run; BCHN op-cost is modelled (DEFINE body bytes), not measured.
- `chainprobe.mjs` and `results/chain-merkle16rc-probe.json` are the bsb22 branch's unfolded probe, kept as history.
- `chain-*.json` `codeBytes` lists C0 and C1 only (C2 is in the plan's blob list).

### Reproduce (integrated)

```sh
npm install                                                     # package.json (libauth 3.1.0-next.8, noble/curves 2.2.0)
cd ../prover && SRS_CACHE=/path/cache ./gen-vectors.sh          # Ignition download + checks, both prover passes, verify.mjs
cp vectors/*.json ../verifier/vectors/ && cd ../verifier
SRS_CACHE=/path/cache node srs-check.mjs                        # all four circuits (PROVER_DIR defaults to ../prover/)
for c in mul2 merkle16; do nice node test.mjs $c spec 23 && nice node test.mjs $c txv5 14 && nice node chaintest.mjs $c; done
for c in range64 merkle16rc; do nice node test.mjs $c spec 21 && nice node test.mjs $c txv5 14 && nice node chaintest.mjs $c; done
for c in mul2 merkle16 range64 merkle16rc; do nice node liveness.mjs $c 1000000; done   # results/liveness-*.json
node summary.mjs                        # results/summary.json (all circuits, Track 6 comparison block, liveness)
node plan.mjs merkle16rc                # per-input data / op / need of the chain plan
node soundness/lattice.mjs
```

Runtimes on this machine: chaintest.mjs 4–6 min per circuit; the full 12-suite matrix took about 27 min in the
measurement review; liveness.mjs about 4 min per circuit at 1M samples (most of it the sampling).

## Track 7 branch `wip/plonk-usable-msm`: GT fold and the chain hand-over

These numbers were measured on the test-SRS vectors, before the integration; the integrated build's are in the
section above.

### Results (score = unlocking + 35 B locking per input + tx overhead; 5 valid proofs per circuit)

| circuit / regime | inputs | score (B) | Track 6 score | change | op-cost (libauth std) | worst margin (BCHN-adj.) |
|---|--:|--:|--:|--:|--:|--:|
| mul2 / bch-spec (J = 23) | 1 | 59,480–59,995 | 66,290–66,549 | −10.0% | 53.28–53.67M | 3.53% |
| mul2 / 100 KB input (J = 14, padded) | 1 | 63,497–63,948 | 69,757–69,919 | −8.8% | 50.37–50.70M | pad per proof |
| mul2 / today, standard | 10 (1 tx) | 81,882–82,035 (tx 81.6 KB) | 92,845–93,095 | −11.8% | 64.01–64.44M | FILL BCHN-sized |
| merkle16 / bch-spec (J = 23) | 1 | 60,790–61,785 | 68,494–68,655 | −10.6% | 54.71–55.10M | 3.26% |
| merkle16 / 100 KB input (J = 14) | 1 | 64,896–65,801 | 72,188–72,438 | −9.6% | 51.82–52.16M | pad per proof |
| merkle16 / today, standard | 10 (1 tx) | 84,476–84,754 (tx 84.1 KB) | 95,637–95,985 | −11.7% | 66.10–66.36M | FILL BCHN-sized |

**Tests** (`results/test-*.json`, `results/chain-*.json`), all in consensus and standard mode:

| | single input (bch-spec and 100 KB) | today's chain |
|---|---|---|
| valid proofs | 5/5 per circuit and regime | 5/5 per circuit |
| tampered vectors | 76/76 (mul2), 78/78 (merkle16) | 76/76, 78/78 |
| witness manipulations | 33/33 | 32/32 (mul2), 33/33 (merkle16) |

New manipulations:
- GT nibble flips, including out-of-range bytes 0x10 and 0x81;
- adaptive "nibbles of a folded base encode s + 1", with a re-witnessed SI;
- G0's ρ, z, QZ and s_i words;
- GZ, WQa, and WQb with a wrong size.

- **Without the fold** (`FOLD=0`), with only the hand-over changes (LOADT tree, SIL altstack, shared PIN): 88,640 B
  (mul2) / 91,364 B (merkle16) unlocking, against 92,295 / 95,185 for Track 6 (proof 0). So about 3.7 KB of the chain gain is
  the hand-over work and about 7.5 KB is the fold.

**Tampered vectors are now 154 in total over both circuits.** That is the same set Track 6 used: its "154/154" is
the sum over both circuits.

### What changed

1. **Measured first** with a function-level profiler (`fprof.mjs`, `chainprof.mjs`), on the Track 6 chain, mul2:
   - MSM table reload (LOADT): 1.055M op per MSM input;
   - TV check: 4.1M;
   - window-loop overhead: about 6.8k op per (window, base);
   - unit costs: affine add 19.6k op + 32 B, affine doubling 19.8k + 32 B, Jacobian madd 47k, Jacobian doubling 34.8k;
   - ROLL / PICK / FROMALT cost includes the moved item's length, and ROLL also its depth.
2. **Hand-over alternatives** (the task's list), measured with these kernels:
   - **Disjoint base subsets per input, hand over a partial sum: negative.** Each extra subset needs its own 255
     doublings, at least 8.2 KB-equivalent (affine 255 × 32 B, or Jacobian 255 × 34.8k = 8.9M). A shared-doubling MSM
     input pays about 1.3 KB of hand-over overhead.
   - **Recompute tables locally: negative.** 270 slope additions per input is 5.3M + 8.6 KB, against 0.65–1.05M for
     reading them.
   - **Fixed-base tables as redeem constants: negative.** They would be paid in every input. In a code blob they cost
     the same bytes as the published TF, and every input hashes the blob. GT folding then removed TF altogether.
   - **Cheaper reading of the published tables: kept.** LOADT splits each table with a balanced SPLIT tree and skips
     the 0x00 sign byte for host-checked words: 1.055M → 0.649M per MSM input. On the Track 6 chain alone this gives
     92,295 → 89,259 B (mul2, proof 0).
3. **GT fold of the fixed bases** (`gt.mjs`; Lemma 4 in SOUNDNESS.md). It applies the SI-GLS GT-GLS technique:
   - The 8 (mul2) / 9 (merkle16) fixed bases leave the G1 MSM. Each scalar s_i is split as Σ_j u_{i,j} π_j (4 × 65
     bits; Babai on the GLS lattice).
   - Per Miller event, F± is multiplied by TP_i/TM_i[nibble] (subset products of the baked monic classes R_{i,j}).
   - Rconst cancels the 2^64 offset, and an exact binding mod r ties the nibbles to s_i.
   - **Deviation from the design: 2-event chunks are kept** (33 states). The design proposed 1-event chunks. The
     quotient cap grows instead: 60 → 348 / 384 words; honest n_q is 225–267.
     - Measured cost: 1-event chunks add 32 states (+6.1 KB) and 32 boundaries. 2-event chunks add about 5.6 KB of
       honest WQ and no op.
   - Measured on the single input, the G1 side alone is −19.5 KB: without the fixed bases, mul2 at bch-spec drops from
     66.4 KB to about 46.9 KB (an invalid build used only to measure). The SI side costs about 9 KB back:
     - 0.19M of tables per base;
     - about 10.8k op per base and event;
     - +170 quotient words;
     - 3.2 KB of R constants.
     
     Net −6.8 to −7.4 KB per regime.
4. **Chain restructuring** around the fold:
   - ST also computes h0, ρ, z, the quotient Horner value QZ and (mul2) the binding, and publishes ρ, z, QZ [, s_i] in
     G0. The SI roles no longer hash WS or WQ.
   - WQ = WQa (4,096 B, fixed) ‖ WQb (variable, PUSHDATA2) is split over two SI inputs.
   - One SI role publishes GZ = R_{i,j}(±z) (8m words), checked against its own computation. The other roles build
     their subset tables from it: 0.95M per role instead of 1.48M.
   - SIL keeps WSs, R and an interleaved schedule/nibble string on the altstack, so the kernels never reorder the main
     stack: −0.3M per SI role.
   - The code is three hash-checked blobs (C0 in input 0, C1/C2 in SI inputs), with shared PIN, GZD, TBC and BND
     functions.
   - FILL sizing iterates on the filled transaction, since remote reads see FILLs, and includes BCHN's DEFINE body
     bytes. So every input is BCHN-safe by construction.
   - Roles: MJ(50..41, C0) · ST · MJ(40..37, TV) · MA(36..24, 23..12, 11..0) · SI(0–16 + GZ + C1, 16–34 + C2,
     34–52 + WQa, 52–65 + WQb). `plans.json` holds the tuned plan per circuit.

### Changed hand-over values (chain)

| value | Track 6 | Track 7 |
|---|---|---|
| G0 (ST → all) | uRaw ‖ s'_q (18–19 bases) ‖ P_R | uRaw ‖ s'_q (10 variable bases) ‖ P_R ‖ ρ ‖ z ‖ QZ [‖ s_i of the folded bases, merkle16] |
| TF (fixed-base tables) | published in input 3, SHA-256-checked | removed |
| TV | unchanged | unchanged; read with a SPLIT tree, no sign byte |
| WS (ST) | s^c ‖ 33 states | s^c ‖ NB (65 m nibble bytes, each < 16) ‖ 33 states |
| WQ | 60 words fixed, in input 8 | WQa (4,096 B, input 8) ‖ WQb (variable, input 9); read and size-checked by ST |
| GZ (new) | – | 8m words R_{i,j}(±z), published by input 6, checked there, read by inputs 7–9 |
| SI → SI HAND | P*, chain states, F±, R | P*_var, chain states, F±, R (same layout) |
| code | C0 + C1 | C0 + C1 + C2 |

### Soundness changes (SOUNDNESS.md)

- **A6** gains the GT factors: they are monic and fixed by q_h0 through NB in WS. The degree cap is 348 / 384 words,
  and the error is 2^-243.75.
- **New Lemma 4:** under A6 and the binding, (E) holds for P*_var + Σ s_i B_i.
- **Lemma 3 is rewritten** for the hand-overs above. B3 now has 9 targets.
- **A gap found while writing Lemma 4, and fixed:** the first fold build did not range-check the nibble bytes. An
  out-of-range byte would decouple the factor lookup from the binding. Since [1]_1 is a folded base, that could absorb
  any error in (E). The check `NB & 0x0f…0f == NB` is now in both builds.
- **An assembler bug was fixed:** `arrange()` kept a prefix with foreign items above it. Track 6 builds are
  byte-identical with the fix. The same pattern exists in the reviewed `sound-si-gls` and `bn-native-sound` assemblers;
  it was not checked whether their builds are affected.

### Open / honest negatives (Track 7)

- **The chain is still above the design model.** The design estimated 66.0 KB over 7 inputs; the chain lands at
  81.9 / 84.5 KB over 10 inputs.
  - Every SI role rebuilds the GT subset tables: 0.95M each, 4 roles.
  - The SI part needs 4 inputs.
  - The code is 17 KB, of which 3.2–3.6 KB are R constants.
- **Liveness is tested on 5 proofs per circuit.**
  - bch-spec margins are 3.3–3.5% at J = 23.
  - Chain inputs are FILL-sized per proof, but data-bound inputs have only the slack of their own data.
  - The honest n_q varies (225–267), and the cap leaves headroom.
- **Not changed on this branch:** the unsafe test SRS, BSB22 commitments, snarkjs. (The integration adds the first two.)
- **Malleability (no soundness effect):** WQ leading zero words in the chain, and the choice of a lattice-equivalent
  nibble decomposition.

### Reproduce (Track 7)

```sh
node single.mjs mul2 spec 23            # bch-spec;  node single.mjs merkle16 txv5 14   (100 KB input)
node chain.mjs merkle16                 # today's rules, tuned plan from plans.json
node plan.mjs mul2                      # per-input data / op / need (planning aid); PLAN='{...}' to try plans
node chainprof.mjs mul2                 # function-level op-cost per input (OPF=<fn> for its opcode mix)
nice node sweep.mjs mul2 spec 21 23 25  # J sweep with the worst BCHN-adjusted margin
nice node test.mjs mul2 spec 23; nice node test.mjs mul2 txv5 14; nice node chaintest.mjs mul2
FOLD=0 node chain.mjs mul2              # the Track 6 design (no fold), with the Track 7 LOADT / SIL / PIN changes
node soundness/lattice.mjs              # incl. the GT-fold degrees and error terms
```

---

# Track 6 (FOLD=0 build), 2026-10-29

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

**Re-run on the Aztec Ignition vectors (Track 7, `wip/plonk-usable-srs`).** `results/` now holds this run. The table above
is Track 6's run on the test SRS.
- The redeem sizes are byte-identical: 18,016 / 18,017 B for mul2 and 18,244 / 18,245 B for merkle16.
- All verdicts are unchanged.
- The new figures are within the proof-to-proof spread, because gnark blinds every proof differently:

| circuit / regime | score (B) | op-cost (libauth std) | BCHN-adjusted | worst margin |
|---|--:|--:|--:|--:|
| mul2 / bch-spec | 66,517–67,035 | 58.38–58.86M | +1,405 | 4.18% |
| mul2 / 100 KB input | 69,983–70,534 | 55.57–56.10M | +1,405 | pad sized per proof |
| mul2 / today, 10 inputs | 92,987–93,614 (tx 92.6–93.3 KB) | 70.96–71.47M | +21,686 per input | 0.13% |
| merkle16 / bch-spec | 68,559–68,623 | 60.48–60.80M | +1,405 | 3.22% |
| merkle16 / 100 KB input | 72,188–72,569 | 57.64–57.96M | +1,405 | pad sized per proof |
| merkle16 / today, 10 inputs | 95,670–96,062 (tx 95.3–95.7 KB) | 73.12–73.45M | +21,686 per input | 0.14% |

Tests on the new vectors:
- Valid proofs: 10/10 accepted in every regime.
- Tampered vectors: 154/154 rejected in every regime.
- Manipulations: 56/56 rejected single-input, 42/42 in the chain.

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

## Track 7 branch `wip/plonk-usable-bsb22`: BSB22 commitments (api.Commit)

Date: 2026-10-30. Branch `wip/plonk-usable-bsb22`. Research, not a leaderboard entry. This section is that branch's
unfolded build on the test SRS (FOLD=0). In the integrated build the commitment's Qcp_j is GT-folded and the chain
fits one transaction; see the integrated section at the top.

Circuits that use gnark's range-check or lookup gadgets carry BSB22 commitments. The single-input verifier now
handles them: `script.mjs` and `plonk.mjs` are generic in the number m of commitments, and m = 1 is tested. The protocol
delta is the prover track's PROTOCOL.md "BSB22 commitments"; the soundness scope is [SOUNDNESS.md](SOUNDNESS.md) §8.

**What the script adds per commitment:**
- decoding a 32-byte qcp_j(ζ) (< r) and a 64-byte point Bsb22_j (canonical, on the curve, not infinity): the proof
  is 864 B;
- [Qcp_j] in γ (a VK constant inside GV) and in v; Bsb22_j in α; qcp_j(ζ) in v;
- gnark's hash-to-field on chain: 3 × `OP_SHA256` and one `OP_XOR` (`expand_message_xmd`, DST `BSB22-Plonk`), then
  48 bytes BE mod r (`script.mjs` 3b);
- one more Lagrange term in PI(ζ), whose denominator joins the one checked batch inverse;
- two more MSM bases: Bsb22_j (proof base, scalar −t'·qcp_j(ζ), folded into P* like every other Λ term) and Qcp_j
  (fixed base, scalar v^{6+j}).

**Results** (merkle16rc: merkle16 with a private 64-bit amount, `std/rangecheck`, one commitment, k = 3, n = 2^14;
`results/test-merkle16rc-*.json`). Score = unlocking + 35 + 63, ranges over the 5 valid proofs, op-cost libauth
standard (consensus about 0.1% lower).

| regime | merkle16 (Track 6) | merkle16rc (m = 1) | delta |
|---|--:|--:|--:|
| bch-spec, J = 13: score | 68,494–68,655 | 72,404–72,760 | +3.9–4.1 KB (+6%) |
| bch-spec: op-cost | 60.42–60.72M | 64.98–65.21M | +4.5M |
| bch-spec: worst margin | 3.3% | 1.10% | |
| 100 KB input, J = 8: score | 72,188–72,438 | 77,402–77,720 | +5.2–5.3 KB |
| 100 KB input: op-cost | 57.60–57.85M | 61.82–62.08M | +4.2M |
| redeem | 18,244 | 18,659 | +415 B |
| BCHN add-on (OP_DEFINE bodies) | +1,405 | +1,405 | 0 |
| proof | 768 | 864 | +96 B |
| today's rules (multi-input) | 95.6–96.0 KB, 10 inputs | **does not fit** (below) | |

Tests, both modes, every verdict as the JS reference:

| | merkle16rc bch-spec | merkle16rc 100 KB | range64 bch-spec |
|---|---|---|---|
| valid accepted | 5/5 | 5/5 | 5/5 |
| prover-track tampered rejected (incl. 13 commitment cases) | 91/91 | 91/91 | 86/86 |
| witness manipulations rejected | 28/28 | 28/28 | 28/28 |

`range64` (k = 1, n = 2^8) is a debugging circuit: 71,988–72,312 B and 64.58–64.99M op on bch-spec, essentially the
same as merkle16rc, since the cost does not depend on n.

**Where the cost goes** (`node profile.mjs merkle16rc 13` against merkle16, proof 0, standard; same k and n):

| phase | merkle16 | merkle16rc | delta |
|---|--:|--:|--:|
| decode + curve checks | 0.459M | 0.502M | +0.043M |
| transcript γ..ζ | 0.027M | 0.031M | +0.004M |
| hash-to-field | – | 0.009M | +0.009M |
| Fr block 1 (PI with the commitment term) | 0.214M | 0.253M | +0.039M |
| v, u, t', MSM scalars | 0.175M | 0.197M | +0.022M |
| MSM tables (2 more bases) | 6.425M | 7.097M | +0.672M |
| P* MSM (2 more bases) | 38.765M | 42.228M | +3.463M |
| rest (P_right, SI) | 14.52M | 14.53M | ≈ 0 |
| total (script) | 60.58M | 64.84M | +4.26M |

- **The commitment's own work is negligible**: the hash-to-field, the larger hashes and the Fr term cost 0.12M op
  together, and about 230 B of redeem.
- **97% of the delta is the two extra MSM bases** (about 2.1M op and 1.6 KB of slopes each).
- The redeem grows by 415 B: 64 B for [Qcp] in GV, 79 B for the hash-to-field, the rest in the Fr kernels.

**Today's rules: does not fit one standard transaction (negative result).** `multi.mjs` handles m ≥ 1. It was run on
the relaxed `free` VM, in consensus mode: the BCH 2026 rules with no item, bytecode or density limit, op-cost still
counted (`node chainprobe.mjs` → `results/chain-merkle16rc-probe.json`).
- **The logic is correct.** All 5 valid proofs accept. The 8 commitment tampers that decode (Bsb22 + G, −Bsb22,
  qcp + 1, commitment from proof 1, commitment and qcp from proof 1, 2·Bsb22, Bsb22 − G, qcp = 0) are re-witnessed
  adaptively and rejected.
- **The bytes do not fit.**
  - Total op-cost is 78.1–78.3M, against Track 6's 73.2–73.5M (standard).
  - The 10-input layout is 101.9–102.2 KB. It also breaks two per-input limits: three MSM inputs need more than
    10,000 B of unlocking, and TV (now 11 variable bases, 10,560 B) exceeds the 10,000 B stack-item limit.
  - The best 11-input layout tried (5 affine roles) is **103.7–104.1 KB**. All inputs but the TV host are within
    10,000 B. A TV split would need one more host and adds bytes.
  - So a circuit with one commitment needs **at least 3.7 KB more than a 100,000 B standard transaction allows**.
- **What would make it fit:**
  - the design's GT folding of the fixed bases (estimated −6 KB, not built);
  - or a chain across two transactions (not designed).
  - Not tried here.

**Not done:**
- m ≥ 2 is built by the same generic code but not tested (SOUNDNESS.md §8 lists a length condition for m ≥ 3).
- `results/summary.json` was not regenerated; it remains the Track 6 summary.
- No large sweep beyond the 5 proofs per circuit was run.
- The bch-spec margin at J = 13 is 1.1%. J = 12 (measured on proof 0) gives 3.4% for +745 B: unlocking 73,310 B, 64.40M
  op of a 66.65M budget.

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
  scripts, with a control point that must be absent. Only the values of the per-circuit VK points changed. The redeem
  sizes did not, and scores moved only within the proof-to-proof spread (see "Re-run on the Aztec Ignition vectors").

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

Track 6 numbers need `FOLD=0` (the fold is the default); `results/` holds the Track 7 runs, and the integrated
build's commands are in "Reproduce (integrated)" above. The Track 6 commands below overwrite `results/`.

```sh
npm install                                   # package.json: @bitauth/libauth 3.1.0-next.8, @noble/curves 2.2.0
# vectors/ is a copy of the prover track's vectors (../prover/vectors)
FOLD=0 node single.mjs mul2 spec 13           # one spend, bch-spec (J = 13 Jacobian windows)
FOLD=0 node single.mjs merkle16 txv5 8        # 100 KB input regime, minimal pad
FOLD=0 node chain.mjs merkle16                # today's rules: 10-input transaction, per-input op / budget
FOLD=0 node profile.mjs mul2 13               # per-phase op-cost
FOLD=0 nice node test.mjs mul2 spec 13        # -> results/test-mul2-spec.json (also merkle16, and txv5 8)
FOLD=0 nice node chaintest.mjs mul2           # -> results/chain-mul2.json (4-6 min per circuit)
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
| `chainprobe.mjs` | Track 7: the m = 1 chain on the relaxed VM (logic check and bytes) |
| `results/` | test-*.json, chain-*.json, summary.json; Track 7: test-merkle16rc-*.json, test-range64-spec.json, chain-merkle16rc-probe.json |
| `SOUNDNESS.md`, `soundness/lattice.mjs` | soundness argument for the t'-fold, the u batching and the chain; its numeric checks |
| `gt.mjs` (Track 7) | GT fold: Miller-value class representatives R_{i,j}, Rconst, GLS decomposition, nibbles, value check |
| `plans.json`, `plan.mjs` (Track 7) | tuned chain plans; per-input data / op / need |
| `liveness.mjs` (review fix) | chain liveness against the quotient size: n_q model, honest distribution, stress at the structural max |
| `package.json` | pinned dependencies (@bitauth/libauth 3.1.0-next.8, @noble/curves 2.2.0) |
| `fprof.mjs`, `chainprof.mjs`, `sweep.mjs` (Track 7) | function-level op-cost profiler; single-input J sweep |
