# Review: kallisti groth16_cashscript #34 + zk-verifier-bench #51 (report only)

Reviewed heads: g#34 `f8b16b2`, b#51 `157c233`. These match the exact commits named in the PR texts.
Bases: source main `838431c`, bench main `37e35f2`. Both PRs branch from the stated bases `8eb2c5d` / `b140f64`.
Scratch worktrees: `work/review-k34/{g34,b51,g-8eb2c5d}`. Notes: `work/review-k34/PROGRESS.md`.
Policy: constructive only. Every check below is a reproduction or ownership check, or a run of existing positive fixtures. No forgeries were built or searched for.

## Verdict: request-changes (small)

One blocking defect (B1): the BN exact-frame descriptor fails its own seal check, so the main 908/908 claim cannot be reproduced from the committed tree.
There are also two missing ownership arguments (F1, F2) on the "corrected" artifacts and three nits.
None of this touches REGISTRY, the feed, results.json or any score. Once B1 is fixed and F1/F2 are answered (a gate or a written argument), this is merge-with-nits.

## Checklist

| Check | Result |
|---|---|
| Changes match the description | Yes, apart from B1, F1 and F2 below. 19 source files (+903/-36) and 20 bench files (+1082/-3), as stated. |
| Artifacts outside REGISTRY and the feed | Yes. No change under `src/harness/`, no change to `results.json`, and none of the 4 new descriptors is imported anywhere. `export-json.ts` reads only `REGISTRY`. The only change to an existing descriptor is a comment line in `bch-groth16-bls12381-intratx-residue.ts`. |
| Repair tools reproduce committed vectors | BN legacy catalog: byte-identical. BLS-large: byte-identical. vk_x successor catalog: byte-identical. BN exact-frame (5 files): byte-identical only with a cashc that emits the gate as `OP_DUP OP_SIZE OP_NIP <n> OP_NUMEQUALVERIFY`. The current fork `compiler-optimizations-8` (`dab3f89f`) and upstream cashc 0.14.0 both emit `OP_SIZE <n> OP_NUMEQUALVERIFY`, so the tool's certificate assert fails (N1). |
| Guarded BN references run the full checker first | Yes, for all 7 profiles. See the "Guarded BN" section. |
| BLS genpow re-export changes only provenance | Yes. A structural diff of both JSON files shows only `provenance.sourceRevision` (`b7338ea` → `8eb2c5d`). `export.mjs checked` run from a clean `8eb2c5d` checkout over the main-branch files reproduces both PR files byte-for-byte. All 9 `sourceFiles` hashes match `8eb2c5d`, and `b7338ea` is an ancestor with no diff under `leader-recovered/`. |
| Both merge cleanly onto current main | Yes. `git merge-tree` is clean for g#34 onto `838431c` and for b#51 onto `37e35f2`. |
| Bench typecheck | `tsc --noEmit` passes. |
| Positive runs | Exact-frame validator, with the seal patched locally: PASS, 52 runs, 908/908 inputs (this matches the PR). Other descriptors: see "Positive re-runs". |

## Blocking

**B1. The `bch-bn-exact-frame-corrected.ts` seal is stale.** `EXPECTED_CATALOG_SHA256 = 'abe6e0e0…'`, but the committed `src/bch/bn-exact-frame-corrected-catalog.json` hashes to `fb6e834c1bba3f8433de4ff4352aa674e531c07d5b6802a7cf05f6e3c3ee3b39`. It has the same value in every PR commit from `ee1e087` on. The module throws on import, so `node --import tsx src/bch/validate-bn-exact-frame-corrected.mjs out.json` fails with "catalog seal mismatch".
- The catalog content itself is consistent: all 5 `correctedVectorSha256` values match the committed vector files, and `sourceHelper.sha256` matches `repair_exact_frames.mjs`.
- With the constant changed to `fb6e834c…`, the validator reports `PASS_CORRECTED_BN_DESCRIPTOR_POSITIVES` with 52 runs and 908 inputs.
- Fix: update the constant (after confirming the catalog is the intended one).

## Ownership findings (missing argument; no counterexample claimed)

**F1. BLS-large input 1 (768-byte genesis carrier) has no exact-frame owner.**
- The repair gates input 0 (288 B, depth 1) and input 2 (1632 B, depth 0). Their frozen programs read the final limb as `OP_BIN2NUM` of the whole remaining carrier.
- The frozen input-1 program (`miller ops[0,155) + validate inputs`) has the same parse shape: 15 × `0x30 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SWAP`, then `OP_BIN2NUM` on the remainder. It contains no `OP_SIZE` anywhere.
- Input 0's forward check reads input 1's unlocking only at a fixed offset (header size + `VKX_LIMB_OFFSET*W`, 2 limbs). It does not compare the push header or the carrier length.
- So the 16th limb of input 1 is not shown to be owned by an exact frame. The same applies to the source path: `build_vectors_residue_bls_large.mjs` sets `enforceExactInputLength` only on the vk_x final and the Miller terminal, while the new transform makes prefix-mode parsing read the declared width.
- The frozen artifact gets gates only, not the transform fix. Please either add the 7-byte depth-0 gate `76 82 77 02 0003 9d` after input 1's `OP_DROP`, or state the owner argument. For example: every one of the 16 limbs is range-checked into `[0, p)` and no consumer commits to input 1's carrier bytes. I saw only 14 `OP_WITHIN [0,p)` checks (depths 2..15) right after the parse, so the argument needs to cover depths 0 and 1.
- `remaining-verifier-corrections-qualification.json` `blsLarge.limits` should also name the exact-program-graph premise. No input pins a sibling's locking hash, in either the original or the corrected fixture. The `.ts` descriptor already says this; the qualification file does not.

**F2. Slim bare terminal: the dropped redeem push is unowned, and the archived reverse-offset readers depend on it.**
- For `…-densless-msm-slim-equation-checked`, input 4's locking is `OP_DROP ‖ guard ‖ terminal`. The trailing unlocking push (the old redeem) is now dropped without any hash or size check.
- The slim executors (inputs 0..2) and the genesis pin read input 4's unlocking from the end with a fixed `backTerminal` (`densless-msm-slim/vkx-stages.mjs:14-16, 46-53`; `build.mjs:149` `pinN: {idx: 4, back: backTerminal}`). Their stated premise was "its redeem push has a fixed length (the locking pins its hash)", and that premise no longer holds.
- The equation claim is unaffected: the copied checker reads n0/n1 from input 4's stack and the proof from input 3's first push, and legacy checks get no credit.
- But the PR text says the guard "preserves its reverse-offset wire frame". The positive fixtures preserve it; nothing enforces it.
- Fix: make the bare terminal start `OP_HASH256 <hash256(original redeem)> OP_EQUALVERIFY` (35 B) instead of `OP_DROP`, or at least `OP_SIZE <len> OP_NUMEQUALVERIFY OP_DROP`. Otherwise reword the claim and record the unowned push in `qualification.json`.

## Nits

- **N1. Pin the gate compiler.** `repair_exact_frames.mjs` compiles a 7-byte gate with whatever `cashc` resolves to. Its certificates pin the full compiled bytes `76 82 77 <n> 9d aa20 <00×32> 87`, which neither the current co-8 fork nor upstream 0.14.0 produces. Either name the cashc build in the catalog or README, or emit the gate as literal bytes (as `registered-bls-large-repair.json` already does with `gateHex`). I confirmed the rest of the tool by substituting a cashc shim that emits exactly those bytes: all 5 vector files then reproduce byte-for-byte.
- **N2. The checker is inherited, not reviewed.** The guarded references take their soundness from the g#33 native5 `equation-guard.mjs` checker (merged as a standalone reference after a delta check, not a verifier.cash three-lens review). That fits "no score claim", but the site and STATUS-MAP should label these references "unreviewed (inherits native5 checker)" if they are ever surfaced.
- **N3. The PairFold-7 successor uses the known checker VK,** and the PR says so. If PairFold-7 is ever listed, the name should not imply equivalence with the original key.

## Guarded BN references (detail)

- `guard.mjs` builds `equationLoader` (5,901 B, sha256 `0c295f59…`) with the same construction as `pairfold5-pevalfuse-deterministic/build.mjs`. `equation-guard.mjs` is unchanged from main, and `main` is empty, so the loader only defines functions.
- The bridge ends with `push 65792 (checker_main) OP_INVOKE OP_VERIFY` (`…03000101 8a 69`).
- The bridge field order is [7,6,11,10,9,8,3,2], with field 3 (−Ay) negated mod p. This is identical to the native5 genesis bridge.
- For all 7 profiles, the guarded code is exactly `guard ‖ original program`, or `0x75 ‖ guard ‖ terminal` for slim. Only the guarded input and the terminal change.
- For the 6 P2SH profiles, the new `HASH256(worker locking hashes)` root is in the terminal program, so the guarded genesis is required by the terminal.
- `OP_DEPTH == argumentCount` pins the frame. The proof is either the 448-byte stack item, or for slim input 3's first push behind the literal `4dc001` header (P2SH push-only).
- n0/n1 come from the same push slots that the original descriptors declare (for example pairfold5 input 3, pushes 37/36; slim input 4, pushes 53/52).
- `catalog` reproduces byte-for-byte via `checked-legacy/export.mjs` against bench `b140f64` fixtures.

## Positive re-runs (existing fixtures only)

- BLS-large corrected: 9/9 inputs and 3/3 graphs in each of the oracle, proposed-spec consensus and proposed-spec standard modes, so 27/27 (matches the PR).
- BLS vk_x successor: 22/22 inputs and 2/2 graphs in each of the oracle, BCH2026 consensus and BCH2026 standard modes, so 66/66 (matches the PR).
- Guarded BN references, oracle: 185/185 inputs, 35/35 graphs (matches the PR).
- Guarded BN references, declared native mode: 0 complete graphs for all 7 profiles, which matches native HOLD. The per-input counts are 0/25 for 4 profiles, 20/25 for slim and spec, and 0/35 for PairFold-7. The PR text gives no per-input native figure, so these counts are new information, not a mismatch.
- BN exact-frame, seal patched locally: 52 runs, 908/908 inputs (matches the PR).

## Draft GitHub comment (for g#34, with a pointer on b#51; not posted)

> Thanks, this is a careful follow-up. I did a constructive delta review: reproduction and ownership checks, plus existing positive fixtures only. Both PRs merge cleanly onto current main, nothing touches REGISTRY or the feed, and the BLS genpow re-export changes only `provenance.sourceRevision`. Running `export.mjs checked` from a clean `8eb2c5d` reproduces both files byte-for-byte.
>
> Reproduced byte-for-byte: `checked-legacy/export.mjs` (7 profiles), `repair_registered_bls_large.mjs`, `export_successor_catalog.mjs`. The guarded BN references do run the copied native5 checker first: `guard ‖ original` (or `OP_DROP ‖ guard ‖ terminal` for slim), `CALL checker_main OP_VERIFY`, the same bridge field order as native5, the root transferred into the terminal, and the same n0/n1 slots as the original descriptors.
>
> Requested before merge:
> 1. **b#51 `bch-bn-exact-frame-corrected.ts`:** `EXPECTED_CATALOG_SHA256` is `abe6e0e0…`, but the committed catalog is `fb6e834c1bba3f8433de4ff4352aa674e531c07d5b6802a7cf05f6e3c3ee3b39`, so the module throws on import. With the constant updated, `validate-bn-exact-frame-corrected.mjs` gives PASS, 52 runs, 908/908.
> 2. **BLS-large input 1:** the frozen `miller ops[0,155) + validate inputs` program parses its 768-byte genesis carrier with the same "last limb = BIN2NUM(remainder)" shape that you gated on inputs 0 and 2, and it has no `OP_SIZE`. Input 0's forward check reads only the vk_x slice at a fixed offset. Could you add the depth-0 768-byte gate (`7682770200039d`), or write down the owner argument for its last limbs? Please also add the exact-program-graph premise to `blsLarge.limits` in the qualification file.
> 3. **Slim bare terminal:** input 4's trailing redeem push is now dropped unchecked, but the slim executors and the genesis pin still locate input 4's state by `backTerminal` from the end, which relied on the hash-pinned redeem length. The equation claim is unaffected (the checker owns it), but the frame is no longer enforced. A `OP_HASH256 <h> OP_EQUALVERIFY` (or `OP_SIZE <len> OP_NUMEQUALVERIFY OP_DROP`) in place of the leading `OP_DROP` would restore it. Otherwise please reword "preserves its reverse-offset wire frame".
>
> Nit: `repair_exact_frames.mjs` depends on a cashc build whose gate output is `OP_DUP OP_SIZE OP_NIP <n> OP_NUMEQUALVERIFY`. Our current fork (co-8) and upstream 0.14.0 both emit `OP_SIZE <n> OP_NUMEQUALVERIFY`, so the certificate assert fails. Could you name the compiler, or emit the gate as literal bytes like `gateHex` in the BLS-large manifest? With a shim emitting the certified bytes, all five vectors reproduce exactly.
>
> With 1–3 addressed this looks good to merge as standalone references (no registry or score change).
