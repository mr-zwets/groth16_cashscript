# Track 11: real keys — SP1 v5 and RISC Zero Groth16 proofs on the reviewed BN254 native verifier

Branch `wip/real-keys`, 2026-11-03. Research, not a leaderboard entry (nothing is registered in the bench).

**Question.** Does the reviewed sound BN254 verifier `../bn-native-sound` (bench entry
`bch-groth16-bn254-sound-native`, SI-MX3, one transaction with 3 P2SH32 inputs) verify *real* zkVM proofs, i.e.
proofs made under the production verifying keys of SP1 v5 and of RISC Zero's Groth16 receipt verifier, from
published fixtures, with the public inputs bound correctly?

**Answer: yes, unchanged.** The verifier code is bn-native-sound's; only the VK-derived constants differ, and
`../sound-si-gls/math.mjs` recomputes each of them from the VK and asserts it against noble at load. Every published
fixture is accepted by libauth (BCH 2026, consensus and standard) and by stock BCHN 29.1.0 (block validation and
`testmempoolaccept` with `acceptnonstdtxn=0`). Every rejection test is rejected. Sizes and op cost match the reviewed
build: about 27.6 kB, 3 inputs, 6.0% standard op-cost margin per input.

## What was pinned (sources)

| item | source (repo @ commit, path) |
|---|---|
| SP1 v5 VK | succinctlabs/sp1-contracts @ 512b5e029abc27f6e46a3c7eba220dac83ecc306 `contracts/src/v5.0.0/Groth16Verifier.sol` (gnark export; `BETA_NEG`, `GAMMA_NEG`, `DELTA_NEG` stored negated, negated back) |
| SP1 v5 wrapper | same commit, `contracts/src/v5.0.0/SP1VerifierGroth16.sol` (the copy here before the fix round was a whitespace-only variant from later commits such as db9ed47; it now holds the 512b5e02 bytes): selector `a4594c59` (VERIFIER_HASH `0xa4594c59…5913`), inputs `[uint256(programVKey), sha256(publicValues) & (2^253 − 1)]`, each `< R` (`publicInputMSM`) |
| SP1 v5 proofs | no v5 fixture exists in sp1-contracts (its test uses v4.0.0-rc.3) or in sp1-project-template's history (v4 `11b6a09d`, then v6 `0e78f4db`). Three published third-party v5 proofs were used instead, each verified with noble against the SP1 v5 VK before use: SilvanaOne/zk-tests @ c2ec296b `packages/sp1/add/arbitrum/src/lib.rs` (`silvana-add`, 64 B public values); sparsity-xyz/zkp-tee-tutorial @ 33117da0 `modules/02-tdx-gcp/gcp_proof.json` (`sparsity-tdx-gcp`, 1,232 B); Pessina/hackathon @ d5f08571 `zk-solana-aa-client/components/TransferForm.tsx` (`pessina-solana-aa`, 49 B). A proof that verifies under the production VK cannot be produced without SP1's prover (or the ceremony trapdoor), so these are real SP1 v5 proofs. Their *programs* are third-party and were not audited. |
| RISC Zero VK | risc0/risc0-ethereum @ fe5adc304262eec32986246a29e46c9a250cd7e9 `contracts/src/groth16/Groth16Verifier.sol` (snarkjs export, 5 public inputs), wrapper `RiscZeroGroth16Verifier.sol` (VERSION 5.0.0-rc.1; splitDigest, input order) and `contracts/src/IRiscZeroVerifier.sol` (ReceiptClaimLib, Output and SystemState digests), both vendored |
| RISC Zero control ids | same commit, `contracts/src/groth16/ControlID.sol` (last changed in 0dd148c3, 2026-01-23): `CONTROL_ROOT = b1f64013…8167`, `BN254_CONTROL_ID = 04446e66…7ac0` |
| RISC Zero receipt | same commit, `contracts/test/TestReceiptV5_0.sol` (image id `51350de4…57a0`, journal "just a simple receipt"). `TestReceiptV2_0/2_1/2_2/3_0` are older receipts: each one verifies (noble) under an *older* control root from ControlID.sol's history (90877d9a, dc9d181c, 6c4fb313, 274eccaf) and not under the pinned one, so they serve as real wrong-version negatives. |

Copies of every upstream file used are in `upstream/`, byte-identical to the pinned commits. `upstream/SOURCES.md` lists
the repo, commit, path and git blob id of each one. `extract.mjs` parses them, checks every proof with
noble's pairing against the **full upstream statement**, and writes `sp1-v5.fixtures.json` and `risc0.fixtures.json`.
It also checks that the vendored RISC Zero wrapper and claim library still contain the splitDigest body, the input
order and the claim encoding that `claims.mjs` and `covenant.mjs` implement.
SP1 v5 and RISC Zero share α, β, γ (the extractor records this; nothing relies on it). Their δ and IC differ.

## Binding the public inputs (the soundness-reset bug class)

The verifier binds exactly two public inputs `n0, n1`:
- every role decodes each one unsigned and requires `< r` (`STMT`, every role);
- role 2 binds them into the GT-GLS fold of `e(vk_x, γ)` with `vk_x = IC0 + n0·IC1 + n1·IC2`, through
  `(acc_k − 2^64Σπ_i − n_k) mod r == 0` (the vk_x MSM over exactly these two inputs, reviewed in bn-native-sound).

**SP1 v5:** `n0 = programVKey`, `n1 = sha256(publicValues) & (2^253 − 1)`, exactly the upstream order.

**RISC Zero:** upstream has 5 inputs `[CONTROL_ROOT_0, CONTROL_ROOT_1, claim0, claim1, BN254_CONTROL_ID]`. Three are
constants of the deployed verifier, so they are folded into the constant term:
`IC0' = IC0 + CONTROL_ROOT_0·IC1 + CONTROL_ROOT_1·IC2 + BN254_CONTROL_ID·IC5`, `IC' = [IC0', IC3, IC4]`,
`n0 = claim0`, `n1 = claim1`. Because `vk_x` is linear in the inputs, this is exactly the 5-input statement with those
three fixed. `extract.mjs` checks every receipt both ways and requires the same verdict. The build pins one control
root, i.e. one RISC Zero recursion-circuit version. A RISC Zero upgrade means a new build and a new locking script,
and receipts for other control roots are rejected (tested below). `splitDigest(d) = (LE(d[0:16]), LE(d[16:32]))`, the
byte-swap-then-split of `RiscZeroGroth16Verifier.splitDigest`.

## Results (libauth BCH 2026 with the bench's OP_DEFINE patch, i.e. BCHN accounting; `node build-key.mjs <key>`)

| build (deployment) | code | fixture | n_q | unlocking per input (B) | tx score | op cost per input, standard / budget (margin) | consensus |
|---|--:|---|--:|---|--:|---|---|
| SP1 v5 (**verifier core, not deployable without application binding**) | 7,309 B | silvana-add | 114 | 9,325 / 9,264 / 8,796 | 27,639 | 7,043,210 / 7,492,800 (6.00%); 6,996,393 / 7,444,000 (6.01%); 6,644,905 / 7,069,600 (6.01%) | 7,008,906 / 6,962,089 / 6,612,009 |
| | | sparsity-tdx-gcp | 111 | 9,325 / 9,282 / 8,797 | 27,658 | 7,043,230 / 7,010,512 / 6,646,036 (6.00 / 6.01 / 6.00%) | accepted |
| | | pessina-solana-aa | 111 | 9,325 / 9,273 / 8,771 | 27,623 | 7,042,801 / 7,003,733 / 6,625,541 (6.01 / 6.01 / 6.02%) | accepted |
| RISC Zero (**verifier core, not deployable without application binding**) | 7,310 B | V5_0 receipt | 105 | 9,360 / 9,298 / 8,744 | 27,656 | 7,068,624 / 7,520,800 (6.01%); 7,022,552 / 7,471,200 (6.01%); 6,604,888 / 7,028,000 (6.02%) | 7,034,448 / 6,988,376 / 6,572,120 |
| SP1 v5 + covenant (example binding) | 7,374 B | silvana-add | 114 | 9,326 / 9,266 / 8,802 | 27,648 (+ PV output) | 6.01 / 6.02 / 6.02% | accepted |
| RISC Zero + covenant (example binding) | 7,557 B | V5_0 receipt | 105 | 9,362 / 9,344 / 8,754 | 27,714 (+ PV output) | 6.00 / 6.42 / 6.00% | accepted |

- **The plain builds take n0, n1 as free statement inputs and accept a valid proof of any program (any RISC Zero
  image id or journal) under the key.** `<key>.build.json` says so in its `deployment` field. Deploy only with an
  application binding such as `covenant.mjs` (section "How a covenant supplies the public inputs").
- Shape: 1 standard transaction, 3 inputs, all `P2SH32(R)` (35-byte locking, 65-byte redeem `R`), every unlocking
  ≤ 10,000 B, tx ≈ 27.6–27.8 kB (BCHN tx sizes in the node-check section below). The score is the bench model
  (unlockings + 3 × 35 + 149).
- Fillers are prover-sized to a 6% standard-mode margin, as in the reviewed build.
- **Liveness (argued, not measured on the real VKs).** Op cost depends on the witness (GT-GLS nibbles, `n_q`), not on
  the VK. The real-key code differs from the reviewed code only in 32-byte constants (7,309 / 7,310 B against
  7,310 B). The reviewed sweep's worst case (every nibble 15, `n_q` 132) was 7.06M per input, 12.1% below the
  10,000-byte cap budget. That forced case needs a proof minted with the trapdoor, which does not exist for a real
  VK, so it could not be re-run here. The real fixtures (n_q 105–114) cost within 0.1% of the densless fixture with the
  same `n_q` (7,043,210 against 7,050,430 standard for input 0 at n_q 114).

## Tests

All rejection tests are plain: tampered or mismatched inputs that a sound verifier must reject. No attack construction.

**`redteam-key.mjs <key>`** runs the reviewed bn-native-sound suite (`redteam-core.mjs` is a documented copy:
imports, build file, a second witness, an anti-no-op assert, plus sections 10 and 10b) against the real key:
- SP1 v5: **169 runs, 0 accepted**; RISC Zero: **173 runs, 0 accepted**; consensus and standard.
- Positive controls: every fixture, and a lattice-shifted GT-GLS witness of fixture 0.
- Section 10, the real-key public-input runs, use fixture 0's honest witness with the claim changed and `DG`, the
  challenges and the handovers recomputed. So the binding has to reject, not a hash check. These runs keep fixture 0's
  GT-GLS digits, so they stop at the first binding test: the digits do not decompose the new `n`. Section 10b reaches
  the checks after binding:

| runs (section 10 unless noted) | SP1 v5 | RISC Zero | first failing guard |
|---|--:|--:|---|
| wrong program: other real programVKeys (2) and programVKey last byte + 1 / image id flipped and the 4 older receipts' image ids, claim recomputed | 3 | 5 | input 2, `binding` |
| wrong public values: PV byte flipped, byte appended, the other fixtures' digests / journal flipped, appended (claim digest recomputed); RISC Zero: halves in big-endian order | 4 | 3 | input 2, `binding` |
| inputs ≥ r: `n0 = r`, `n1 = r`, both `+ r`, `n1 = 2^254`, `n1 + 2r`; SP1: unmasked `sha256(PV)` (≥ r) | 6 | 5 | input 0, `statement` (`< r`) |
| whole statements (A, B, C, n0, n1) of the other real proofs, and fixture 0's inputs with their proof points | 4 | 8 | input 0, `loop` (B-walk inverse-norm equation) |
| **10b (fix round): a false statement carried all the way through.** SP1: PV first byte flipped, `n1` = its digest. RISC Zero: journal first byte flipped, `(n0, n1)` = its claim-digest halves. The GT-GLS digits are recomputed by `glsDecompose` (so binding holds), the inverse-norm witnesses by `factorSchedule`, and the states by proveCore's recurrence. The residue root and quotient stay fixture 0's: none exists for a false statement. | 1 | 1 | inputs 0 and 1 **accept**; input 2 at `cleanup` (final identity fails), after `binding` passed |
| reviewed section 1: `n0 ± 1`, `n1 + 1`, `n0 = 0`, **swapped `n0, n1`**, another proof's `n0`, `n0` without recommitting | 7 | 7 | `binding` / `transcript` |
| reviewed section 1: `n + r` aliases, top bit, `2^256 − 1` | 4 | 4 | `statement` |
| reviewed sections 2–9: proof points (+1, +p aliases, identity, negation, B outside G2), GLS digits, residue root, states, inverse norms, quotient, handovers, staples, layout, filler, code, graph | 140 | 140 | as in bn-native-sound |

**`covenant-test.mjs <key>`** runs in covenant mode (see below). The control is accepted. Every rejection fires in
role 2's `covenant` section:
- SP1 v5: 12 runs, all rejected. They include **valid SP1 v5 proofs of other programs**
  (`sparsity-tdx-gcp`, `pessina-solana-aa`, with their own or the application's PV). The plain verifier accepts these,
  and the covenant rejects them on `n0 ≠ PROGRAM_VKEY`. The other runs: PV byte flipped (first, last), appended,
  truncated, missing, moved to output 1, non-minimal push header, its digest instead of the data.
- RISC Zero: 10 runs, all rejected (the same PV family, plus a whole-journal xor).
- Both (fix round): a covenant pinned to another program (`programVKey` or `IMAGE_ID` with its last byte xor 1),
  spent with the application's valid proof and PV. Rejected at `r2:covenant`; inputs 0 and 1 accept.

**Determinism and default build.** The `BN_VK_FIXTURES` switch in `math.mjs` and the `setCovenant` / `setOutputs`
hooks in `script.mjs` / `vm.mjs` are off by default. `bn-native-sound/build.mjs` reproduces code sha256
`75c780ae…78d7` unchanged. Every real-key build is built twice and compared byte for byte, and every fixture's 33
states and residue root equal the reviewed single-input SI-GLS prover's.

## Stock BCHN (node-check harness)

zk-verifier-bench `research/node-check` (branch `wip/real-keys`: `export-realkeys.mjs`, `run-t11.sh`; raw results
`raw/t11a-*`, `raw/t11b-*`, fix round `raw/t11c-*`). Stock BCHN 29.1.0, regtest, fresh localhost-only nodes, every node stopped afterwards.
148 workloads: 6 valid (4 plain fixtures, 2 covenant controls), 142 rejections (red-team public-input, proof-point and
staple runs, and every covenant rejection).

| workload | tx B | BCHN block | libauth cons/std | testmempoolaccept (`acceptnonstdtxn=0`) | Verify ms/tx (run 2) | worst input: op / budget, std + DEFINE |
|---|--:|---|---|---|--:|--:|
| SP1 v5 silvana-add | 27,534 | accept | accept/accept | allowed | 3.69 (noisy run, 45% spread) | 94.00% |
| SP1 v5 sparsity-tdx-gcp | 27,553 | accept | accept/accept | allowed | 3.48 | 94.00% |
| SP1 v5 pessina-solana-aa | 27,518 | accept | accept/accept | allowed | 3.50 | 93.99% |
| SP1 v5 covenant control | 27,608 | accept | accept/accept | allowed | 3.50 | 93.99% |
| RISC Zero V5_0 receipt | 27,551 | accept | accept/accept | allowed | 3.50 | 93.99% |
| RISC Zero covenant control | 27,631 | accept | accept/accept | allowed | 3.48 | 94.00% |
| reference: bn-native-sound (densless VK) | 27,026–28,082 | accept | accept/accept | fee only (1,000-sat inputs) | 3.44–3.53 (run 1) | 94.19–94.21% |

- Rejections: SP1 v5 70/70 and RISC Zero 72/72 rejected by BCHN block validation (`blk-bad-inputs`) and by libauth.
  The mempool script error is `mandatory-script-verify-flag-failed` for each. This comes from the **timing node's**
  testmempoolaccept (acceptnonstdtxn=1). The POLICY=1 node runs only the valid workloads; these are consensus
  failures, so policy cannot change them.
- Fix round (t11c, groth16_cashscript 8a9fa1c, fresh nodes, both stopped): 152 workloads. 6/6 valid accepted and
  allowed. SP1 v5 72/72 and RISC Zero 74/74 rejected (`blk-bad-inputs`). This adds each key's section-10b
  false-statement run (BCHN: false top stack element at the end, i.e. cleanup) and each key's covenant pinned to
  another program (BCHN: `OP_NUMEQUALVERIFY`). BCHN = libauth on every workload. Verify takes 3.49–3.50 ms per tx on
  a quiet machine (load average about 2.3).
- The machine was not idle (load average 5–11 from other processes). Run 1's RISC Zero median (8.2 ms, 200% spread)
  was noise; run 2 (valid workloads only, fresh node) gives 3.48–3.50 ms. All verdicts are identical in both runs.
- Fees as exported: 3 × 100,000-sat inputs and a 1,000-sat output, ≈ 10.9 sat/B. The policy node allowed all 6
  valid transactions as built.

## How a covenant supplies the public inputs

The plain verifier proves "(A, B, C, n0, n1) satisfies Groth16 for the baked VK" for **whatever n0, n1 the spender
writes into STMT**. Its outputs are unconstrained. Used as is, any valid SP1 v5 proof of *any* program unlocks it
(shown above: three different programs all pass). A covenant that releases value must derive `n0, n1` itself and
require equality. `covenant.mjs` adds this to role 2 (the role that owns `STMT` and runs the binding), right after
`n0, n1` are decoded and range-checked. That position is before every challenge-dependent step, and the code is pinned
by `K_code` like the rest:

```
SP1 v5:    <PROGRAM_VKEY> n0 NUMEQUALVERIFY                                   (32-byte constant in the code)
           PV  <- output 0 must be exactly OP_RETURN <push PV>, |PV| = PV_LEN
           SHA256(PV) REVERSEBYTES | split 31 | AND 0x1f | CAT | 0x00 CAT BIN2NUM  == n1   (sha256 & (2^253-1), LE)
RISC Zero: PV (the journal) from output 0 as above
           od = SHA256(sha256("risc0.Output") ‖ SHA256(PV) ‖ 0^32 ‖ 0x0200)
           cd = SHA256(sha256("risc0.ReceiptClaim") ‖ 0^32 ‖ IMAGE_ID ‖ SYSTEM_STATE_ZERO ‖ od ‖ 0^8 ‖ 0x0400)
           BIN2NUM(cd[16:32] ‖ 0x00) == n1;  BIN2NUM(cd[0:16] ‖ 0x00) == n0          (IMAGE_ID a constant)
```

Cost (input 2, standard): +65 B of code and +3.9k op for SP1, +247 B and +8.7k op for RISC Zero (three SHA-256 calls).
Margins stay at 6%.

- **Which program.** The program identity (`programVKey`, or `IMAGE_ID`) must be a constant of the covenant. If it
  were spender-supplied, any program's proof would do.
- **Which public values.** PV must be something the covenant can see and the application gives meaning to: here,
  output 0's data. A real application parses PV and enforces what it says (e.g. that output 1 pays the amount to the
  address PV names, that PV's state root equals the one in the covenant's NFT commitment). Hashing PV on-chain is
  what makes it the statement. Comparing against a spender-supplied digest would not.
- **Size.** PV must fit the carrier. A standard OP_RETURN holds ≤ 220 B of data, so `sparsity-tdx-gcp`'s 1,232 B
  journal would need another carrier (an input's unlocking data, with the owner layout pinned like `STMT`).
- **The RISC Zero claim digest is standard SHA-256.** risc0-ethereum's tagged-struct encoding of
  `ReceiptClaimLib.ok(...)` is plain EVM `sha256`, and OP_SHA256 reproduces it. The covenant control (on-chain digest
  = the digest the Groth16 proof binds) shows it on the real receipt. This settles, for the *Groth16 receipt* path, a
  question Track 10's design left [UNV]. It says nothing about the succinct-receipt hash suite.
- **Fixed graph.** The verifier requires exactly 3 inputs, all `P2SH32(R)`. Fees and released value come from those
  UTXOs (bn-native-sound "Open risks").

## Security notes (honest scope)

- This track shows that the **Groth16 wrapper** is verified soundly on BCH under the production keys. End-to-end
  security is the minimum of: BN254 pairing security (about 100–110 bits classical, not post-quantum); the trusted
  setups behind both keys; and the inner STARKs that the Groth16 circuits wrap. **A covenant
  that accepts these receipts is no more secure than the zkVM itself.** RISC Zero's succinct receipts are 97 bits
  *conjectured* (risc0 `zkp/src/lib.rs`) and about 48 bits provable in the Johnson-bound regime (EF soundcalc @ b325e30,
  `reports/risc0.md`; recomputed independently in Track 10 G0 as 48.22, bench `research/pq-stark/design-t10/params10.py`).
  For SP1, soundcalc's summary lists SP1 6.1.0 at 100 bits (unique-decoding regime); SP1 v5, the version pinned here,
  is not in that summary and was not assessed. Any application or site text that mentions RISC Zero receipts should
  carry the 48-bit provable figure.
- The verifier itself carries bn-native-sound's open risks unchanged (README there). The new code here is
  `covenant.mjs` (about 60 lines of script generation), the `math.mjs` switch and the two hooks. The Track 11 review
  passed them with minor findings only, and those were fixed in the fix round. The fix-round additions themselves
  (section 10b, the wrong-program covenant run, the extractor's text checks) have not been re-reviewed.
- The third-party SP1 fixtures prove that their programs ran. Their programs' semantics are irrelevant to this test,
  but an application must pin its own program.

## Reproduce

```sh
# groth16_cashscript, this directory (node_modules: zk-verifier-bench's, with the libauth OP_DEFINE patch)
node extract.mjs                                    # VKs + fixtures from upstream/, noble checks
node build-key.mjs sp1-v5 && node build-key.mjs risc0                         # writes <key>.build.json
node build-key.mjs sp1-v5 --covenant && node build-key.mjs risc0 --covenant   # writes <key>.cov.build.json
node redteam-key.mjs sp1-v5 sp1-v5.redteam.json sp1-v5.redteam-report.json    # ~1 min each
node redteam-key.mjs risc0 risc0.redteam.json risc0.redteam-report.json
node covenant-test.mjs sp1-v5 sp1-v5.cov.report.json && node covenant-test.mjs risc0 risc0.cov.report.json
# zk-verifier-bench research/node-check (BCHN): see README there, section "Track 11"
G16=<this checkout> node export-realkeys.mjs <data-dir> sp1-v5   (and risc0);  run-t11.sh NAME 9 7 11
```
