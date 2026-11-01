# Track 9 S0: Poseidon2-Gl-8 in CashVM

Research only (wip/pool). This folder holds the Poseidon2 permutation over Goldilocks, width 8, as BCH 2026 script.
It uses Plonky3's stock p3-goldilocks constants: `poseidon2-gl8-constants.json` (copied from bench
`research/pq-stark/design-t8`; Plonky3 0d803737). It also holds its differential test against p3-goldilocks and the
flush op-cost table that replaces the estimates in DESIGN-T9 §2.

## Files

| file | what |
|---|---|
| `p2gl8.mjs` | JS reference `permRef` (a transcription of air8_ref.py `perm`) and the script generator `genPerm` / `permCode` (8-lane output, or the 4-lane compress T∘P) |
| `test-p2.mjs` | acceptance: the test vector plus 1,000 random and 4 edge inputs, checking script = permRef = p3-goldilocks; also op-cost and plain rejections → `results/s0-p2.json` |
| `p3ref/` | a Rust binary that prints `default_goldilocks_poseidon2_8()` outputs for its stdin inputs (same Plonky3 pin and Cargo.lock as Track 8's prover) |
| `flush-fit.mjs` | a real flush worker input, with the most compressions that fit in it → `results/s0-flush.json` |
| `s0-bchn-export.mjs` | that input as node-check workloads, for BCHN → `results/s0-bchn-policy.jsonl` |
| `vm.mjs`, `lib/asm.mjs` | copied from Track 8 (libauth 3.1.0-next.8, unpatched) |

## Reproduce

```
CARGO_TARGET_DIR=$CACHE/target-p3ref nice cargo build --release --offline -j4 --manifest-path p3ref/Cargo.toml
node test-p2.mjs --cache $CACHE        # p3ref binary: $CACHE/target-p3ref/release/p2gl8-ref
node flush-fit.mjs
node s0-bchn-export.mjs $CACHE/s0-bchn/t9-s0.json
# bench checkout: OPCOST_DIR=<dir> POLICY=1 research/node-check/node.sh start t9s0p 9
#   npx tsx research/node-check/nc.ts policy --node t9s0p --src json:$CACHE/s0-bchn/t9-s0.json --out policy.jsonl
#   research/node-check/node.sh stop t9s0p
```

## How the script computes

- **Lanes are VM numbers, reduced lazily.** A VM MOD returns the truncated remainder, which keeps the residue. Every
  intermediate value is therefore congruent to the field value, even when it is unreduced or negative.
- **S-box.** `DUP DUP MUL OVER MUL <p> MOD DUP MUL MUL <p> MOD` (12 instructions). It reduces x³ before squaring it.
  This "mid" reduction costs two more instructions than a single final MOD, but it shrinks the operands of the last
  two multiplications and of the MOD. It saves 75K op-cost per permutation.
- **ME (the external layer).** Each input pair (x_i, x_{i+4}) becomes g = 2a + b and h = a + 2b in 8 stack
  instructions. Then Plonky3's 10-addition M4 chain runs on g and on h. Each output goes straight into the next round's
  round-constant add and S-box, in the order the next ME's pair phase wants.
- **MI (the internal layer, 22 partial rounds).**
  - The rule is y_i = S + d_i·x_i, with d = [−2, 1, 2, ½, 3, −½, −3, −4].
  - The small coefficients are signed VM numbers. The ±½ lanes are multiplied by a 63-bit constant and reduced every
    round. Lane 0 is reduced before its S-box.
  - The other lanes grow by less than 4 bits a round, to about 150 bits.
  - Lanes may be negative here. Before the final full rounds each lane gets `<p> MOD <rc + p> ADD`, which makes it
    positive. Every value after that is non-negative, and the outputs are reduced to [0, p).
- **Code.** Straight-line code with no OP_DEFINE inside: 7,681 B for the 8-lane output, 7,567 B for the compress.

## Results

**Correctness** (`results/s0-p2.json`):
- Test vector: PASS.
- 1,005 inputs (1,000 random plus 4 edge inputs plus the test vector): the script under libauth (consensus and
  standard), permRef and p3-goldilocks agree on all 1,005. The 4-lane compress agrees on all 1,005.
- 100 plain rejections (expected output + 1 or + p on one lane) are all rejected.

**op-cost per permutation** (libauth, between two markers):

| | op-cost | instructions | arithmetic cost | pushed bytes |
|---|--:|--:|--:|--:|
| permutation, 8 lanes out | **580,112–582,868** (mean 582,070) | 4,251 | 114.5–116.3K | 40.5–41.5K |
| compress T∘P, 4 lanes out | 571,221–573,974 (mean 573,181) | 4,173 | 114.0–115.8K | 39.9–40.9K |

- **BCHN-adjusted.** This is the same code with no DEFINE inside, so the BCHN figure equals the libauth figure per
  permutation. Packaged as one OP_DEFINE body, BCHN also charges the body bytes once per input: 7,567 B for the
  compress.
- **Variants measured on the test vector** (libauth op-cost, 8 lanes):

  | S-box | M4 | sum | op-cost |
  |---|---|---|--:|
  | plain | Σ form | picks | 673,166 |
  | plain | chain | 3DUP | 656,169 |
  | mid | Σ form | 3DUP | 588,756 |
  | **mid** | **chain** | **3DUP** | **580,603** (used) |

- **Gate (DESIGN §6 S0: more than 1.2M per permutation).** Not triggered: 0.58M is 48% of the gate, at the low end of
  the design's 0.5–1.0M planning range. k = 4 stays.

**Flush worker input, measured** (`results/s0-flush.json`, `flush-fit.mjs`):
- Shape: a P2S locking of 94 B: `DUP HASH256 <H(code)> EQUALVERIFY 0 DEFINE <n> TOALTSTACK BEGIN 0 INVOKE … UNTIL`,
  then a check of the 4-lane result.
- Unlocking: a pad, n siblings (4 lanes each), the start node and the compress code, exactly 10,000 B. The budget is
  then 8,032,800.
- The whole transaction is verified in the libauth BCH 2026 standard VM.
- **13 compressions fit in one 10 KB input.** n = 13 costs 7,508,795 op-cost in libauth and 7,516,362 BCHN-adjusted
  (93.6%). n = 14 is over the budget even in libauth (8,032,894).
- Per compression in the loop: 574,314. Fixed cost per input (code hash, DEFINE, loop entry, result check): 42,709 in
  libauth and 50,276 BCHN-adjusted.
- With raised per-input limits (one input with 99,800 B unlocking, r100 regime): 138 compressions, at 99.4%.

**BCHN v29.1.0 regtest** (`results/s0-bchn-policy.jsonl`): one fresh POLICY=1 node (acceptnonstdtxn=0) under
work/pool/bchn, stopped afterwards.

| workload | testmempoolaccept | mined | bench libauth (DEFINE-charging) std op-cost / budget |
|---|---|---|---|
| fit13 (n = 13, 10,000 B) | **allowed** | yes | 7,516,362 / 8,032,800 (= the BCHN-adjusted figure above, exactly) |
| probe13 (n = 13, unlocking 9,345 B: budget sits between libauth alone and libauth + DEFINE) | **rejected**: VM cost limit exceeded | yes, on the consensus basis (hash iterations at 64), as node-check found | 7,508,810 / 7,508,800 |

over14 was exported as a reject, but nc.ts policy mode replays only valid workloads and DEFINE probes, so BCHN did not
run it. libauth rejects it.

**Flush op-cost table** (it replaces DESIGN-T9 §2's estimates):
- Compressions per flush = (2^k − 1) for the subtree plus (30 − k) for the path.
- op-cost = compressions × 574,314, plus 50,276 per input (BCHN-adjusted).
- Inputs needed today = ⌈compressions / 13⌉, each a padded 10 KB input.

| flush size 2^k | compressions | op-cost (BCHN-adj.) | 10 KB inputs today (bytes) | compressions per deposit | 100 KB inputs |
|--:|--:|--:|--:|--:|--:|
| 1 (per deposit) | 30 | 17.38M | 3 (30 KB) | 30 | 1 |
| 4 | 31 | 17.95M | 3 (30 KB) | 7.75 | 1 |
| 8 | 34 | 19.68M | 3 (30 KB) | 4.25 | 1 |
| **16 (k = 4, chosen)** | **41** | **23.75M** | **4 (40 KB)** | **2.56** | 1 |
| 32 | 56 | 32.41M | 5 (50 KB) | 1.75 | 1 |
| 64 | 87 | 50.32M | 7 (70 KB) | 1.36 | 1 |

The design estimated 20–41M and 3–5 inputs for k = 4. The measurement is 23.75M and 4 inputs.

**Not included in the table, and still open:**
- The rest of a real flush, which is S4:
  - the leaf lanes' < p checks;
  - re-deriving the queue hash (2^k SHA-256);
  - the depHash/frontier check (SHA-256 over about 964 B);
  - the ring update in histRoot (4 levels, twice);
  - the D/W covenant checks;
  - passing intermediate nodes between the worker inputs (pushes checked by their owner, as in a′).

  None of these involves Poseidon2. I estimate them at well under 1M in total; that is not measured. The k = 4 plan has
  4 × 13 − 41 = 11 spare compression slots, about 6.3M.
- Sibling and leaf lanes taken from unlocking data are not range-checked in this measurement input. The real flush must
  check them < p.
- The code is 7.6 KB of straight-line code. It shares the 10 KB unlocking with the data, which is ample for a flush
  input (13 × 36 B of siblings). A compact variant (a round loop over a constants table) would shrink the code but cost
  roughly +5% op-cost. It was not built.
