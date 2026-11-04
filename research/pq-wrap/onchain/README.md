# Track 8 S4: layout (b) for M1 — one 100 KB input

Research only. This folder holds the CashVM (BCH 2026) verifier generator for Plonky3 `p3-batch-stark` proofs in
p3b-v1 (`../prover/FORMAT.md`), built for the M1 statement (Merkle membership at depth 30 plus a nullifier, AIR-SPEC
§3) under parameter set Z128 with Merkle cap 0 (DESIGN-T8 §5, layout b). Track 5 files are untouched; its generator
was copied here and adapted, and its generic model functions are imported read-only.

## What the generator does

- **Verifying key → script.** `model.mjs` `vkxFromVector` takes VK data only (via S3's `vkFromVector`, which
  re-derives the PCS layout, cap lengths and FRI schedule and requires them to equal the vector's `shape`). It also
  asserts the VK-time properties the per-proof check relies on: strict FRI height and the hiding budget. Supported:
  one table, one height, no preprocessed columns, no lookups, ood PoW 0, cap 0 (S5–S7 extend this).
- **Transcript.** As Track 5 (a chain of SHA-256 digests), with batch-stark's prefix: the batch domain-separator
  seed and degree_bits as an extension element are one constant, followed by the trace cap and the 12 public values.
- **Statement layer** (AIR-SPEC §3.1):
  - ROOT is a constant of the script (the pool's root; Track 9 would read it from covenant state).
  - NF is a witness item, 4 × u64 LE, each lane checked < p.
  - CTX is computed by the script from the spending transaction's outputs (`ctx.mjs`; serialization in
    `../prover/FORMAT.md` "CTX serialization"). The prover takes the hash as `m1@LEAF@WSEED@<hash>`.
- **AIR at ζ.** The exported constraint DAG (551 nodes, 53 constraints) runs in a small byte-code interpreter
  (`dagProgram` in `gen.mjs`): the DAG becomes a constant program of 2.1 KB, executed in 40-byte chunks by OP_INVOKE
  dispatch (op ids 100–113). Multi-use nodes are computed once into stack registers. Selectors are multiplied through
  by (ζ−1)(ζ−g⁻¹), so no inversion is needed. Periodic columns (11, period 32) use a 32-step loop with the
  coefficients packed at run time into 17-byte slots; the quotient is recomposed with prefix/suffix products.
- **DEEP, FRI, Merkle.** As Track 5: one hint per query, the packed dot products, the arity-8 fold, the group-packed
  final polynomial and the LIFO Merkle records. α′ powers, A_z and the packed row keys come from one loop over the
  94 opened values. Extension multiplication is a packed schoolbook product (17-byte slots).

## Files

| file | what |
|---|---|
| `model.mjs` | the on-chain algorithm in JS, and the witness encoder `encodeB` |
| `gen.mjs` | the generator (`build`, `makeGen`, `dagProgram`) |
| `ctx.mjs` | CTX: the script block and the JS serialization |
| `layout-b.mjs` | the program (VK + ROOT) and the spend (witness, unlocking, spending transaction) |
| `vm.mjs`, `lib/` | libauth 3.1.0-next.8 VMs: `bch` (today's rules), `r100` (one 100 KB input), `spec` (bch-spec), `loose` |
| `gen-statements.mjs` | transaction-bound statements: outputs → CTX → prover |
| `model-agree.mjs` | model vs `../verifier/verify-batch.mjs`, including transcript bytes |
| `grade-b.mjs`, `profile-b.mjs` | regimes, bytes and op-cost; per-phase profile against the S0 model |
| `test-b.mjs`, `test-ctx.mjs` | the accept/reject sweep; the CTX block against its definition |
| `gen-s4.sh` | everything, end to end |
| `results/` | outputs (see below) |

## Reproduce

```
CARGO_TARGET_DIR=<cache>/target S4_CACHE=<cache>/s4 S3_CACHE=<cache>/s3 ./gen-s4.sh
```

The S3 case files (`$S3_CACHE/cases`) come from `../verifier/gen-s3.sh`.

## Results

See PROGRESS.md (S4 entry) and `results/` for the numbers: `grade-b.json`, `profile-b.json`, `test-b.json`,
`test-b-harness.json`, `model-agree.txt`, `test-ctx.txt`.

# Track 8 S5 + S6: multi-height, LogUp and layout b2 (two inputs)

The generalized generator `genn.mjs` (model `modeln.mjs`) covers what S4 left out: N tables, several LDE heights,
preprocessed columns, LogUp, extension-valued constraints and non-ZK sets. Merkle cap 0 only (cap > 0 is S7). S4's files
(`gen.mjs`, `model.mjs`, `layout-b.mjs`, ...) are unchanged; S4's M1 results still stand.

## What is new on chain

- **Transcript:** every instance's degree_bits in the batch prefix; the preprocessed cap (a VK constant) after the
  public values; lookup PoW, lookup alpha/beta, then permutation cap ‖ terminals before alpha.
- **AIR, per instance:** its own n, selectors, periodic columns, quotient chunks and constraint DAG. New DAG leaves:
  `pre`, `perm` (ext elements recomposed from 3 base-flattened openings), `challenge` (bus prefix = alpha + (k+1)·beta^maxW,
  and beta), `perm_value` (the terminal), `ext_const`. The terminals must sum to zero. VK-time checks: strict FRI height,
  hiding budget, multiplicity height bound (Σ count_weight·n < p).
- **Opened values** stay a byte string. The AIR extracts only the values it reads, and the alpha' loops read each
  height's claims sequentially from a per-height byte string. This keeps the stack under 1,000 items for M2
  (212 opened values).
- **DEEP:** opening points are ζ and ζ·g_i for each distinct trace height. Each LDE height h has its own alpha' ladder,
  its own packed row keys, and x_h = 7·xo^(2^(logH−h)). There is one inverse hint per height per query:
  - T_top = 1/(s0·∏N_pt(x));
  - T_h = 1/∏N_pt(x_h).
- **FRI roll-ins:** after the fold that lands on height h, folded += β^(arity)·ro_h.
- **Mixed-height Merkle trees: per-query bottom paths instead of INJ records.** This is a deviation from DESIGN §7's
  wording.
  - B is the deepest injection level of a round. For each query, the query function walks the bottom B levels from
    B siblings in that query's blob: node = H(H(l‖r) ‖ H(injected rows)).
  - The level-B node is the leaf of the LIFO record tree, which has depth top − B.
  - With 24 queries in 2^20 leaves, bottom levels practically never share nodes, so this costs no proof bytes. No
    injection op is needed in the records, so nothing has to enforce that an INJ record is placed correctly.
  - Queries that meet at or below level B are caught by DUPM (equal upper-leaf digests). DUPM therefore also enforces
    consistent injected rows.
- **Statement:**
  - `pool` (M1/M2): ROOT is a constant, NF a witness item with lanes < p, CTX comes from the transaction (or is a witness
    item in the harness).
  - `witness` (the Plonky3 AIRs): every public value is a witness item, each < p.
  - The per-instance layout of the public values is VK data.

## Layout b2 (DESIGN §5): two P2S inputs sharing one code library

- **lib:** all function bodies, plus MAIN0 and MAIN1, as records [id][len 3 B][body].
  - The transcript, the DEEP/FRI constants and the query function are shared by both mains. They are compiled once over
    a canonical top-of-stack region.
  - M1 lib: 19,468 B. M2 lib: 27,759 B.
- **Input 0:**
  - Unlocking: lib (first push), its query blobs and records, then the PT and statement pushes.
  - Locking (P2S, 63 B): `DEPTH 1SUB ROLL <H_lib> OVER HASH256 OVER EQUALVERIFY TOALTSTACK <define loop> <MAIN0> INVOKE`.
  - MAIN0 pins the transaction: exactly 2 inputs, INPUTINDEX = 0, and input 1's locking = loader template(H_lib).
  - It runs the statement, transcript, AIR, constants and queries [0, QA), then their Merkle paths.
- **Input 1:**
  - Unlocking: its query blobs and records only.
  - Locking (P2S loader, 84 B): it reads input 0's unlocking with OP_INPUTBYTECODE, takes lib (PUSHDATA2, first push) and
    the tail (the PT and statement pushes, fixed length), checks HASH256(lib) = H_lib, defines lib and invokes MAIN1.
  - MAIN1 pins 2 inputs, INPUTINDEX = 1 and input 0's locking = template(H_lib). It checks every push prefix of the tail,
    re-derives the transcript and the DEEP/FRI constants, then runs queries [QA, Q) and their Merkle paths.
- **No cycle:** both lockings contain H_lib, and the mains contain only the templates around it.
- **Split:** QA = 12 for M1 (24 queries), 9 for M2.

## Results (`gen-s5.sh`; results/)

- **Model agreement** (`model-agree-n.txt`): 17,911 case runs, 0 disagreements.
  - Each case runs both unsplit (b) and split as b2. Every S3 cap-0 case file is included: M1, M2, and Plonky3's
    single_instance, three_instances_mixed_sizes, mixed_preprocessed, both_lookups_zk and periodic_air_zk under Z128,
    Z128g, Z128_zk0, n1024 and PT.
  - Valid proofs: every SHA-256 transcript input is byte-identical to the reference's.
  - 5 files are refused by the generator: the ood-PoW VK variants, which are not supported (a reject).
- **b2 sweep on the S3 case files**, harness statement (`test-b2-m2p3.json`, `test-b2-m1.json`). Every case needs the
  same verdict from the script (both inputs), the model and verify-batch.mjs.
  - M2 and Plonky3: 63 files, 8,252 cases, 0 unexpected. The 3 PT files run in layout b, because input 1 of b2 would be
    too small for its density budget at Q = 2.
  - M1: 36 files, 2,558 cases, 0 unexpected.
  - Cases outside the comparison: public values ≥ 2^64 are n/a. Malformed-by-length proofs are refused by the encoder and
    rejected on chain, except one truncated zero byte that reproduces the valid witness.
- **Layout family** on every valid proof:
  - the library flipped or truncated;
  - query blobs or records swapped across the inputs;
  - duplicated or missing items in either input;
  - hint T_top or T_h + 1, + p, or taken from another query;
  - bottom (injection-path) siblings flipped or swapped between queries;
  - injected rows flipped or moved to another query;
  - a third input;
  - the inputs swapped;
  - another locking on either input;
  - input 1 = a copy of input 0;
  - input 1's data taken from a second-seed proof. Its control (that proof alone) verifies.
  - All of these are rejected.
- **Production** (`test-b2-prod.json`): the 24 M1 and 8 M2 transaction-bound statements plus second-seed proofs, with
  CTX from the spending transaction. 36 files, 1,030 cases, 0 unexpected:
  - 36 valid;
  - 144 tx (changed value, recipient, extra output, token);
  - 36 root;
  - 814 layout.
- **Regimes** (`grade-b2.json`; op-cost is BCHN-adjusted = libauth + the OP_DEFINE body bytes of the whole library,
  per input):

| | M1 (24) | M2 (8) |
|---|---|---|
| proof | 71,344–74,928 B | 121,350–124,710 B |
| unlocking in0 + in1 | 61,919–63,555 + 33,335–35,245 B | 79,778–82,436 + 75,783–77,391 B |
| transaction | **96,153–98,321 B** (≤ 100,000) | 156,384–159,749 B |
| op-cost in0 / in1 | 27.16–27.38M / 19.56–19.82M | 35.20–35.52M / 33.20–33.51M |
| % of budget (r100) in0 / in1 | 53.8–54.8% / 70.2–73.3% | 53.8–55.1% / 54.1–54.8% |
| % of budget (bch-spec) | 46.5–47.2% / 54.8–56.4% | 48–49% / 47.9–48.4% |
| r100 (both inputs, std + cons) | 24/24 | 8/8 |
| whole tx, tx limit 100,000 B | 24/24 | 0/8 (tx size) |
| whole tx, tx limit raised to 200,000 B | 24/24 | 8/8 |
| bch-spec inputs / whole tx | 24/24 / 24/24 | 8/8 / 0/8 (tx size) |
| today's rules | 0/24 (unlocking > 10,000 B) | 0/8 |

**Standardness limits each layout needs:**
- M1 b2 needs raised per-input limits: unlocking, bytecode and stack item size up to 100,000 B. OP_INPUTBYTECODE
  pushes input 0's unlocking as one stack item, and MAIN0 is over 10,000 B. It does not need a raised transaction size.
- M2 b2 needs both the raised per-input limits and a raised transaction size (about 160 KB).

**Per-phase op-cost** (`profile-b2.txt`, libauth, markers subtracted):

| | entry | transcript | AIR | constants | queries | Merkle |
|---|--:|--:|--:|--:|--:|--:|
| M1 input 0 | 2.76M | 0.18M | 7.85M | 4.68M | 8.04M (12 × 0.67M) | 3.80M |
| M1 input 1 | 3.08M | 0.18M | — | 4.68M | 8.05M (12 × 0.67M) | 3.78M |
| M2 input 0 | 3.89M | 0.20M | 10.44M | 8.18M | 8.44M (9 × 0.94M) | 4.04M |
| M2 input 1 | 4.28M | 0.20M | — | 8.19M | 14.06M (15 × 0.94M) | 6.45M |

- **Entry** is mostly the define loop. It SPLITs the remaining library once per function, so its cost grows
  quadratically with the library size. Input 1 also pushes input 0's whole unlocking with OP_INPUTBYTECODE.
  - Splitting the library from its end, or in chunks, would save roughly 1–2M per input. This was not done; every input
    is already at or below 73% of its budget.
- **Input 1** pays for the DEEP/FRI constants again (4.7M for M1, 8.2M for M2). This is the main cost of the split.
- **b2 versus b for M1:** b2's two inputs total 47.0M against S4 layout b's 35.8M, and 97.4 KB against 93.7 KB.

**Not covered or open:**
- Merkle cap > 0 (S7).
- ood PoW > 0: the generator refuses it.
- PT/PTZ-sized proofs (Q = 2) do not fit b2's density budget on input 1, so they run in layout b.
- For Plonky3's own test AIRs, the preprocessed commitment is salted with the prover's RNG, so a second-seed proof is a
  proof for another VK. The layout control runs it under its own VK. The M1/M2 statement VKs use the published
  SETUP_SEED and do not have this issue.

# Track 8 S7: layout a′ for M1 under today's standard rules (Z128, Merkle cap 5)

Files: `modela.mjs` (model, encoder: full paths below the cap, TBL, partial accumulators), `gena.mjs` (generator),
`layouta.mjs` (plans, witnesses, transactions, NFT thread), `grade-a.mjs`, `profile-a.mjs`, `test-a.mjs`, `dbg-a.mjs`,
`gen-s7.sh`. S4–S6 output is unchanged: `vkxN` takes cap > 0 only with `allowCap`, and `dagProgram` takes an
optional constraint range. At S7 the M1 b2 library hash was unchanged (553a3cfc…); the S8b residue fix changed it
(see the S8b section below).

**Layout.** Every input has the same P2S locking R (118 B). R reads the two code blobs from the CODE inputs (first
push, header checked), checks each blob's SHA-256, defines and invokes them. The last blob pins the input graph: the
input count per transaction kind, and every input's locking equal to R. It then invokes the role for (kind, input
index):

| input | role | pushes | work |
|---|---|---|---|
| 0 | HEAD | caps (3 × 32 digests), OOD, PoW, FRI cap, NF, CTXW | statement (NF < p; in the final tx, CTXW = CTX of the outputs), transcript and every PoW check; kind 0: Σ_j ACC_j α^(C−hi_j) = q·Z_H·Dd^maxScale; NFT thread |
| 1, 2 | CODE | code blob, ACC_j | kind 0: transcript again, AIR at ζ for constraint range j (53 constraints split [0,21) / [21,53)), checks its own ACC_j |
| 3 | FIN | final polynomial, TBL (312 B) | transcript, DEEP point constants, A sums; checks its own TBL (query indices, α′, β, point constants, A sums) |
| 4.. | QRY | 3 × (L_q, full path_q) | α′ ladder and row keys, fold columns, final polynomial, 3 queries, full paths up to the cap entry |

- Values cross inputs only as pushes that the owning input checks: ACC by CODE, TBL by FIN, CTXW by the final HEAD.
  Readers parse them from OP_INPUTBYTECODE with exact push headers.
- Plans with more than one transaction use Track 5's NFT thread. Kind 0 spends the minting baton (returned to R) and
  mints immutable NFTs with commitment k ‖ SHA256(tag ‖ G ‖ k). G is the final transcript digest, so it binds the
  proof and ROOT, NF, CTX. Transaction k spends and burns its NFT. CTX is the final transaction's outputs.
- Design choice: QRY inputs recompute the α′ ladder (1.40M op-cost each). Publishing it would cost 2.3 KB, and bytes
  are the binding limit here.

**Results** (24 transaction-bound statements, the S4 statements under Z128 cap 5; `results/grade-a.*`). Sizes are
the same for every statement, because full paths have fixed size:

| plan | transactions | inputs | bytes | every input std + cons | whole-tx verify | bch-spec |
|---|--:|--:|---|---|---|---|
| **1 transaction (stretch)** | 1 | 12 | **98,690** | 24/24 | 24/24 | 24/24 |
| 2-transaction baseline | 2 | 11 + 5 | 91,059 + 40,497 = 131,556 | 24/24 | 24/24 | 24/24 |

Op-cost per input, BCHN-adjusted (libauth + 36,844 B of OP_DEFINE bodies), 1-transaction plan:

| role | unlocking | op-cost | % of budget |
|---|--:|--:|--:|
| HEAD | 6,454 | 1.31M | 25.2% |
| CODE1 | 9,322 | 5.47M | 73.1% |
| CODE2 | 9,316 | 4.98M | 66.6% |
| FIN | 6,462 | 3.76M | 72.4% |
| QRY (×8) | 8,322 | 6.07–6.09M | **90.7–91.0%** |
| total | | 64.1–64.2M | |

- The 1-transaction plan fits at Z128 itself: Q = 24, query PoW 24, no parameter change. The design's Z128-s stretch
  (Q = 23, query PoW 28) is not needed. The margin is 1,310 B.
- The design modelled 101–103 KB; the difference is the 312 B TBL in place of a 2.3 KB α′ table.
- The binding limit on the QRY inputs is op-cost: about 91% of their budget.
- QRY profile (`profile-a.txt`): entry 0.32M, row keys 1.40M, final-polynomial unpack 1.26M, three queries with full
  paths about 2.95M.
- CODE profile: AIR pre-pass 1.51M (periodic columns, selectors), DAG range 3.38M / 2.89M.
- FIN profile: A sums 3.11M.
- Policy controls: libauth standard rejects an unlocking of 10,025 B, a 100,118 B transaction and a 208 B output
  locking, so these checks are live.

**Sweeps** (`results/test-a-*.json`): 0 unexpected verdicts in all three. Every case needs the same verdict from the
chain, the a′ model and the S3 reference (the last two only for proof-level cases).

| sweep | cases |
|---|--:|
| production, 1 transaction | 3,765 |
| production, 2 transactions | 4,181 |
| harness (S3 M1 cap-5 case files, CTX as a witness item) | 2,387 |

- **Production families** add:
  - constants (650): every TBL field, a TBL index replaced by another valid index, TBL ±1 byte, ACC flips and swap,
    ACC_1 + 1 with ACC_2 compensated so that HEAD's sum still holds, CTXW, NF;
  - input (598): HEAD/FIN data, hint T, rows, paths, query swaps, missing or extra pushes;
  - graph (208): code blob flipped or truncated, input order, another locking, extra or missing input;
  - mix (130 / 156): HEAD, FIN, ACC or a QRY input from another proof or statement, and tx1 replayed from another
    proof with this proof's NFT;
  - tx (104), root (26);
  - thread (390, 2 transactions): an NFT of another G, k = 2, another category, a mutable NFT, no NFT, the NFT passed
    on, a token on another input, changed outputs, a tx0 QRY in tx1; baton not returned or to another locking, a wrong
    or mutable minted NFT, an extra mint, no baton.
- **Encoder-only:** 55 malformed-by-length cases (trailing bytes, a sibling count + 1 at the end) give the valid
  proof's full-path witness, so the script accepts them, as in Track 5's layout a. A production encoder refuses them.
- **Out of the generator:** the cap-6 and ood-PoW VK variants (the generator refuses them, counted as rejects) and
  cap-0 proofs under their own VK (layout a′ is the cap-5 deployment).

**Notes for S8:**
- Chain lemma: R authenticates the code; the graph is pinned; each published value is checked by its owner and parsed
  exactly by its readers; the HEAD identity is the S4 constraint sum split into ranges; full paths end at cap entries
  of caps observed whole in the transcript.
- 2 transactions: tx0 alone can be valid and mint an NFT for a proof that tx1 would reject (a partial check); the
  effect, the outputs bound by CTX, is only in tx1.
- Assumption: the minting baton is created at deployment under R.
- Replaying one valid proof in two final transactions is the nullifier set's job (Track 9), as for layouts b and b2.

# Track 8 S8b: interpreter residue fix and the post-fix re-run

test-b.json, test-b2-prod.json, test-ctx.txt and model-agree-n.txt were regenerated post-fix with identical output (logs dated after 12d47d4), so git shows no change for them.

The constraint interpreter's `D_SUB`, `D_SUBL`, `D_RSUBL` and `D_NEG` now add 2p (not p) before `MOD`, in `gen.mjs`
and `genn.mjs`, so every op is congruent mod p for raw proof lanes in [0, 2^64) (SOUNDNESS-T8 §9.1, `s8-arith.mjs`:
69 cases, 0 wrong on the fixed bodies). Every script changed, so every S4–S7 node step was re-run on the cached
proofs (`rerun-s8b.sh`; the first run stopped inside test-b2-m2p3 when the machine went down, and
`rerun-s8b-resume.sh` ran the rest on 2026-11-01). All result files in `results/` are post-fix.

**Verdicts: 0 unexpected in every suite.** Case totals include cases that never ran on chain:

| suite | cases | not run on chain | encoder-only | files skipped |
|---|--:|--:|--:|--:|
| S4 b production / harness | 2,929 / 3,309 | 0 / 33 | 0 / 1 | 0 / 2 |
| S5/S6 b2 M2 + Plonky3 / M1 harness / production | 8,252 / 2,558 / 1,030 | 59 / 35 / 0 | 0 / 1 / 0 | 3 / 2 / 0 |
| S7 a′ 1 tx / 2 tx / harness | 3,765 / 4,181 / 2,387 | 0 / 0 / 35 | 55 / 55 / 69 | 2 / 2 / 2 |

- *Not run on chain:* the statement layer or the generator refuses the case before a script exists (statement
  family: CTX lane ≥ 2^56, another per-instance public-value layout, non-canonical ROOT; vk_variant: VKs the generator
  refuses). The verdict (reject) is right, but these are not on-chain rejections.
- *Encoder-only:* malformed-by-length proofs that the reference rejects and the encoder refuses, whose on-chain
  witness is the valid proof's, so the script accepts it.
- *Files skipped:* the cap+1 and ood-PoW = 1 VK variants (out of the generators' scope) and, in a′ production, the two
  cap-0 vectors (a′ is the cap-5 deployment).

**Post-fix figures** (bytes are identical to pre-fix; op-cost moved by a few hundred per input that runs the
interpreter; every budget percentage is unchanged to 0.1 point):
- Layout b (24): BCHN-adjusted op-cost 35,528,878–36,043,226 (mean 35,833,248), 47.4–48.6% of the r100 budget;
  24/24 under r100 and bch-spec; 0/24 today.
- b2 M1 (24): in0 27.16–27.38M, in1 19.56–19.82M; b2 M2 (8): in0 35.20–35.52M, in1 33.20–33.51M (`grade-b2.txt`).
  M1 b2 library 19,468 B, HASH256 for statement 0 = `95630cefe3d0c46347a21c43c2680201f9c216d07a22c0f8f95ef679c52726b9`
  (pre-fix 553a3cfc…; the hash also depends on the statement's ROOT). M2 library 27,759 B.
- a′ (24): 1 transaction 98,690 B, total 64,092,057–64,207,225 BCHN-adjusted; CODE1 ≤ 5,475,822 (73.1%); QRY
  6,066,097–6,088,611 (90.67–91.01%). 2 transactions 131,556 B, 68.90–69.03M.
- `grade-b.mjs` now gates on max(std, cons) + OP_DEFINE body bytes, as `grade-b2.mjs` and `grade-a.mjs` already did
  (no verdict changed).

**Against the S0 model (unchanged by the fix, stated here for REPORT):**
- Op-cost: layout b is +26.8% over params8's 28.26M, outside the ±15% acceptance band. The miss is the fixed part:
  the AIR at ζ costs 7.85–8.03M against an assumed 0.6M.
- Bytes agree with S0 within about +0.5% to +1.3% once the real code sizes are put in the model (figures from the
  S8b measurement review's re-modelling; layout b unlocking
  mean 93,612 vs 93,181 at redeem 19,024; b2 M1 tx 97,417 vs about 97,591 at lib 19,468; b2 M2 tx 158,006 vs about
  155,926 at lib 27,759; a′ 98,690 vs 98.5–101.5 KB). All are above S0's modelled ranges because the code came out
  larger than the 13–18 KB (b), 18–24 KB (b2) and 7.5–9 KB (a′) assumed.

# Track 10 G2: layout-review optimizations of layout a′ (measured)

Research only, nothing deployed. These are the candidates from the pq-merkle-bytes layout review
(zk-verifier-bench `research/pq-wrap/layout-review/PLAN.md`), built behind `--opt` in `grade-a2.mjs`, `profile-a2.mjs`
and `test-a2.mjs` (`gena.mjs` `plan.opt`). Without `--opt` the generator is the baseline: its grade is reproduced byte
for byte (`results/g2/grade-a2-cap0.log`).

| `--opt` | candidate | what changes |
|---|---|---|
| `sib` | 1 | one 32 B push per Merkle sibling, fetched by `DEPTH 1SUB ROLL` with `SIZE 32`; replaces re-pushing the PTH blob at every level |
| `lad` | 3 | FIN publishes LAD = α′^0..α′^93 (2,256 B) and checks it against the powers it walks for the A sums; QRY only packs the row keys from it |
| `state` | 2 | tx0 (R0) mints NFT k = k ‖ SHA256(STAG ‖ k ‖ HS), HS = SHA256(ROOTS‖FROOTS‖FIN‖TBL‖LAD‖NF‖CTXW‖G), locked to R1; later txs under R1 have STATE + one library blob + QRY inputs |
| `cap=c` | 5 | LAYER (2^c nodes per tree at level c) in tx0's HEAD and in a TOP input (input 2) of R1 txs, checked against the roots; paths stop at level c |

All figures below are MEASURED on `tw2x18x16-g2-0` cap 0 (libauth BCH 2026 standard and consensus, BCHN-adjusted
op-cost, grade target 0.93). `test-a2 --layout` was run on both cap-0 case files.

| plan | txs | inputs | bytes | QRY input | pad | q/input | max % | test-a2 |
|---|---|---|---|---|---|---|---|---|
| baseline | 7 | 78 | 639,351 | 8,587 | 2,170 | 1 | 92.72 | 286 cases, 0 unexpected |
| `sib` | 6 | 73 | 561,732 | 7,726 | 1,176 | 1 | 92.62 | 310, 0 |
| `sib,lad` | 5 | 68 | 480,380 | 6,548 | 0 | 1 | 86.36 | 332, 0 |
| `sib,lad,state` | 4 | 54 | 377,245 | 6,548 | 0 | 1 | 87.27 | 390, 0 |
| `sib,lad,state,cap=3` | 4 | 57 | 355,817 | 5,855 | 0 | 1 | 91.62 | 426, 0 |

- **sib:** the QRY "queries" phase drops from 1,059,906 to 408,559 op. The review modelled 0.42M and 7 txs at about
  602 KB; it predicted 6 txs would miss by about 190 B. In fact the 8-QRY final tx is 99,841 B, so 6 txs fit.
- **lad:** the QRY row-keys phase (PACK) drops from 2,082,864 to 657,032 op. That is above the PLAN's 0.48M zero-pad
  threshold but below its 0.7M 5-tx threshold. With `sib` the pads still go to 0: QRY is byte-bound at 82%.
  FIN's a-sums phase rises from 4,560,469 to 5,339,455 op, and FIN is 8,918 B.
- **state:**
  - The R1 query-only library blob is 9,077 B (66 functions, redeem 59 B). The review estimated 8.6–9.3 KB.
  - STATE is 9,244 B at 3.1% of its budget. LIB is at 1.9%, and R1 QRY inputs are at 78.5%.
  - HEAD's thread phase rises from 22,047 to 101,800 op, which puts HEAD at 87.27%.
  - The review modelled 6 txs / about 491 KB for `state` alone, and 4 txs / about 372 KB together with the ladder.
- **cap=c sweep (with `sib,lad,state`):**
  - c=1: 370,149 B; c=2: 362,088 B; c=3: 355,817 B.
  - c=4: 365,576 B, because QRY is op-bound again and needs a 282 B pad.
  - c=5: no plan, because HEAD with the 7,168 B layer is 10,855 B.
  - In R1 txs the layer cannot share STATE's input (11,039 B > 10,000), so it gets its own TOP input.
- **per=2 still has no plan** with any of these. At `sib` the QRY op fits (7.37M), but the unlocking is 13,095 B
  (11,709 B at cap 3).
- The second vector (g2-1) gives the same tx counts.

Reproduce (each grade takes about 20 s, test-a2 about 75 s):
```
nice -n 19 node grade-a2.mjs --nc 3 --opt sib,lad,state,cap=3 --out results/g2/grade-a2-opt1235.json <vec0>/tw2x18x16-g2-0-*cap0.json
nice -n 19 node test-a2.mjs --layout --nc 3 --opt sib,lad,state,cap=3 <cases0>/tw2x18x16-g2-{0,1}-*cap0.json
```
Results are in `results/g2/{grade,profile,test}-a2-opt{1,12,123,1235}.*`, `grade-a2-opt1{,2}-per2.*`,
`grade-a2-opt1235-csweep.log` and `profile-a2-base.*`.

**Soundness and seam notes (not reviewed):**
- *sib:*
  - The compressions, left/right order and root comparison are the same as before.
  - The item count is fixed by the QRY `DEPTH` check (1 + siblings per query), and each sibling is `SIZE 32`.
  - There is no new cross-input read.
  - The 'sib' test family covers wrong, missing, extra, swapped, resized and merged siblings.
- *lad:*
  - FIN owns LAD the way it owns TBL: it serializes the powers of the α′ it derived (canonical limbs, `P MOD`) and
    `EQUALVERIFY`s its own push.
  - QRY reads LAD only from FIN's input, through the checked parse. Every height's ladder is a prefix of LAD.
  - A non-canonical limb with the same value mod p is rejected (test family 'lad').
- *state:* behaviour change. Later txs no longer re-derive the transcript; they rest on tx0's HEAD and FIN plus
  SHA-256 collision resistance of HS.
  - Every preimage field has a fixed length, and k appears both in the clear and inside the hash.
  - tx0's HEAD pins each NFT output to R1's exact bytecode and to the immutable category.
  - R1 checks:
    - input 0 is exactly CAT;
    - no other input or output carries a token, so R1 never mints;
    - CTXW = CTX(outputs) in the final kind;
    - every input is R1.
  - R1's QA function is asserted byte-identical to R0's, and R1's blob is the call-graph closure of its roles.
  - R0 now dispatches kind 0 only.
  - Review items: HS covers exactly what tx0 checked (HEAD hashes copies taken before the transcript; TBL and LAD come
    from FIN's input in the same tx); the closure scan (it refuses computed invokes); R1 dispatch kinds 1..T−1 (kind 0
    has input count 0).
- *Ordering hole (open, unchanged, not fixed here):*
  - tx0 still mints every thread NFT, so the final tx (which creates the CTX outputs) does not depend on the middle
    txs having run. Only tx0's and the final tx's queries are enforced before the outputs exist: 9 + 12 = 21 of 43
    with `state` (counts 9/11/11/12), and 10 + 11 = 21 with `cap=3` (10/11/11/11); the baseline has 6 + 7 = 13.
  - `state` makes this hole more visible but does not widen it. Each later tx was already independent of the others,
    and `state` adds no new way to skip one.
  - The natural fix forwards one NFT through the chain (mutable commitment, k raised each step). That needs an
    NFT update path in R1, which conflicts with "R1 never mints". The two must be designed together.
- *cap:*
  - LAYER is recomputed against the roots in every tx: HEAD's own roots in tx0, and STATE's roots via the fixed TOP
    input 2 in R1 txs. It is not carried in the NFT.
  - c is a covenant constant, and LAYER has an exact length.
  - QRY reads LAYER only from the fixed input, with the same index convention as the paths (k − 2^c).
  - The top c layers contain no injected rows, since every tree is at least 2^13 high.
  - The encoder derives LAYER from the proof's own paths. On this vector every node at c ≤ 5 is covered; a node that
    no query reaches could not be derived from the proof alone, and a real prover would supply it from the tree.
