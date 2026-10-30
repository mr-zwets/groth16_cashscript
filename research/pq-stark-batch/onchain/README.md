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
