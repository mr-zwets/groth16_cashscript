# Track 8 / Soundness: the batch-stark CashVM verifier as built

Date: 2026-10-30. Stage S8a of DESIGN-T8 §6/§7. Research only; not a leaderboard entry; not reviewed yet (the three
S8 reviews follow this document).

- **Code under argument:** groth16_cashscript `wip/stark-usable` at 14b9862 (S7 head), folder
  `research/pq-stark-batch/`: prover (`prover/`, p3b-v1), reference verifier (`verifier/verify-batch.mjs`), on-chain
  model and generators (`onchain/model*.mjs`, `gen.mjs` (S4), `genn.mjs` (S5/S6), `gena.mjs` (S7)).
- **Calculator:** zk-verifier-bench `wip/stark-usable-design` (c488300), `research/pq-stark/design-t8/params8.py`.
  - `python3 params8.py` gives the S0 λ tables (`tables8-output.txt`, unchanged by S8).
  - `python3 params8.py --asbuilt <vector dirs>` (new in S8) rebuilds every shape the scripts were tested on from the
    VK data in the committed vectors and computes λ for each (`asbuilt8-output.{txt,json}`).
- **Unit check (new in S8):** `onchain/s8-arith.mjs` → `onchain/results/s8-arith.json` (§9.1).
- **Base:** Track 5's `research/pq-stark/soundness/SOUNDNESS.md` and `params5.py`, used unchanged.

Every λ figure in this document carries the label **"JB, powers-batching adaptation, unpublished"**: it is a
list-decoding (Johnson bound) figure that uses Track 5's own, unreviewed adaptation of [ADK] Thm 2 to Plonky3's
powers-of-one-challenge batching (§6).

## 1. Result

1. **Protocol level: 128 bits for both statements, as built.**

   | statement / set | λ_IOP | binding round | λ (digest 4h) | strict digest |
   |---|--:|---|--:|--:|
   | M1, Z128 (cap 0, layouts b and b2; cap 5, layout a′) | **128.06** (m = 5) | fold1 | 128 | 127.21 |
   | M2, Z128-g with commit PoW 3 and lookup PoW 8 (layout b2) | **128.70** (m = 5) | query | 128 | 127.21 |

   - The shapes are read from the committed vectors, not typed in: all 45 vectors give a byte-model view of the VK
     equal to the exported shape (rounds, widths, heights, opening points, chunk counts, fold schedule, ladder
     lengths), and the S0 tables of M1 and M2 equal the as-built DAGs field by field (`asbuilt8-output.txt`).
   - Caps do not change the IOP: M1 cap 0 and cap 5 have identical rounds.
   - Every new charge of DESIGN §6 is a lemma below with its own round term in params8.py (§5).
2. **Script level: every accept-relevant value has an owner, with one exception that is open.**
   - §7 lists each value that can change the verdict and the script step that fixes or checks it, for layouts b,
     b2 and a′. §8 gives the layout hand-over lemmas (b2 tail, a′ ACC/TBL/CTXW, the NFT thread).
   - **Exception (§9.1): canonicity of proof-supplied field lanes.** The scripts read OOD values, terminals, row
     values, FRI values and final-polynomial coefficients as unreduced 8-byte integers in [0, 2^64), as Track 5 did.
     Track 5 accepted this as "malleability with no soundness impact" on the premise that the script computes on the
     residues. **That premise does not hold for the S4–S7 constraint interpreter**: its SUB/NEG ops add only p, so
     a lane in [p + 1, 2^64) can drive an intermediate negative, and the packed extension product is then not
     congruent to the field product (`s8-arith.mjs`: 2 of 2 negative-lane cases give a wrong residue; the canonical
     and non-negative-unreduced controls are correct). The constraint DAGs contain such subtractions with a raw
     proof lane as subtrahend: 8 in M1, 27 in M2.
     - Not shown exploitable, and not shown safe: building a proof that tests it would be attack construction, which
       is outside this stage.
     - Consequence for the claims: **until fixed, the 128-bit statement covers the protocol and the scripts on
       proofs whose field lanes are canonical; it does not yet cover the as-built scripts against arbitrary
       witnesses.**
     - Fix candidates (§9.1): a `< p` check on every proof lane at parse time, or a 2p offset in four interpreter
       ops. The second was checked congruent in `s8-arith.mjs`; neither is applied (both change the library hash,
       op-cost and every committed script, and need the sweeps re-run).
3. **What rests on our unreviewed Track 5 adaptation** (§6): the batching round of every set (margin 8.33 bits
   over 128 for M1, 7.15 for M2), the roll-in fold of M2 (margin 0.87), and the per-height splitting of the batching
   term (our own extension). The query rounds, ALI, DEEP and LogUp terms do not depend on it.
4. **CTX** (the transaction-output binding) is not constrained by the AIR. It is bound because it is a public value
   observed before every challenge (Lemma 13). That a mempool observer cannot re-bind someone else's proof to new
   outputs additionally needs simulation extractability of the Fiat–Shamir-compiled ZK STARK, which this document
   does not prove (§12).
5. **Coverage vectors are not all at 128 bits.** Plonky3's own `three_instances_mixed_sizes` under Z128 and Z128-g
   (n 1024) give λ_IOP 127.92 / 127.90 under our accounting. They are coverage vectors for the generator, not
   production statements, and Z128 was only ever certified for M1. Nothing in Track 8's production claims uses them.

## 2. What is being argued, and how

The verdict of a deployed script is the conjunction of four things. Each has its own section.

| part | claim | where | status |
|---|---|---|---|
| A. Protocol | `p3-batch-stark` (pin 0d80373) with the hiding two-adic FRI PCS, Goldilocks, D = 3, SHA-256, at the as-built shapes and parameters, is round-by-round knowledge sound with error 2^−λ_IOP per round | §3–§6 | argument; rests on the Track 5 base |
| B. Script = protocol | for canonical proofs, the script accepts exactly when the reference verifier accepts, and every value the verdict depends on is fixed by the VK or checked by an owner | §7–§9 | argument plus tests; one open gap (§9.1) |
| C. AIR ⇒ relation | a trace satisfying M1's (or M2's) constraints yields a witness of the M1 relation for the public values | §10 | proof sketch, row type by row type; mutation-tested |
| D. Statement | the relation gives membership, a unique nullifier per leaf, hiding of the leaf, and binding to the outputs | §11 | argument; collision resistance of T∘P and SHA-256 |

**Evidence that B holds as implemented** (from the build stages, not re-run here):
- the on-chain model agrees with the independent reference `verify-batch.mjs` on 3,762 (S4) and 17,911 (S5/S6) case
  runs, with byte-identical transcripts; the reference agrees with Plonky3's Rust `verify_batch` on 14,027 cases
  (S3), with byte-identical transcripts on 128 proofs;
- the scripts agree with model and reference on 2,929 + 3,309 (S4), 8,252 + 2,558 + 1,030 (S5/S6) and
  3,765 + 4,181 + 2,387 (S7) cases, 0 unexpected;
- S3's sensitivity run shows which checks plain tampering cannot reach (the lookup PoW and final-polynomial checks);
  those are argued from the code (§7), not from the sweeps.

Tests support B; they do not prove it. In particular no test exercises a consistently built proof with non-canonical
lanes, which is why §9.1 is open although every sweep passed.

## 3. Base (unchanged from Track 5)

- **[ADK] Thm 2** (ePrint 2024/1553): round-by-round knowledge soundness of DEEP-ALI plus batched FRI in the list-decoding
  regime, with per-round errors; built on **[BCIKS]** (ECCC TR20-083 rev. 3) Lemma 8.2 and Thm 7.2/7.4.
- **[BGKTTZ] Cor. 5** (ePrint 2023/1071): ε_FS ≤ Q_H·2^−λ_IOP + 3(Q_H² + 1)/2^{8h}. With h = 32 this is the digest
  term 4h = 128 (birthday convention) or 127.21 (strict reading).
- **Powers batching** (Track 5 SOUNDNESS §2.1): Plonky3 combines t opened quotients with powers of one α′; replacing
  BCIKS Thm 7.4 by Thm 7.2 (curve of degree t − 1) inside the [ADK] proof multiplies the batching error by t − 1.
  **Ours, unpublished, unreviewed.** §6 says what depends on it.
- **Grinding** adds g bits to the round whose challenge it precedes.
- **Track 5's on-chain primitives**, reused by S4–S7:
  - the transcript as a chain of SHA-256 digests, byte-identical to `SerializingChallenger64<HashChallenger<Sha256>>`;
  - a challenge sample ≥ p is rejected instead of re-drawn (completeness loss about 2^−32 per sample, no soundness
    effect);
  - query indices are the low log H bits of an 8-byte slice of a SHA-256 output, so they are uniform (Track 5 §5,
    condition 4);
  - the LIFO Merkle record programs (`lifoPrograms`/`lifoRun`, Track 5 `verifier/model.mjs`): every query leaf is
    consumed exactly once (`acc = 2^Q′ − 1`), duplicates must carry equal digests (DUPM), and the walk must end at
    the root.

## 4. The protocol as built (transcript order and PoW sites)

From `modeln.mjs` `transcriptN`, which the scripts follow and which is byte-identical to Plonky3's transcript
on every valid vector.

| # | observed (in this order) | challenge drawn | PoW before it |
|--:|---|---|---|
| 1 | batch domain seed and every instance's degree_bits (one VK constant `SO.batch`) ‖ main cap ‖ public values (ROOT, NF, CTX; in instance order) ‖ preprocessed cap (VK constant) | – | – |
| 2 | (lookups only) lookup PoW witness | lookup α, β | lookup PoW (M2: 8 bits) |
| 3 | (lookups only) permutation cap ‖ terminals | constraint α | none (no site in batch-stark) |
| 4 | quotient cap ‖ random cap | ζ | ood PoW: 0 (the generator refuses > 0) |
| 5 | PCS separator ‖ every opened value (claims in round, matrix, point order, random-codeword values included) | – | – |
| 6 | batch PoW witness | α′ | batch PoW 20 |
| 7 | per FRI round r: (r = 0: FRI separator) ‖ FRI cap r; commit PoW witness r | β_r | commit PoW 2 (M1) / 3 (M2) per round |
| 8 | final-polynomial coefficients; query PoW witness | Q query indices | query PoW 24 |

Things not in the transcript but fixed by the VK (Plonky3 does not bind them in batch-stark): periodic columns,
commitment widths, the constraint DAG, the FRI schedule. In our setting the VK is compiled into the script before
any proof exists, so they need no binding (§7, group V).

## 5. Round terms (DESIGN §6 charges), one lemma each

Notation: q = |F_p^3| = p^3; for table i, D_i is its LDE domain and L_i = m/(ρ − 2m/|D_i|) the [ADK] list size;
N_max = 2^20 is the top LDE size. Numbers are params8.py at the as-built shapes; "raw" means before grinding.

**Lemma 1 (multi-table ALI).** One α folds all constraints of all tables. If some table's committed trace (any
element of its list) violates a constraint, the folded constraint quotient is a polynomial only if α is a root of a
nonzero polynomial of degree ≤ |C_i| − 1 for that list element. Union bound over tables and list elements:
ε_ALI ≤ Σ_i L_i·|C_i|/q.
- |C_i| counts AIR and LogUp constraints: M1 53; M2 44 + 35. We charge |C_i|, not |C_i| − 1 (as Track 5).
- M1 174.94 bits, M2 174.34. No PoW site exists before α, and none is needed.

**Lemma 2 (DEEP, one shared ζ).** ε_DEEP ≤ Σ_i L_i²·num_i/q with num_i the [ADK] numerator at table i's degree
(DAG degree: M1 4; T_hash 4; T_ctl 2) and chunk count.
- ζ must avoid every trace domain H_i. The script checks Z_{H_i}(ζ) = ζ^{n_i} − 1 ≠ 0 for every instance, and,
  under ZK, ζ^{n_i} ≠ −1 (ζ not in the doubled trace domain). That is stronger than DESIGN's "ζ^{n_max} ≠ ±1
  covers every H_i" and implies it.
- ζ at an LDE point makes some DEEP denominator norm zero, and then no inverse hint can satisfy its check (§7, Q5):
  rejected.
- M1 155.17 bits, M2 155.07.

**Lemma 3 (batching per height).** Plonky3's `open_input` reduces the claims of each LDE height with its own α′
ladder (powers restart at α′^0 for each height). For each height h the bad event "the t_h quotients have no
correlated agreement but their α′-combination has agreement above the Johnson threshold" is a curve of degree
t_h − 1 in α′; by the powers-batching adaptation it has probability ≤ (t_h − 1)(A0 + B1). Union over heights:
ε_batch ≤ Σ_h (t_h − 1)(A0(N_max) + B1(N_max)).
- Every height is charged at N_max (A0 grows with |D|²), which over-charges the shorter heights. Charging each at
  its own N_h gives M2 135.88 instead of 135.15 (sensitivity).
- t_h: M1 {20: 94}; M2 {20: 127, 17: 85}, read from the as-built shapes.
- M1 136.33 bits (raw 116.33, batch PoW 20); M2 135.15 (raw 115.15).
- B's claim that per-height batching is "unchanged" from the single-height formula is not used; for M2 both give
  the same rounded figure here, because the top height dominates.

**Lemma 4 (roll-in folds).** In fold round r that lands on a height h carrying inputs, the next codeword is
Fold_a(f_r; β_r) + β_r^a·ro_h, a curve of degree a in β_r (the fold alone has degree a − 1). BCIKS Thm 7.2 is
therefore charged with a instead of a − 1: (a·A0·(N_{r+1}/N)² + a·B1).
- Queries on the shorter input use the reduced index idx ≫ (top − h); the script computes the input-tree leaf index
  as idx ≫ (log H − top of that tree) and x_h = 7·xo^{2^{log H − h}} (`modeln.mjs` `xoAt`, `genn.mjs` per-height DEEP).
- The VK enforces the shape conditions this needs (`vkxN`, at generation time):
  - strict FRI height: every log LDE height > log final length + log blowup (otherwise an input would never be
    folded and is checked only against the final polynomial);
  - every height lies on the fold grid (some round lands exactly on it), and the fold schedule ends exactly at the
    final height.
- M2 fold1 (20 → 17, roll-in of T_ctl): 128.87 bits with commit PoW 3 (raw 125.87). At commit PoW 2 it would be
  127.87, which is why S0 raised it; the vectors are built with 3.
- M1 has one height: no roll-in.

**Lemma 5 (LogUp, M2).** ε_LogUp ≤ L·N·(W + 2)/q (Haböck, ePrint 2022/1530; p3-security `logup.rs`), with
N = Σ interactions × rows = 1·2^10 + 1·2^7 = 1152 and W = 13 (both from the as-built DAG). The conditions the bound
needs, and where each is enforced:
- the lookup challenges are drawn after the main commitment, the public values and the preprocessed cap, behind the
  lookup PoW (transcript steps 1–2);
- the permutation columns and terminals are observed before α (step 3), so the LogUp gadget's constraints are part
  of Lemma 1's fold;
- **multiplicities cannot wrap**: Σ count_weight·n = 1152 < p, asserted at generation time; and in M2 the
  multiplicities are not prover data at all: −C on T_hash is a periodic VK constant, f_used on T_ctl a
  preprocessed VK column;
- **buses are separated** by prefix_k = α + (k + 1)·β^{maxW}, an injective offset (M2 has one bus);
- the terminal sum over the batch is checked exactly (three `NUMEQUALVERIFY` on the lane sums mod p).
- M2: 174.54 bits including lookup PoW 8 (raw 166.54).

**Lemma 6 (preprocessed columns).** The preprocessed commitment is VK data, observed in step 1 before any challenge,
opened at ζ, included in its height's ladder (it adds to t_h) and authenticated per query against the VK constant
root. It adds no round.
- Recomputability, which matters for trust in the VK, not for soundness: the commitment is salted by the hiding MMCS.
  For M1/M2 the salts come from the published `SETUP_SEED` = 0x7438534554555031, and S2's `check` recomputes the root
  for every vector. (DESIGN §4's word "transparent" should read "recomputable from the published SETUP_SEED".)
  Plonky3's own test AIRs salt it with the prover's RNG, so each of their proofs has its own VK.

**Lemma 7 (caps and mixed-height injection).** Opening binding reduces to SHA-256 collision resistance (the digest
term), with no separate round term, provided the verifier fixes the tree geometry. It does:
- every tree's depth, injection levels, group widths, cap height and leaf byte lengths are VK constants; nothing about
  the geometry is read from the proof;
- the whole cap (2^c digests) is observed in the transcript before the challenges that depend on it, and each path
  ends at the cap entry selected by the index (`gena.mjs` QRY: entry k − 2^{capH});
- leaves, injected-row hashes and nodes sit at fixed levels, so the lack of domain separation between leaf and node
  hashes does not matter: a fixed-depth tree is binding under collision resistance;
- **deviation from Plonky3 (S5): per-query bottom paths instead of INJ records.** For a mixed-height tree, each query
  walks the bottom B levels from B siblings in its own blob, hashing in the injected rows
  (node = H(H(l‖r) ‖ H(rows))); the level-B node is the leaf of the LIFO record tree. Each query's rows are
  therefore authenticated by a complete path to the root, and two different openings of one position give a
  collision. Plonky3's pruned multiproof is a compression of the same paths, so binding is the same. DUPM additionally
  forces equal level-B digests for queries that share a node (which also makes their injected rows equal).
- As built, only M1 uses cap > 0 (cap 5, one height), so Plonky3's "effective cap" lowering for injected matrices
  never applies; M2 runs at cap 0.

**Query round.** (√ρ·(1 + 1/2m))^Q with ρ = 2^−9, Q = 24, plus query PoW 24: 128.70 bits for both statements
(raw 104.70). Shorter inputs have the same rate, so the term is unchanged by mixed heights.

**Composition.** λ_IOP = min over rounds (§1 table; per-round values in `asbuilt8-output.txt`). With [BGKTTZ] Cor. 5:
λ = min(λ_IOP, 128) = 128, strict 127.21, for both statements.

| round | M1 / Z128 | M2 / Z128-g, cpow 3, lpow 8 |
|---|--:|--:|
| LogUp | – | 174.54 |
| ALI | 174.94 | 174.34 |
| DEEP | 155.17 | 155.07 |
| batch | 136.33 | 135.15 |
| fold1 | **128.06** | 128.87 (roll-in) |
| fold2 | – | 135.06 |
| query | 128.70 | **128.70** |
| λ_IOP | 128.06 | 128.70 |

## 6. What rests on the unpublished powers-batching adaptation

| item | what depends on it | M1 | M2 | if the adaptation failed |
|---|---|---|---|---|
| batching round, factor (t_h − 1) | Lemma 3 | 136.33 (8.33 over 128) | 135.15 (7.15 over 128) | the bound would have to be redone; batch PoW is a free knob (Plonky3 `batch_proof_of_work_bits`), so a larger constant factor costs grinding, not bytes |
| per-height splitting of the batching term | Lemma 3, our extension of the adaptation | – (one height) | included above | as above |
| curve of degree a in a roll-in fold | Lemma 4, the same Thm 7.2 substitution inside [ADK]'s proof | – (no roll-in) | fold1 128.87 (0.87 over 128) | commit PoW is the knob: +1 bit per bit lost, no byte cost |
| ALI with powers of α | Lemma 1 (Track 5 §2.1 item 4, Schwartz–Zippel) | 174.94 | 174.34 | 46 bits of slack |

- For comparison, independent batching challenges (the published [ADK] Thm 2 with Thm 7.4) would give a batch round
  of 142.87 (M1) and 141.87 (M2); the powers factor costs 6.54 / 6.72 bits, and batch PoW 20 pays for it with margin.
- Not dependent on the adaptation: ALI (except item 4's standard argument), DEEP, LogUp, the query round, the
  non-roll-in folds and the digest term.
- In words: M1's binding round (fold1, 128.06) does not use the adaptation; its batching round does, with 8.33 bits of
  slack. M2's roll-in fold uses the curve version with 0.87 bits of slack, and that is the tightest dependence in
  Track 8.

## 7. Owner table: every accept-relevant value

"Owner" = the script step that fixes the value (VK constant) or checks it before it can influence the verdict.
Layout columns: **b** (`gen.mjs` S4 for M1, `genn.mjs` `buildB`), **b2** (`genn.mjs` `buildB2`: input 0 / input 1),
**a′** (`gena.mjs`: HEAD, CODE_j, FIN, QRY).

**V. VK constants** (compiled into the script or library; authenticated by P2S locking, H_lib or R's code hashes)

| value | owner | b | b2 | a′ |
|---|---|---|---|---|
| widths, heights, degree_bits, chunk counts, opening points, round layout | generator; `vkFromVector` re-derives it and refuses a vector whose `shape` differs | redeem | lib (HASH256 = H_lib in both lockings) | code blobs (SHA-256 checked by R) |
| FRI schedule, final length, Q, every PoW bit count, cap height | generator (strict height, fold grid, hiding budget, Σw·h < p asserted) | redeem | lib | blobs |
| constraint DAG and its emission order, periodic coefficients | generator (`dagProgram`, periodic coefficients) | redeem | lib | blobs, constraint ranges [0,21) / [21,53) |
| domain separators `SO.batch` (seed + degree_bits), `SO.pcs`, `SO.fri` | transcript constants | redeem | lib | blobs |
| preprocessed cap (M2) | transcript constant and Merkle root constant | – | lib | – |
| ROOT | transcript constant and DAG constant (pool mode; Track 9 would read it from covenant state) | redeem | lib | blobs |
| H_lib, templates of the other input's locking | the lockings themselves (b2) | – | both lockings, MAIN0/MAIN1 | – |
| R, CAT (token category), TTAG | R (P2S locking of every input); thread code | – | – | R / HEAD |

**S. Statement** (public values; observed in transcript step 1)

| value | owner | b | b2 | a′ |
|---|---|---|---|---|
| NF (4 lanes) | size 32 checked, each lane < p checked, bytes observed, lanes used by the DAG | entry | input 0 (input 1 gets the same bytes, §8.2) | HEAD; CODE/FIN/QRY read HEAD's push |
| CTX (4 × 7 bytes) | `ctxCode` recomputes it from the spending transaction's outputs; lanes < 2^56 by construction; not read by the DAG (generator refuses a DAG that reads CTX) | entry | input 0 | final HEAD: CTXW = `ctxCode`; non-final HEAD: CTXW lanes < 2^56, bound to the final transaction through G (§8.4) |
| public-value count and order | VK constant layout (instance order) | ✓ | ✓ | ✓ |

**P. Proof items before the queries** (all observed in the transcript at the step in §4)

| value | owner |
|---|---|
| main / permutation / quotient / random caps (ROOTS) | item size = VK length; split at VK offsets; observed whole; the same bytes are the Merkle roots (cap entries in a′) |
| terminals (TERM) | size checked; observed with the permutation cap before α; used as DAG leaves; batch sum = 0 checked |
| opened values (OOD) | size checked; observed whole (step 5); used by the AIR check (instance by instance) and by the A sums of every ladder. **Lane canonicity: not checked (§9.1)** |
| PoW witnesses (LPOW, BPOW, CPOW, QPOW) | size checked; low g bits of the next digest = 0 (`powCheck`) |
| FRI caps (FROOTS) | size checked; observed per round before β_r; Merkle roots of the FRI trees |
| final polynomial (FIN) | size = L·24 (so degree < L by construction); observed before the query PoW; evaluated per query and compared with the folded value. Lane canonicity: not checked (residues used in a non-negative path, §9.1) |

**C. Challenges and derived constants** (never witness data except where noted)

| value | owner |
|---|---|
| lookup α, β; α; ζ; α′; β_r | sampled by the script from the digest chain; each sample < p checked (`POPB`) |
| query indices | low log H bits of the chain after the query PoW. b, b2: computed in the script. a′: in TBL, which FIN recomputes and checks byte for byte; QRY reads TBL |
| Z_H(ζ) ≠ 0, ζ^n ≠ −1 (ZK) | per instance, `nonzero` checks in the AIR phase |
| bus challenges, selectors, periodic values at ζ, quotient recomposition constants | computed from the above and VK constants |
| α′ powers, A sums, DEEP point constants, β^arity | computed in the script. b2: input 1 recomputes them from the same tail. a′: FIN checks them in TBL; QRY recomputes the α′ ladder and row keys itself |
| G (final digest) | a′ only; computed by HEAD from its own and FIN's pushes; bound into the NFT commitment |

**Q. Per-query data** (query blobs and Merkle records/paths)

| value | owner |
|---|---|
| Q1. blob length | `SIZE = blob.total` (VK constant), then fixed-length splits: every row, salt, FRI value block and hint has a fixed position |
| Q2. rows and salts of every input matrix | hashed into the leaf (tallest group) or the injected-row hash (shorter groups); the leaf is authenticated to the root (Lemma 7); row lanes parsed unreduced (§9.1) and used in the DEEP dot products |
| Q3. bottom siblings (mixed heights) | consumed per query in the B-level walk; the level-B node must authenticate in the record tree |
| Q4. FRI sibling values and salts | the folded value from the previous round is inserted at the index position, the leaf hashed and authenticated in FRI tree r |
| Q5. inverse hints T_top, T_h | parsed < p; T·s0·∏N = 1 resp. T_h·∏N = 1 checked; a zero product cannot pass, so the hint is unique and exists only when every DEEP denominator is nonzero |
| Q6. Merkle record programs (b, b2) | LIFO records: each query leaf consumed exactly once, DUPM for shared nodes, walk ends at the root, every sibling consumed (`rbc = 0`), marker checked |
| Q7. full paths (a′) | fixed length `pathB`; depth − capH levels; final digest = cap entry at the index; nothing left over |
| Q8. stack shape | `DEPTH` checked at entry and after the Merkle phase of every tree; leftover items or bytes make the script fail |

**L. Layout hand-overs** (§8): b2 TAIL and lib; a′ HEAD/FIN pushes, ACC_j, TBL, CTXW, code blobs, the NFT.

Two values have **no owner in the script by design**, and need none:
- **the random-codeword openings** (ZK): they are claims of the random matrix and of the random columns of each
  matrix, included in the ladders and the PCS check exactly as in Plonky3 (`verify_batch` constrains them no further);
- **witness encoding choices outside the proof bytes** (which encoder produced the records, item order within what
  the DEPTH and size checks allow): Track 5 already listed these as malleability; S4/S7 sweeps show the remaining
  encoder-only cases reproduce the valid witness.

## 8. Layout lemmas

### 8.1 Layout b (one input)

The redeem script is the whole verifier (P2SH32 hash or P2S); all VK constants are in it. The unlocking holds the
query blobs, record groups, the PT items and the statement items. The entry checks `DEPTH` = the VK's item count and
the size of every PT and statement item; from there §7 applies item by item. No other input is read.

### 8.2 Layout b2 (two inputs): chain lemma

**Lemma 8 (b2).** If both inputs accept, then (i) both ran the same library, (ii) input 1 used exactly the PT and
statement bytes that input 0 consumed, and (iii) the queries checked by the two inputs are [0, QA) and [QA, Q) of
the same transcript; so the transaction accepts only if the single-input verifier would accept the same proof.

- **(i) Same library.** Input 0's locking takes the bottom stack item (the first push of its unlocking) and checks
  HASH256 = H_lib before defining it. Input 1's loader reads input 0's unlocking with OP_INPUTBYTECODE, requires the
  first push to be a PUSHDATA2, and checks the same H_lib. By collision resistance both define the same library.
- **(ii) Same tail.** Input 1 takes the last `tailLen` bytes of input 0's unlocking (a VK constant) and parses them
  forward with exact push headers for each fixed-length item, requiring nothing to remain (`parseTail`). Input 0
  checks `DEPTH` and that each of its top items has exactly the VK length. BCH consensus requires unlocking bytecode
  to be push-only with minimal push encodings, so input 0's last pushes, with those lengths, occupy exactly the last
  `tailLen` bytes with exactly those headers: both inputs parse the same items.
- **(iii) Same transcript and graph.** Both inputs run the shared TRANSCRIPT and CONSTS functions on the same tail
  bytes and so derive the same challenges and indices. MAIN0 and MAIN1 each pin the transaction: exactly 2 inputs,
  their own input index, and the other input's locking = the template around H_lib. So no third input, no swapped
  roles and no other verifier can take part. The query split is a VK constant; input 1 also authenticates its paths
  against the same roots (read from the tail).
- The AIR check runs on input 0 only, which is enough: it depends only on tail data and challenges.
- Tests: S6's layout family (814 production + 1,333 harness cases) covers each condition above.

### 8.3 Layout a′, one transaction: chain lemma

**Lemma 9 (a′, 1 tx).** If every input of the 12-input transaction accepts, the checks performed together are exactly
those of the single-input verifier on one proof, for the statement (ROOT, NF, CTX of this transaction's outputs).

- **Code.** Every input's locking is R (P2S, 118 B). R reads two code blobs from the CODE inputs' first pushes (header
  checked) and checks each blob's SHA-256 against constants in R. The last blob pins the graph: the input count for
  the transaction kind, and every input's locking = R. It then dispatches on (kind, input index), so each role runs at
  a fixed position.
- **Values cross inputs only as pushes their owner checks.** Readers parse other inputs' unlocking with
  OP_INPUTBYTECODE, exact push headers, fixed lengths and nothing left over.
  - HEAD's pushes (caps, OOD, PoW witnesses, FRI cap, NF, CTXW): checked by HEAD (sizes, NF < p, CTXW = CTX of the
    outputs, the transcript with every PoW). CODE, FIN and QRY re-derive the transcript from these bytes and FIN's FIN.
  - ACC_j (24 B): CODE_j evaluates its constraint range at ζ and checks ACC_j equals it. HEAD checks
    Σ_j ACC_j·α^{C − hi_j} = q(ζ)·Z_H(ζ)·Dd^{maxScale}. With ACC_j = Σ_{i∈[lo_j,hi_j)} α^{hi_j−1−i}·c_i, the left
    side is Σ_i α^{C−1−i}·c_i, the full Horner fold, so this is S4's single-input AIR check split into ranges.
  - TBL (312 B: query indices, α′, β, DEEP point constants, A sums): FIN recomputes every field from the transcript
    and checks TBL byte for byte. QRY uses TBL's indices and constants and recomputes the α′ ladder itself.
- **Queries.** The QRY ranges partition [0, Q) (checked when the plan is built; each QRY's range is a constant of
  its role). Each QRY checks its blobs' sizes, runs the S5 query function and the full paths of every tree to the
  cap entry for the index; the caps are HEAD's pushes, observed whole in the transcript.
- Tests: S7's constants (650), input (598), graph (208) and mix (130) families.

### 8.4 Layout a′, two transactions: the NFT thread

**Lemma 10 (a′, 2 tx).** If tx0 and tx1 both accept, there is one G (the final transcript digest) for which the
union of their checks is Lemma 9's set, and the statement's CTX is tx1's outputs.

- tx0 is kind 0 (input 0 holds the minting baton of CAT, capability byte 2). Its HEAD returns the baton to R in
  output 0 and mints, for each later transaction k, one immutable NFT of CAT under R with commitment
  k ‖ SHA256(TTAG ‖ G ‖ k). Outputs beyond those carry no token.
- tx1 is kind 1: its input 0 must hold an NFT of CAT with commitment 1 ‖ SHA256(TTAG ‖ G′ ‖ 1), where G′ is
  computed by tx1's own HEAD from its own pushes. By collision resistance G′ = G. G covers every transcript input
  (caps, ROOT, NF, CTXW, OOD, PoW witnesses, FRI caps, final polynomial), so both transactions verify the same proof
  prefix and statement. No input or output of tx1 may carry another CAT token, so the NFT is burned.
- tx0 runs the AIR check (CODE inputs and HEAD identity) and its QRY ranges; tx1 runs FIN and the remaining QRY
  ranges and checks CTXW = CTX(tx1's outputs). The ranges partition [0, Q).
- **Assumptions and limits.**
  - The minting baton is created under R at deployment, and CAT has no other minting baton.
  - tx0 alone is a partial check: it can mint an NFT for a proof tx1 would reject. Its only effect is that NFT;
    payment happens in tx1.
  - A second tx0 for the same proof can mint another NFT, so one proof can drive two final transactions. Preventing
    that is the nullifier set's job (Track 9), as for every layout.
- Tests: S7's thread family (390 cases) and the 2-transaction production sweep (4,181 cases).

## 9. Where the scripts deviate from the reference verifier

### 9.1 Field lanes from the proof are not range-checked, and the interpreter is not residue-safe (OPEN)

**What the scripts do.** The reference verifier and Plonky3 reject any 8-byte lane ≥ p. The scripts, like Track 5's,
check `< p` only on challenge samples, NF, public values (harness) and the inverse hints. OOD values, terminals, row
values, FRI values and final-polynomial coefficients are parsed as integers in [0, 2^64) (`RDV`, `PKL`, the row
parser) and used directly.

**Track 5's argument and why it no longer covers the scripts.** Track 5 accepted this because "the residues are used":
if every step of the script maps a lane to the same residue as its reduced value, an unreduced lane is just another
byte encoding of the same field element. Changing the encoding changes the transcript bytes and Merkle leaves, so it
is a different oracle query, and Fiat–Shamir soundness is unaffected. That argument needs every script operation to be
congruent mod p for inputs in [0, 2^64).
- Additions, multiplications by constants, `SUBE` (offset 2p), the DEEP numerators, `PAIRK` (bias p·2^137), the
  final-polynomial Horner step and the terminal sum are all congruent for such inputs: every intermediate stays
  non-negative, and the packed products fit their 17-byte slots.
- The constraint interpreter's `D_SUB`, `D_SUBL`, `D_RSUBL` (a − b + p) and `D_NEG` (p − a), present in `gen.mjs`
  (S4) and `genn.mjs` (S5–S7, so also a′'s CODE inputs), are **not**: with b in [p + 1, 2^64) and a < b − p the
  result is negative, `MOD` keeps the sign, and the next packed extension product (`MULE`) is then not congruent to
  the field product.
- `s8-arith.mjs` runs the real `MULE` body in libauth (`results/s8-arith.json`): canonical lanes and an unreduced but
  non-negative lane (p + 5) give the correct residue; a lane from `D_SUB(2, p + 5)` = −3 and a case with two such
  lanes do not (the results differ by borrow errors); the same inputs through a − b + 2p are correct.
- Reachability: in the as-built DAGs, `sub` nodes whose subtrahend is a raw proof lane (a `main`, `pre` or
  `perm_value` leaf) number 8 in M1 (u_j − s_j in the chain constraints D_j) and 16 + 11 in M2.

**Status.** For any proof whose lanes are all canonical, every intermediate is non-negative and the script computes
the field semantics; the sweeps confirm agreement there. For a proof with a non-canonical lane in such a position, the
AIR check evaluates something that is not the AIR identity, while DEEP/FRI use the residue. Whether a prover can turn
this into acceptance of a false statement is **unknown**: it was not analysed further and no such proof was built
(attack construction is out of scope for this stage). The S3 `noncanon` family (343 cases) does not test it: it
modifies honest proofs after the fact, which changes the later challenges and fails the Merkle/FRI checks first.

**Fix candidates** (not applied; each changes every committed script and the b2 library hash, so S4–S7's sweeps and
op-cost figures would need to be re-run):
1. Offset 2p in `D_SUB`, `D_SUBL`, `D_RSUBL` and `D_NEG` (as `SUBE` already does). No size change; makes every
   operation congruent for lanes in [0, 2^64), so Track 5's residue argument then holds. Checked in `s8-arith.mjs`.
   An audit of every subtraction site is needed; S8a's grep found no other site with a raw operand.
2. A `DUP <p> LESSTHAN VERIFY` on every proof lane at parse time, as Plonky3 does. This also removes the malleability,
   but costs op-cost per lane, and layout a′'s QRY inputs already run at 91% of their budget.

### 9.2 Other deviations (no soundness effect)

- **Rejection sampling** of challenges ≥ p instead of re-drawing: completeness loss about 2^−32 per sample.
- **Encoder-only malformed cases:** a′ (55 cases) and b/b2 (1 case) where the encoder's lenient parse of a malformed
  proof reproduces the valid proof's witness; the script then accepts the valid proof, which is correct.
- **ood PoW > 0** and **cap > 0 for multi-height VKs** are refused by the generator, not handled.
- **ROOT** is a script constant written as 4 × u64 LE; the generator should assert each lane < p when it builds a
  pool VK (not done; ROOT comes from the pool's field-element state, so this is a deployment check).
- **The per-query bottom path** replaces Plonky3's INJ handling (Lemma 7): same binding.

## 10. AIR ⇒ relation

### 10.1 M1 (AIR-SPEC §3)

**Lemma 11.** If a trace of height 2^10 satisfies all 53 constraints of AIR-SPEC §3.4 on every row (with the
periodic columns of §3.3, which are VK constants), then with nk = row 0's lanes 0..3, r = row 31's u0..u3,
b_k = row 32k+31's u4 and S_k = row 32k+31's u0..u3 (k = 1..30):
NF = T(P(nk ‖ IV_NF)), leaf = T(P(NF ‖ r)), node_k = T(P(swap_{b_k}(node_{k−1}, S_k))), ROOT = node_30.

Proof sketch, row type by row type:
1. **Selectors partition every slot.** F, Pt, C are periodic VK constants with values in {0, 1} and disjoint
   support; L = 1 − F − Pt − C is 1 exactly on slot row 0. Because they are constants of the script, not prover data,
   they are trusted (batch-stark does not bind them in the transcript; our VK does, §7 V).
2. **F rows** (slot rows 1–4, 27–30). A_i forces u_i = (s_i + rc_i)^3 for all i, so u_i²·(s_i + rc_i) = (s_i + rc_i)^7
   and C_j gives s′ = M_E·(s + rc)^7.
3. **Pt rows** (5–26). A_0 forces u_0 = (s_0 + rc_0)^3; B forces u_1..u_4 = 0 (unused). C_j gives
   s′ = M_I·((s_0 + rc_0)^7, s_1, …, s_7), using rc_{1..7} = 0 on these rows.
4. **L row** (0). C_j gives s′ = M_E·s, Plonky3's initial linear layer. So for every slot, row 31's state is
   P(row 0's state) with Plonky3's round order (`add_rc → sbox → M`), which air8_ref.py and S2's differential test
   (10,002 inputs) confirm against p3-goldilocks.
5. **C row** (31). F = Pt = L = 0, and the (1 − C) factor makes C_j vacuous there. For k < 31, D_j sets the next
   slot's row 0 to swap_{u4}(s_0..s_3, u_0..u_3); E forces u4 ∈ {0, 1}. The is_transition gate excludes the wrap
   from row 1023 to row 0.
6. **z.** F0 sets z = 1 on row 0; F1 gives z′ = (1 − C)·z on every transition, so z = 1 on rows 0..31 and z = 0
   from row 32 on.
7. **Slot 0 (NF).** G fixes row 0's lanes 4..7 to IV_NF = (0, 0, 0, TAG_NF); lanes 0..3 are free (nk). H_j
   (C·z·(s_j − NF_j)) fires only on row 31 and gives T(P(nk ‖ IV_NF)) = NF. F2 forces u4 = 0 there, so slot 1's
   input is (NF ‖ r).
8. **Slots 2..31** take swap_{b_k}(node_{k−1}, S_k) by step 5, and I_j fixes row 1023 (slot 31's output) to ROOT.
9. B and J only zero otherwise free cells (u on rows where it has no role, u0..u4 on the last row); they constrain
   no relation value and make S2's single-cell mutation test complete (17,408 / 17,408).

The depth is fixed at 30 by the trace height and the slot count, so a leaf cannot be confused with an inner node.

### 10.2 M2 (AIR-SPEC §4): the bus lemma

**Lemma 12.** If T_hash (2^10 rows) and T_ctl (2^7 rows) satisfy their constraints and the bus P2 balances (the
batch terminal sum is 0, Lemma 5), the same conclusion as Lemma 11 holds, with nk = T_ctl row 0's in_0..in_3, r = row
1's in_4..in_7 and (b_k, S_k) from T_ctl rows k + 1.

1. **T_hash computes 32 independent permutations.** Steps 1–4 of §10.1 apply per slot (A, B′, C). K loads s = in on
   row 0 of each slot; M carries in unchanged through the slot. So on each slot's C row,
   (lvl_h, in, s_0..s_3) = (k, in, T(P(in))) for slot k, with lvl_h a preprocessed VK column.
2. **The bus.** T_hash receives with multiplicity −C (periodic VK constant: one receive per slot, 32 in all, with
   the distinct tags 0..31); T_ctl sends (lvl, in, out) with multiplicity f_used (preprocessed: 1 on rows 0..31,
   0 elsewhere; lvl = row index there). All multiplicities are fixed VK data in {0, 1} and Σ w·h < p, so a balanced
   bus is an exact multiset equality over the integers (Lemma 5). With distinct tags on both sides it is a bijection
   that preserves lvl: T_ctl row k's (in, out) equals T_hash slot k's, so **out_k = T(P(in_k))** for k = 0..31.
3. **T_ctl's chaining.**
   - N1 fixes row 0's in_4..in_7 = IV_NF, so out_0 = NF by N2.
   - N4 forces b = 0 on rows 0 and 1; N6 then gives row 1's in_0..in_3 = out_0 = NF (in_4..in_7 = r free), so out_1 =
     leaf.
   - For rows k = 2..31: N5 makes b boolean; N6/N7 put out_{k−1} in the half selected by b_k (the other half, S_k,
     is free); N3 fixes out_31 = ROOT.
   - N8 zeroes out, b and in_4..in_7 on unused rows, and N6 from row 31 fixes row 32's in_0..in_3 = ROOT; every cell
     is constrained (S2: 1,664 / 1,664, of which 128 cells, nk, r and the siblings, are caught only through the bus).

## 11. Statement-level lemmas

**Collision resistance.** T∘P truncates Poseidon2-Gl-8 to 4 Goldilocks lanes (≈ 255.99 bits): generic collision
resistance about 128 bits classical and about 85 bits quantum (BHT). All Merkle commitments use SHA-256 (128 / 85).
The maintainer accepted this level (decision 2).

**Binding of membership.** A proof for ROOT gives (Lemma 11/12 plus knowledge soundness) a path of depth 30 from
leaf = T(P(NF ‖ r)) to ROOT. Two different leaves at one position, or a leaf that is not in the tree, give a
collision of T∘P.

**Nullifier uniqueness.** NF = T(P(nk ‖ IV_NF)) is a deterministic function of nk. A second nullifier NF′ ≠ NF for
the same leaf needs T(P(NF′ ‖ r′)) = T(P(NF ‖ r)): a collision. So each deposited leaf can produce one NF, and the
nullifier set (Track 9) prevents its second use.

**Leaf hiding.** leaf = T(P(NF ‖ r)) with r uniform in F_p^4 (≈ 256 bits) reveals nothing about NF, modelling P as
a random permutation. ZK of the proof itself is "by construction" (Plonky3's hiding PCS, ePrint 2024/1037); FRI-layer
hiding is not analysed (DESIGN limits).

**Canonical public values.** NF lanes are checked < p; CTX lanes are < 2^56 by construction; ROOT lanes must be
< p by deployment (§9.2). So the public values the transcript observes are the field elements the AIR uses.

**Lemma 13 (CTX binding, transcript only).** CTX is not referenced by any constraint (AIR-SPEC §3.1; the generator
refuses a DAG that reads it). It enters only transcript step 1, before every challenge.
- *Binding to the transaction.* The script computes CTX from the spending transaction's outputs with an injective
  serialization (prover/FORMAT.md, "CTX serialization") and SHA-256 truncated to 28 bytes. A different output set
  with the same CTX is a second preimage of 224-bit truncated SHA-256 (224 bits classical, about 112 quantum); the
  prover, who chooses the outputs, gains nothing from a collision, because it could prove any CTX anyway.
- *A proof for one CTX does not verify for another.* Changing CTX changes the first digest, hence every challenge.
  Accepting the same commitments under new challenges is exactly the event round-by-round soundness bounds, so a
  replayed proof with changed outputs is rejected except with probability about Q_H·2^−128 (S3's statement family and
  S4/S5/S7's tx families test this: 0 accepted).
- *A mempool observer cannot make a fresh proof for new outputs.* The statement (ROOT, NF, CTX′) is true for any
  CTX′, so soundness alone does not stop a party that knows the witness. Stopping a party that only saw an honest
  proof needs **simulation extractability** of the Fiat–Shamir-compiled ZK proof: an adversary that sees proofs and
  outputs a proof for a new statement must know a witness, here nk. [ADK] Thm 2 gives round-by-round *knowledge*
  soundness, and with ZK and a random oracle this is the standard route to simulation extractability, but we have not
  proved it for this protocol, and FRI-layer hiding (which the simulator needs) is open. **Stated as an assumption.**

## 12. Stated limits

- 128 bits is **classical**, with the birthday convention for the 256-bit digests; the strict [BGKTTZ] reading is
  127.21. Generic quantum collision search gives about 85 bits for T∘P and SHA-256.
- Every λ is "JB, powers-batching adaptation, unpublished" (§6).
- ZK is by construction; FRI-layer hiding and simulation extractability are not proved (§11).
- The scripts are covered only for canonical proof lanes until §9.1 is fixed.
- Replay of one valid proof in two final transactions is not prevented by the verifier in any layout (Track 9's
  nullifier set). In a′ two transactions, tx0 alone is a partial check, and the baton is a deployment assumption.
- Standardness (for REPORT, not soundness): layout a′ needs no raised limit; M1 b2 needs the per-input unlocking,
  bytecode and stack-item limits raised to 100,000 B; M2 b2 additionally needs the transaction-size limit raised;
  layout b needs the per-input limits raised.

## 13. Open items for the reviews (ordered)

1. **§9.1:** decide and apply a fix (2p offsets or range checks), audit every subtraction site, re-run the S4–S7
   sweeps and op-cost grading. Until then, state the as-built scripts as covered for canonical lanes only.
2. **Write the powers-batching adaptation (Track 5 §2.1) and its two curve extensions (per-height ladders, roll-in
   degree a) as a proof** and have it checked; M2's roll-in has only 0.87 bits of slack.
3. **Simulation extractability** for the CTX lemma: find a published result that covers BCS-compiled, hiding FRI
   STARKs, or state the assumption in REPORT exactly as in §11.
4. Assert ROOT lanes < p in the generator (§9.2).
5. DESIGN §4: "transparent preprocessed" → "recomputable from the published SETUP_SEED".
6. Plonky3's `three_instances_mixed_sizes` coverage vectors are at 127.90–127.92 under our accounting; if they are
   ever cited as more than coverage, they need commit PoW +1.

## 14. Reproduce

```
# zk-verifier-bench, branch wip/stark-usable-design
cd research/pq-stark/design-t8
python3 params8.py                       # S0 tables: tables8-output.{txt,json}
V=<groth16_cashscript wip/stark-usable>/research/pq-stark-batch/prover/vectors
python3 params8.py --asbuilt $V/S2 $V/S4 $V/S5 $V/S7 $V/Z128 $V/P3   # asbuilt8-output.{txt,json}, about 1 s

# groth16_cashscript, branch wip/stark-usable (node_modules: symlink to a libauth 3.1.0-next.8 install)
cd research/pq-stark-batch/onchain && node s8-arith.mjs   # results/s8-arith.json, under 1 s
```

Both need only the standard library (Python) or the repository's own modules (node).
