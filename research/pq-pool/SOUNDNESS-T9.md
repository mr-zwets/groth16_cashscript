# Track 9 / Soundness: the post-quantum shielded pool as built

Date: 2026-11-01. Stage S7a of DESIGN-T9 §6 (zk-verifier-bench `research/pq-pool/DESIGN-T9.md`, "Soundness outline").
Research only; not a leaderboard entry. Constructive: every claim below is backed by an argument from the scripts and
by plain acceptance/rejection tests; no attack was constructed.

- **Code under argument:** groth16_cashscript `wip/pool9b` at 2f8f931 (S4 head), folder `research/pq-pool/`:
  - `d/dcov.mjs` (`buildD`, `flushBlob`, `workerBlob`, `workerLocking`): the D state, the flush coordinator and the
    flush workers;
  - `w/wcov.mjs` (`buildW` with `flushBranch`, `smtCode`): the W state and the nullifier SMT;
  - `r/gena.mjs`, `r/genn.mjs`, `r/ctx.mjs`, `r/layouta.mjs`: the pool's R (Track 8 layout a′ with the Track 9
    changes); unchanged Track 8 modules are imported read-only from `../pq-stark-batch/`;
  - `p2/`: Poseidon2-Gl-8 (T∘P) in CashVM, used by the flush workers;
  - JS references: `w/smt.mjs`, `w/genesis.mjs` (`tree()`), `d/dpool.mjs` (`DState`, `WState`, `flushPlan`).
- **Base:** Track 8's `research/pq-stark-batch/SOUNDNESS-T8.md` (S8b), cited as **T8**. Its λ figures carry the
  label "JB, powers-batching adaptation, unpublished" (T8 §6); so does every use of them here.
- **Input:** the assumptions A1–A5 collected in `README.md` ("Assumptions and known properties"). §6 resolves or
  carries each of them.

## 1. Result

Under the hash assumptions H1–H2 (§2), the Track 8 verifier result (T8 §1: M1, Z128, cap 5, λ_IOP 128.06, digest
128 classical), the deployment checks G (genesis) and T (thread category), and the simulation-extractability
assumption SE (T8 §11), the pool as built has these properties, **per pool**:

| | property | rests on | status |
|---|---|---|---|
| L1 | Exactly one D and one W of the pool category exist at any time; each spend replaces it by its own successor at a fixed output | G; CashTokens rules; D/W successor pins | argument + tests |
| L2 | An accepted withdrawal inserts a key K that was absent from the set nfRoot commits to, and the new nfRoot commits to the set plus K. Key truncation gives only false "spent" | H1; L1 | argument + 10,000-case agreement + rejection families |
| L3 | Every non-empty ring entry is the Poseidon2 root of a prefix (a multiple of 16 leaves) of the pool's own deposit sequence, written by that pool's flush | H1, H2 (for what the root binds); L1; G | argument + root = offline tree (17/17, libauth and BCHN) |
| L4 | An accepted tx0 + tx1 means one Track 8 proof for (ROOT, NF, CTX) was fully verified; knowledge soundness gives nk, r and a depth-30 path from T(P(NF ‖ r)) to ROOT | T8 (128.06 bits), T | cited; S2 sweeps re-run in S4 |
| L5 | One leaf yields one NF | H2 (T8 §11) | cited |
| L6 | Withdrawals ≤ distinct NFs of flushed leaves ≤ 16·flushes ≤ deposits; W pays exactly D per withdrawal and W's value always equals its genesis value + D·(still-withdrawable upper bound) | L1–L5 | argument |
| L7 | tx1's outputs ≥ 1 are bound by CTX; output 0 is fully fixed by W; nobody but the note owner can redirect the payout | T8 Lemma 13 + SE | argument + `out0`/`tx`/`thread` families |

Three deployment-level facts are **not** enforced by any script and must be checked off chain (§6): the pool genesis
(G, A2), the thread category's minting NFTs (T, new as A6), and that a funded pool's ring is never seeded (part of G,
A1). Liveness (§7) is separate from soundness: flushes and relaying are permissionless; censorship is bounded by
self-relay.

## 2. Model, notation and assumptions

**Objects.**
- **CAT**: the pool category, the txid of the outpoint (index 0) spent by the pool genesis. **TCAT**: the thread
  category of Track 8's a′ layout (R's code constant).
- **D**: the D state, P2SH32 (291 B redeem), mutable NFT of CAT, commitment `0x44 ‖ queue ‖ depHash` (65 B).
- **W**: the W state, P2SH32 (671 B redeem), mutable NFT of CAT, commitment `0x57 ‖ nfRoot ‖ histRoot ‖ epoch` (69 B).
- **R**: the pool's verifier, P2S (118 B), Track 8 a′ with code blobs; HEAD is input 0.
- **Worker**: the flush worker, P2S (43 B), running WBLOB (Poseidon2 compression + IO interpreter).
- **D_den** (written D in the scripts' parameter lists) = 1,000,000 sat; **f** = 10,000 sat (regtest values). Below,
  "D" alone means the D state and **δ** the denomination, to keep the two apart.
- **Z** = 32 zero bytes. **p** = 2^64 − 2^32 + 1. **T∘P**: Poseidon2-Gl-8 truncated to 4 lanes (the compression of the
  deposit tree and of M1). **ZH[l]**: the empty-subtree roots, ZH[0] = (0,0,0,0), ZH[l+1] = T(P(ZH[l] ‖ ZH[l])).
- **Tree T_n**: the depth-30 Poseidon2 tree of the first n deposited leaves in flush order, leaf i at index i, empty
  positions = ZH[0].

**Hash assumptions.**
- **H1 (SHA-256):** collision resistance, and no known x ≠ Z ‖ Z with SHA-256(x) = Z (a preimage of the zero digest).
  128 bits classical, about 85 bits quantum (BHT) for collisions.
- **H2 (T∘P):** collision resistance (≈ 255.99-bit output, about 128 / 85 bits; T8 §11), and no preimage of ZH[0]
  under a leaf computation T(P(NF ‖ r)).

**Proof-system assumptions** (carried from T8, not re-proved):
- **KS:** the a′ verifier is round-by-round knowledge sound at λ_IOP = 128.06 for M1 (T8 §1, §5), with the T8 §6 caveat
  on the unpublished powers-batching adaptation.
- **SE:** simulation extractability of the Fiat–Shamir-compiled hiding STARK (T8 §11, Lemma 13, last bullet). Stated as
  an assumption, as in T8.

**Deployment checks** (off chain; §6 gives the full lists):
- **G:** the pool genesis transaction is the reference one (two mutable NFTs of CAT at the reference lockings with the
  empty initial commitments, no minting NFT, no fungible amount).
- **T:** every minting NFT of TCAT is locked by R (T8 Lemma 10's deployment assumption).

## 3. The lemmas

### L1. State uniqueness

**Lemma L1.** Assume G. At every point of the chain, the unspent outputs carrying a token of CAT are exactly two:
one at D's locking (mutable, prefix 0x44, 65 B commitment) and one at W's locking (mutable, prefix 0x57, 69 B
commitment), with no fungible amount. Every transaction that spends one of them creates its successor at a fixed
output: D′ at output 0, and W′ at output 0 (withdrawal) or output 1 (flush).

*Proof.*
1. **Creation.** Under the CashTokens rules, tokens of CAT can be created only by the one transaction that spends
   outpoint (CAT, 0); that outpoint can be spent once, so the genesis is unique. G checks it: exactly two NFTs of CAT,
   both mutable, no minting NFT, no fungible amount. Without a minting NFT no new NFT of CAT can ever be created
   except as the replacement of a spent mutable NFT (one output NFT per mutable input), and no fungible amount of CAT
   can ever exist.
2. **D's successor** (`buildD`, before the branch): D must be input 0; its own category is CAT ‖ 0x01; output 0 has
   D's own locking (`OUTPUTBYTECODE 0 = UTXOBYTECODE self`), category CAT ‖ 0x01 (mutable), fungible amount 0, and a
   commitment equal to the `com` the branch builds, which starts with 0x44 and is 65 B.
3. **W's successor** (`buildW`): withdraw branch: output 0 has W's own locking, CAT ‖ 0x01, amount 0 and the 69 B
   commitment `0x57 ‖ N ‖ histRoot ‖ epoch`. Flush branch: output 1 has W's own locking, CAT ‖ 0x01, amount 0, the
   first 33 B (prefix and nfRoot) unchanged; D's flush blob fixes the full 69 B (`0x57 ‖ nfRoot ‖ histRoot′ ‖ epoch+1`).
4. **Which spends are possible.** By induction only D and W carry CAT.
   - A transaction spending D alone runs D's deposit or flush branch; the flush branch requires W at input 1 (step 5),
     so D alone is a deposit. One mutable input allows one NFT of CAT in the outputs, and output 0 holds it.
   - A transaction spending W alone: the flush branch requires input 0 to carry CAT ‖ 0x01 with prefix 0x44, which by
     induction is D, so W alone is a withdrawal (W's withdraw branch: TXINPUTCOUNT = 6, W at input 5, input 0's locking
     hashes to HR). Its single NFT output of CAT is output 0.
   - A transaction spending both: D must be input 0. W's withdraw branch needs input 0's locking to hash to HR, which
     D's P2SH32 locking does not (H1). So W runs the flush branch at input 1. W's flush branch requires output 0's
     value = D's value − 16(δ + f), which D's deposit branch (value + δ + f) never gives, so D runs its flush branch.
     Two mutable inputs allow at most two NFT outputs of CAT; outputs 0 and 1 hold them.
5. In each case the successor's locking equals the spent one, so the lockings, and every parameter compiled into them
   (CAT, δ, f, HF in D; CAT, HR, δ, f, nIn = 6, wIdx = 5 in W), never change after genesis. ∎

**Consequence (identification).** Under L1, "an input with category CAT ‖ 0x01 and commitment prefix 0x44" is the
real D, and "… prefix 0x57" is the real W. D's flush blob (W at input 1), W's flush branch (D at input 0) and R's W-slot
pin (input 5, A3) all identify the other state this way, without naming its locking.

**Tests.** libauth `d/test-d.mjs`: `deposit` (prefix 0x57, W's locking, immutable NFT, token moved, D at input 1),
`wout`/`dout` (successor fields), `wbranch` (a fake D with another category; a fake W; W's flush branch next to D's
deposit branch), `wpin` (78 cases in the S2 production re-run: a non-W input, another pool's W naming this R, the
pool's category with prefix 0x44); `w/test-w.mjs` `output` and `graph` families. BCHN `t9s4a`: the genesis has exactly
two outputs of CAT, both mutable (`noMintingNft: true`), and its D and W commitments equal the empty JS states
(`checkD`, `checkW`); after every step BCHN's `gettxout` of D and W equals the JS state.

### L2. SMT correctness (nullifier set)

**Definitions** (`w/smt.mjs`, `smtCode`). Depth 64; absent leaf Z, present leaf ONE = 0x01 ‖ 0³¹; H(Z, Z) = Z and
H(l, r) = SHA-256(l ‖ r) otherwise; at level l the node is the right child iff bit l of K is 1. root(S) is the root
of the tree whose present leaves are the keys in S; root(∅) = Z. The key is K(NF) = SHA-256("t9NF" ‖ NF)[0..8).

**Lemma L2.** Assume H1 and L1, and that W's genesis nfRoot is Z (G). Let S_t be the set of keys inserted by the
withdrawals accepted so far. Then W's nfRoot = root(S_t). If a withdrawal with nullifier NF is accepted at state t,
then K(NF) ∉ S_t and the new nfRoot = root(S_t ∪ {K(NF)}).

*Proof.* Induction on the W chain (L1: the only transactions that change nfRoot are W's withdrawals; W's flush
branch keeps prefix and nfRoot). Base: nfRoot = Z = root(∅) by G. Step: W computes K from the NF bytes it reads
(§4, row W5), then the SMT code computes, from the same 64 siblings s_0..s_63 (Z where the bitmap bit is clear, the
next 32 B of S where it is set), the chain o_0 = Z, o_{l+1} = H(order_l(o_l, s_l)) and n_0 = ONE,
n_{l+1} = H(order_l(n_l, s_l)), and requires O = o_64 = nfRoot. The checks that every bitmap bit and every byte of S
are used, and that exactly 64 levels run, make the sibling sequence a function of the witness.
- Let σ_l be the true siblings of K in tree(S_t) and v its true leaf. Both (o_l) and the true chain (h_l) end at
  root(S_t). Going down from level 63: if the ordered pairs (o_l, s_l) and (h_l, σ_l) differ at the highest level
  where they differ, H has a collision there: either a SHA-256 collision or SHA-256(x) = Z for x ≠ Z ‖ Z (the H(Z, Z)
  rule). Both contradict H1. So s_l = σ_l at every level and Z = o_0 = h_0 = v: **K is absent.**
- With the true siblings and leaf ONE, n_64 is root(S_t ∪ {K}), because inserting K changes only the nodes on K's own
  path. W writes N into output 0's commitment (L1). ∎

The script implements H exactly: in loop A (levels below L) every sibling is Z, O stays Z (H(Z, Z) = Z) and N ≠ Z
is hashed with SHA-256; in loop B (levels ≥ L) the level-L sibling is non-Z, so O ≠ Z from there on (H1) and plain
SHA-256 is right for both chains. Leaves and internal nodes cannot be confused because the depth is fixed.

**Double spends.** The same NF gives the same K, so a second withdrawal of NF fails non-membership against every
later state. Two conflicting withdrawals spend the one W outpoint (L1), so at most one confirms; the loser rebuilt on
the new state fails non-membership.

**64-bit key truncation: false "spent" only.** K is a deterministic function of NF, so truncation can never make a
spent NF look unspent. Two different NFs with one K make the second one look spent: a denial for that note, never a
payout. Accidentally this happens with probability about n²/2^65 (≈ 2^−25 at n = 2^20 spends). Aiming it at a given
note needs that note's NF, which stays hidden in leaf = T(P(NF ‖ r)) until its tx0 is published, and then a 64-bit
key match by a note the aimer owns, deposited, flushed and withdrawn before the victim's tx1 confirms (§7). It never
moves funds to the aimer beyond their own deposit.

**Tests.** `w/test-w.mjs` (S4 re-run, `w/results/s4rerun/`): library vs the independent node-store reference,
10,000 cases, 0 disagreements (6,449 inserts, 3,551 present keys; all 65 values of L); W on whole transactions,
10,000, 0 disagreements (7,460 withdrawals, 2,540 already-spent NFs rejected); 203 rejection cases (`nf`, `present`,
`bitmap`, `sibling`, `carry`, …). S2 `nf` family (86: same NF in sequence and in conflicting transactions, every
rejection by W). BCHN: S3 `replay` and `conflict` (re-run `t9s3b`), rejected by W in libauth and by BCHN.

### L3. Ring entries come from the pool's own flushes

**Invariants.** After E flushes and with len leaves queued since the last one (c_1..c_len), the pool state satisfies:
- **(I1)** D.depHash = SHA-256(u32le(16E) ‖ F(T_16E)), where F(T) is the frontier at levels 4..29: F[l] = the left
  node at level l if bit l of the count is 1, else Z.
- **(I2)** D.queue = SHA-256(len ‖ chain), chain = the SHA-256 hash chain of c_1..c_len from Z; 0 ≤ len ≤ 16; every
  c_i is 32 B with every lane < p.
- **(I3)** W.epoch = E; W.histRoot = the 4-level SHA-256 Merkle root of the ring, where slot (e mod 16) holds
  root(T_16(e+1)) for each e in [max(0, E − 16), E − 1] and every slot never written holds Z.

**Lemma L3.** Assume H1, L1 and G (the initial D commitment is `0x44 ‖ SHA-256(0x00 ‖ Z) ‖ SHA-256(u32le(0) ‖ Z^26)`,
the initial W commitment is `0x57 ‖ Z ‖ ringRoot(Z^16) ‖ u32le(0)`). Then I1–I3 hold at every point. In particular
every ring entry ≠ Z is root(T_16e) for some 1 ≤ e ≤ E, a tree made only of leaves deposited into **this** pool, in
deposit order.

*Proof.* Induction over the transactions that spend D or W (L1). G gives the base case (E = 0, len = 0, ring all Z).
- **Withdrawal:** W copies histRoot and epoch byte for byte (`rest`), and D is not spent.
- **Deposit** (D's deposit branch): SHA-256(len ‖ chain) = queue with the witness (len, chain); by H1 these are the
  true len and chain. 0 ≤ len < 16; C is 32 B with every lane < p; the new queue is SHA-256(len+1 ‖ SHA-256(chain ‖ C));
  depHash is copied. So I2 holds with c_{len+1} = C, and I1, I3 are unchanged.
- **Flush** (D's flush branch; HASH256 of the blob = HF, so the code is the reference blob):
  1. *Queue.* The blob folds LV (exactly 512 B) from chain = Z and requires SHA-256(0x10 ‖ chain′) = queue. By H1
     (hash-chain collisions are SHA-256 collisions) len = 16 and LV = (c_1, …, c_16) in order.
  2. *Frontier.* SHA-256(u32le(count) ‖ FR) = depHash with FR exactly 832 B, count % 16 = 0, 0 ≤ count ≤ 2^30 − 16.
     By H1 and I1, count = 16E and FR = F(T_16E).
  3. *Ring.* slot = epoch mod 16 (epoch read from W's input commitment, so = E by I3); RING is exactly 160 B: OLD and
     4 siblings. OLD with the siblings must hash to histRoot; by H1 the siblings are the true siblings of slot E mod 16,
     so histRoot′ = ROOT with the same siblings is the ring root with only that slot replaced. D fixes W′'s commitment
     to `0x57 ‖ nfRoot ‖ histRoot′ ‖ u32le(E + 1)`.
  4. *ROOT is the appended tree's root.* D builds each worker's IO program from LV, count, FR, the 26 zero hashes
     (constants in the blob) and MID = A8 ‖ B4 ‖ H11 ‖ H23 ‖ ROOT ‖ X, and requires that inputs 2..5 have the worker
     locking and that each one's first push is exactly that program (PUSHDATA2 header included). Each worker checks
     HASH256(WBLOB) against its locking, runs the program (every literal is 32 B with lanes < p; `02` computes T∘P of the
     top two nodes; `04 lit` pops and requires equality; the node stack must end empty). So every MID item is the
     value the program computes, the hand-over items (A8, B4, H11, H23) are checked by the worker that computes them
     and re-imported by the next, and ROOT is the output of the frontier append: the 16 leaves give the level-4 subtree
     root; at each level l ≥ 4 the node is compressed as the right child of F[l] when bit l of count is 1, and as the
     left child of ZH[l] otherwise. This is the standard append of an aligned 16-leaf subtree to an incremental Merkle
     tree, so ROOT = root(T_16E+16).
  5. *New frontier.* With l0 the lowest zero bit of count at or above 4, the level function writes F′[l] = Z below l0,
     F′[l0] = X (the node entering level l0, exported by the worker that holds l0) and F′[l] = F[l] above l0, which is
     F(T_16E+16) because count + 16 clears bits 4..l0−1 and sets bit l0. D′'s commitment is
     `0x44 ‖ SHA-256(0x00 ‖ Z) ‖ SHA-256(u32le(count + 16) ‖ F′)`. So I1 and I2 (queue reset, len = 0) hold for E + 1.
∎

**What the roots bind (H2).** By H2, a depth-30 opening of root(T_16e) at position i opens to the i-th deposited
leaf if i < 16e (two different openings at one position give a T∘P collision), and an opening at i ≥ 16e of a
leaf of the form T(P(NF ‖ r)) needs a preimage of ZH[0] or a collision. This is where Poseidon2 collision resistance
enters; the computation of the roots themselves (L3) is deterministic.

**Same Poseidon2 as the AIR.** The workers run S0's T∘P (`p2/`), which matches p3-goldilocks on 1,005 inputs
(`p2/results/`). On BCHN (`t9s4a`), 5 proofs from the Track 8 Rust prover have public ROOT equal to on-chain flush
roots, so the flush computes the same root function as M1's path constraints.

**Tests.** `d/test-d.mjs` (72 cases, 0 unexpected): `seq` (4 flushes over 64 deposits: root = offline tree, a separate
full-tree computation in `w/genesis.mjs` `tree()`, and histRoot = ring of the roots), `premature` (2), `frontier` (7),
`ring` (4), `mid` (7, including consistent wrong claims where only the computing worker rejects), `io` (6), `lane`
(4), `edge` (l0 = 29, count = 2^30 − 16, count = 2^30 rejected, a queued lane = p rejected by worker 1), `wrap`
(root 0 accepted at epoch 16 and rejected at epoch 17). BCHN `t9s4a`: 17/17 flush roots equal the offline tree over
272 deposits; the stale root is rejected by W at epoch 17 (libauth, testmempoolaccept, block).

### L4. The verifier is Track 8's

**Lemma L4.** Assume T. If tx0 and tx1 of the pool's R both accept, with tx1 the final transaction (6 inputs, W at
input 5), then there is one proof π and one statement (ROOT, NF, CTX) such that:
- ROOT, NF are the last-but-one and second-to-last 32 B pushes of tx1's HEAD unlocking, and CTX = CTX(outputs[1..] of
  tx1);
- π passed every check of Track 8 layout a′ (T8 Lemmas 9, 10) for M1 under Z128, cap 5;
- by KS (T8 §1: λ_IOP 128.06, binding round fold1; digest 128 classical, 127.21 strict) and T8 Lemma 11, an extractor
  obtains nk, r ∈ F_p^4, an index and 30 siblings such that NF = T(P(nk ‖ 0,0,0,TAG_NF)), leaf = T(P(NF ‖ r)), and the
  path from leaf to ROOT is valid.

*Why T8 carries over.* The AIR, the VK, the prover's circuit and the wire format are unchanged (`r/README.md`). The
Track 9 changes are on the script side:
1. **ROOT is a statement value, not a VK constant** (T8 §7, row V "ROOT": "Track 9 would read it from covenant
   state"). HEAD checks its size (32 B); every input that runs the transcript (HEAD, CODE, FIN) checks each lane < p
   (T8 relied on a generator assert); the transcript observes it in step 1, before every challenge, next to NF and
   CTX; the CODE inputs pass the lanes to the last-row constraints. Because the whole statement is hashed before the
   first challenge, a prover that picks ROOT adaptively is covered by the same round-by-round bound. What ROOT may be
   is restricted by W (ROOT ≠ Z and in the ring), not by R.
2. **CTX over outputs[1..]** with count n − 1 (`r/ctx.mjs`): Track 8's injective serialization applied to outputs 1..n−1,
   SHA-256 truncated to 28 B. The loop runs at least once, so tx1 needs a payout output. T8 Lemma 13 applies unchanged
   to this output list.
3. **Graph slot and pin.** Inputs 0..4 are R and the input count is 6; input 5 is not R, carries CAT ‖ 0x01 and has
   commitment prefix 0x57 (A3). The thread rules skip input 5 and output 0 (output 0 must not carry TCAT). None of this
   removes a verification check.
4. **The 2p interpreter fix** of T8 §9.1 is in the pool's copy of the generator (`r/genn.mjs` `D_SUB`, `D_NEG`,
   `D_SUBL`, `D_RSUBL`, as in `pq-stark-batch/onchain/genn.mjs`).
5. The prover's explicit-witness case (`m1@LEAF@0@CTX@WIT`) is a witness input, not part of verification.

T8 Lemma 10 leaves two things to the deployment and to Track 9: (a) the thread minting NFT exists only under R
(assumption T, §6 A6), and (b) one proof can drive several tx1 (a second tx0 mints another thread NFT). (b) is stopped
by L2: every tx1 inserts NF.

**Tests.** S2 production sweep re-run in S4 (`r/results/s4rerun/`): 5,055 cases, 0 unexpected (4,912 chain
rejections, 88 required accepts, 55 encoder-only; every Track 8 S7 family plus `root`, `ring`, `nf`, `windex`,
`commit`, `out0`, `wonly`, `wpin`); harness sweep 2,387, 0 unexpected; grading 24/24, one (R, W) pair for all 24
statements. BCHN: S3 re-run `t9s3b` (24/24 and the replay/chain10/race/conflict cases), S4 `t9s4a` (4 withdrawals
with real proofs against flush roots).

### L5. One nullifier per leaf

**Lemma L5** (T8 §11, "Nullifier uniqueness"). NF = T(P(nk ‖ IV_NF)) is a function of nk, and leaf = T(P(NF ‖ r)).
Two extractions with NF ≠ NF′ for the same leaf value give T(P(NF ‖ r)) = T(P(NF′ ‖ r′)), a T∘P collision (H2). So
each leaf value determines at most one NF that can be withdrawn against it.

### L6. Conservation

**Theorem L6.** Assume G, T, H1, H2, KS. At every point of one pool's chain, with E flushes, len queued deposits and
w withdrawals accepted so far:
1. w ≤ 16E, i.e. withdrawals ≤ deposits that have been flushed ≤ deposits;
2. W.value = V_W + δ·(16E − w) and D.value = V_D + (δ + f)·len, where V_W, V_D are the genesis values;
3. each withdrawal reduces W's value by exactly δ, and the outputs of tx1 other than W′ (the payout, an optional
   relayer output) are those the note owner committed to in CTX.

*Proof.*
- **Values.** Deposit: D′ = D + δ + f (D). Flush: D′ = D − 16(δ + f) (D and W both check it), W′ = W + 16δ (D and
  W both check it); the 16f and the worker inputs go to the keeper. Withdrawal: W′ = W − δ (W). No other transaction
  changes D or W (L1). Induction gives (2).
- **Counting.** Map each accepted withdrawal to its NF. The map is injective: two accepted withdrawals with one NF
  would have one K, and the second would fail (L2). By L4 each accepted withdrawal yields (except with the T8 knowledge-soundness error per
  proof) an opening of its ROOT to a leaf of the form T(P(NF ‖ r)). W required ROOT ≠ Z in the ring,
  so by L3 ROOT = root(T_16e) for some e ≤ E, and by the binding remark under L3 the opened position i is < 16e ≤ 16E
  and holds the i-th deposited leaf. By L5 the leaf value at i determines NF, so distinct NFs use distinct positions.
  Hence w ≤ 16E. Deposits not yet flushed are not in any ring tree, so they cannot be withdrawn yet. ∎

**Corollary (solvency).** W's value always covers every note that can still be withdrawn: at most 16E − w of them,
and W holds V_W + δ·(16E − w). Leaves that can never be withdrawn (a malformed leaf, a leaf whose NF was already
used by an equal leaf deposited twice, a note whose K collides) leave their δ in W for good: the depositor's loss,
never another depositor's.

**Per pool, and A1.** L6 is per pool: nothing in a proof names the pool. A note whose leaf was deposited (and paid)
into two pools can be withdrawn once from each, which L6 allows on both sides. A proof against a root that is in pool
X's ring but was never flushed by X is impossible under G, because G requires X's ring to start empty (§6 A1).

### L7. Binding of the withdrawal

**Lemma L7.** In an accepted tx1:
- outputs 1..n−1 are fixed by CTX (final HEAD recomputes CTX from tx1's outputs and the transcript observes it; T8
  Lemma 13: a different output list with the same CTX is a second preimage of 224-bit truncated SHA-256);
- output 0 is fully fixed by W: its locking (= W's), token category and capability (CAT ‖ 0x01), fungible amount (0),
  commitment (`0x57 ‖ N ‖ histRoot ‖ epoch`, with N determined by NF and the current set, L2) and value (W − δ). These
  are all the fields an output has;
- the inputs are the 5 R inputs (unlockings bound to the proof through G and the thread NFT, T8 Lemma 10) and W.

So a relayer or mempool observer who holds π can change only which W state tx1 spends (a race rebuild changes output
0 and W's unlocking, not CTX), the R carrier inputs and thus the fee. Replaying π with other outputs ≥ 1 is rejected
(T8 Lemma 13, "the same proof bytes do not verify for another CTX"). Producing a new proof for the same (ROOT, NF)
with another CTX without knowing nk is excluded **only under SE** (T8 §11; open item in T8 §13.3). The note owner
can always self-relay (§7). ∎

**Tests.** S2 `out0` (208: output 0 changes rejected by W only; race rebuild accepted 26/26; any output ≥ 1 changed
rejected by HEAD), `tx` (104), `thread` (416); BCHN S3 `race` (rebuilt tx1 accepted, byte-identical R unlockings).

## 4. Owner table: every accept-relevant value

"Owner" = the script step that fixes the value (a constant compiled into a locking) or checks it before it can
influence the verdict. Proof-internal values (caps, OOD, PoW witnesses, FRI data, query paths, challenges, layout
hand-overs) are owned exactly as in **T8 §7** (layout a′ column); only the rows Track 9 adds or changes are listed.

**K. Constants** (authenticated by the locking that compiles them; that locking is fixed for the pool's life by L1
and checked once by G)

| value | where compiled | owner / authentication |
|---|---|---|
| CAT | D redeem, W redeem, R (HEAD's W-slot pin) | P2SH32 hash of D and W; R's P2S locking; HR in W |
| TCAT, TTAG | R code | R's locking (T8 §7 row V) |
| HR = SHA-256(R) | W redeem | W's P2SH32 hash |
| HF = HASH256(flush blob) | D redeem | D's P2SH32 hash; the blob is checked against HF before OP_DEFINE |
| WORKER (worker locking) | flush blob | HF |
| H(WBLOB) | worker locking | the worker's P2S locking (= WORKER) |
| δ, f, BATCH = 16 | D redeem, flush blob, W redeem | P2SH32 hashes, HF |
| nIn = 6, wIdx = 5 | W redeem; R (input count per kind) | W's hash; R's locking |
| ZH[4..29] (832 B), Q0 = SHA-256(0x00 ‖ Z) | flush blob | HF |
| MAX_COUNT = 2^30 − 16 | flush blob | HF |
| NF_TAG "t9NF", SMT depth 64, ONE | W redeem (`smtCode`) | W's hash |
| p | D deposit code, worker blob, R | D's hash, H(WBLOB), R |
| T∘P round constants | worker blob (S0 compression) | H(WBLOB) |
| prefixes 0x44, 0x57 | D, W, flush blob, R | as above |

**G. Genesis state** (not script-checkable; owner = the off-chain check G, §6 A2): CAT has exactly two NFTs, both
mutable, no minting NFT and no fungible amount; D at the reference D locking with `0x44 ‖ Q0 ‖ SHA-256(u32le(0) ‖ Z^26)`;
W at the reference W locking (HR of the reference R for (TCAT, CAT)) with `0x57 ‖ Z ‖ ringRoot(Z^16) ‖ u32le(0)`.

**Dp. Deposit transaction** (D at input 0)

| value | owner |
|---|---|
| D's input index | D: INPUTINDEX = 0 |
| D's own token | D: category = CAT ‖ 0x01; commitment 65 B, prefix 0x44 |
| branch | D: DEPTH = 5 (3 items + queue + depHash) selects deposit; otherwise DEPTH = 8 (flush) |
| len, chain (witness) | D: 0 ≤ len < 16; chain 32 B; SHA-256(len ‖ chain) = queue |
| C (leaf) | D: 32 B, every lane < p. Well-formedness (that it is T(P(NF ‖ r)) of a note the depositor owns) has no owner and needs none: a bad leaf is unwithdrawable and only its depositor loses |
| output 0 (D′) | D: locking = own, CAT ‖ 0x01, amount 0, commitment `0x44 ‖ SHA-256(len+1 ‖ SHA-256(chain ‖ C)) ‖ depHash`, value = in + δ + f |
| other inputs and outputs | no owner needed: the depositor's own funds and change |

**Fl. Flush transaction** (D at 0, W at 1, workers at 2..5)

| value | owner |
|---|---|
| flush blob | D: HASH256 = HF, then OP_DEFINE / OP_INVOKE |
| item count | blob: DEPTH = 7 at entry |
| LV (16 leaves) | blob: 512 B, chain fold from Z, SHA-256(0x10 ‖ chain) = queue; lanes < p checked again by the worker literals |
| count | blob: % 16 = 0, 0 ≤ count ≤ 2^30 − 16, SHA-256(u32le(count) ‖ FR) = depHash |
| FR | blob: 832 B, in the depHash preimage |
| MID = A8, B4, H11, H23, ROOT, X | blob: 192 B, split into 6 × 32 B and written into the worker programs; each item checked by the worker that computes it (`04 lit`) and re-imported (`01 lit`) by the next; ROOT by worker 4; X by the worker holding l0 |
| W's identity at input 1 | blob: category = D's own (CAT ‖ 0x01), commitment 69 B with prefix 0x57 (L1); W: INPUTINDEX = 1 in its flush branch |
| nfRoot, histRoot, epoch (read from W) | blob: parsed from W's input commitment |
| RING = OLD ‖ 4 siblings | blob: 160 B; OLD path = histRoot; ROOT path = histRoot′; slot = epoch mod 16 |
| worker inputs 2..5 | blob: UTXOBYTECODE = WORKER; first push = the expected IO (header and length included) |
| worker unlocking | worker: DEPTH = 3 (IO PAD WBLOB), HASH256(WBLOB) = H(WBLOB); IO literals 32 B, lanes < p; final node stack empty. PAD has no effect on the verdict beyond the budget |
| output 0 (D′) | D: locking, CAT ‖ 0x01, amount 0, commitment `0x44 ‖ Q0 ‖ SHA-256(u32le(count+16) ‖ F′)`, value = in − 16(δ + f); W: value = D's value − 16(δ + f) |
| output 1 (W′) | blob: locking = input 1's, category = input 1's, amount 0, commitment `0x57 ‖ nfRoot ‖ histRoot′ ‖ u32le(epoch+1)`, value = W + 16δ; W: locking = own, CAT ‖ 0x01, amount 0, first 33 B unchanged, value = own + 16δ |
| W's branch | W: DEPTH = 0 selects the flush branch; input 0 = CAT ‖ 0x01 with prefix 0x44 |
| keeper outputs, extra inputs | no owner needed: the 16f and the workers' values are the keeper's |

**Wd. Withdrawal tx1** (inputs 0..4 R, input 5 W; output 0 W′, outputs 1.. payout)

| value | owner |
|---|---|
| proof items, transcript, challenges, queries, ACC/TBL hand-overs, thread NFT | R, exactly as T8 §7 (a′) and T8 Lemma 10 |
| ROOT (HEAD push) | R: 32 B, lanes < p (HEAD, CODE, FIN), observed in transcript step 1, read by the DAG's last-row constraints. W: read from HEAD's unlocking tail with exact push headers; ≠ Z; in the ring at `slot` (W4) |
| NF (HEAD push) | R: 32 B, lanes < p, observed, used by the DAG. W: read from the tail; K = SHA-256("t9NF" ‖ NF)[0..8) |
| CTXW (HEAD push) | final HEAD: = `ctxCode` over outputs[1..] (count n − 1, at least one output) |
| HEAD tail = ROOT NF CTXW | W: the last 99 B of input 0's unlocking, three `0x20` headers. R checks every HEAD item's size and pushes are minimal (consensus), so the tail is exactly those items |
| input count, W index | R: input count of the final kind = 6, inputs 0..4 = R, input 5 ≠ R. W: TXINPUTCOUNT = 6, INPUTINDEX = 5 |
| input 0 is R | W: SHA-256(input 0's locking) = HR; R: its own inputs |
| input 5 is the pool's W | R (final HEAD, A3): category = CAT ‖ 0x01, commitment prefix 0x57. W: own category CAT ‖ 0x01 and prefix 0x57 |
| W's own commitment (nfRoot, histRoot, epoch) | W: 69 B parse; nfRoot = O (L2); histRoot = ring root (W4) |
| W1. S, B, L (SMT witness) | W: bitmap 8 B, L checked by shifts, every sibling sent ≠ Z, every bit and byte used, 64 levels; O = nfRoot |
| W4. HS, slot | W: HS exactly 128 B, 0 ≤ slot < 16, ROOT with HS hashes to histRoot |
| W5. key K | W: computed from the NF bytes it read, not a witness |
| output 0 (W′) | W: locking = own, CAT ‖ 0x01, amount 0, commitment `0x57 ‖ N ‖ histRoot ‖ epoch` (bytes copied), value = own − δ. R: output 0 must not carry TCAT |
| outputs 1..n−1 | R: CTX (L7) |
| tx1's other token rules | R: no other input or output carries TCAT (thread burned) |

Values with **no owner by design**: the deposited leaf's well-formedness (above); the keeper's outputs; the PAD
item of workers; the R carriers' values (fee only); and, as in T8 §7, the random-codeword openings and encoder choices
outside the proof bytes.

## 5. How the lemmas use the tests

Tests do not prove the lemmas; they check that the scripts implement what the arguments assume. The counts, with A5's
reading rule (a sweep's "cases" are not all on-chain rejections):

| suite | result | lemmas |
|---|---|---|
| `p2/test-p2.mjs` (S0) | T∘P = p3-goldilocks on 1,005 inputs | L3 (same root function as the AIR) |
| `w/test-w.mjs` (S4 re-run) | 10,000 library + 10,000 transactions, 0 disagreements; 203 rejection cases pass | L2 |
| `r/` production sweep (S4 re-run) | 5,055 cases, 0 unexpected = 4,912 chain rejections + 88 required accepts + 55 encoder-only | L4, L7, A3 |
| `r/` harness sweep (S4 re-run) | 2,387, 0 unexpected | L4 |
| `d/test-d.mjs` | 72 cases, 0 unexpected | L1, L3, L6 (values) |
| BCHN `t9s3b` (S3 re-run) | 24/24; replay and conflict rejected by W; race rebuild accepted; 76/76 allowed | L2, L7 |
| BCHN `t9s4a` | genesis checked; 272 deposits, 17 flushes (root = offline tree), 4 withdrawals; stale root rejected; 299 allowed | L1, L3, L4 |

## 6. Assumptions A1–A5 (README), resolved or carried

**A1. Ring roots are unique to one pool. Resolved, with one deployment rule moved into G.**
- L3 shows that every ring entry of a pool is the root of that pool's own deposit tree, provided the ring starts
  empty. G now includes "W's genesis histRoot = ringRoot(Z^16)" and "D's genesis count = 0", so the deployment rule
  ("never seed a funded pool's ring") is part of the genesis check, not a separate promise.
- What remains is by design and harmless to L6: a note whose leaf was deposited into two pools can be withdrawn once
  from each; each pool paid out only what it received for that leaf.
- S1–S3's static genesis tree (a seeded ring) is a test fixture that fails G on purpose (pool B in S3).
- Making NF pool-specific would need an AIR change; it is not needed for L6.

**A2. W's (now D's and W's) state uniqueness rests on an off-chain genesis check. Carried as assumption G, fund
relevant.** A script cannot see that no minting NFT of CAT exists. With one, a forged W could receive a flush's 16δ, or
a forged D could drive W's flush branch. Wallets, depositors and relayers must check, once per pool, from the genesis
transaction (the unique spender of outpoint (CAT, 0)):
1. exactly two outputs carry CAT; both are mutable NFTs, without fungible amount; no output carries a minting NFT of
   CAT;
2. output 0 is at P2SH32(buildD({CAT, δ, f, HF})) with HF = HASH256 of the reference flush blob for (δ, f, WORKER),
   commitment `0x44 ‖ Q0 ‖ SHA-256(u32le(0) ‖ Z^26)`;
3. output 1 is at P2SH32(buildW({HR, CAT, δ, f, nIn: 6, wIdx: 5})) with HR = SHA-256 of the reference R for (TCAT, CAT),
   commitment `0x57 ‖ Z ‖ ringRoot(Z^16) ‖ u32le(0)`.

S4's BCHN run did (1) through BCHN's token decoding and (2)–(3) by comparing `gettxout` with the JS empty states built
from the same reference builders. A standalone checker for wallets does not exist yet (§8).

**A3. R pins W. Closed in S4.** The final HEAD checks input 5's category CAT ‖ 0x01 and prefix 0x57; under L1 that is
the pool's W. Owner rows in §4 (Wd: "input 5 is the pool's W"); tested by `wpin` (78 cases). The cost is a pool-specific
R (+46 B per transaction; +92 B of OP_DEFINE charge per R input).

**A4. Scope of the BCHN policy checks. Carried as a test-scope note; no soundness effect.** Policy (testmempoolaccept)
covers every withdrawal (S3), and the S4 genesis, deposits, flushes and withdrawals (299). The funding transactions
(deposit inputs, worker UTXOs, R carriers, the thread NFT) were mined through submitblock from bare-OP_1 coinbases.
They are not covenant transactions and no lemma depends on them.

**A5. How to read the sweep totals. Carried as a reading rule** (used in §5): 5,055 = 4,912 chain rejections + 88
required accepts + 55 encoder-only relabels (malformed-by-length proofs whose on-chain witness is the valid one).

**A6 (new). The thread category's minting NFTs exist only under R. Carried as assumption T, fund relevant.** This is
T8 Lemma 10's deployment assumption. tx1 alone is a partial check (it re-runs the transcript, FIN and queries 21..23,
but not the AIR identity or queries 0..20, which tx0 checked); the thread NFT is what ties tx1 to an accepted tx0. If a
minting NFT of TCAT existed outside R, that tie would not hold, and L4, hence L6, would not follow. In the S3/S4
regtest rig the node faucet keeps a minting NFT of TCAT at an OP_1 output to fund thread batons: a rig fixture that
fails T on purpose, like the static ring of A1. A deployment must create TCAT with its minting NFTs locked by R only,
and wallets must check TCAT's genesis like CAT's.

## 7. Liveness and properties outside soundness

- **Flushes are permissionless** and paid (16f to the keeper). Deposits stall at len = 16 until someone flushes; there
  is no partial flush or refund. The tree holds 2^30 leaves (count ≤ 2^30 − 16 per flush check), i.e. 2^26 flushes,
  after which flushes, and so deposits beyond the queue, stop.
- **Root expiry.** A proof's ROOT leaves the ring 16 flushes after it was written. The note is not lost: the tree only
  grows, so the owner re-proves against a newer root (BCHN `t9s4a`, note 9).
- **Relaying.** A relayer can censor but not redirect (L7); the owner can self-relay. R carriers and thread batons
  must exist under R (A6). W is a single UTXO: withdrawals serialize, and losers rebuild tx1 without re-proving
  (S3 `race`).
- **Key collisions** (L2) are denial only, never theft. A targeted one needs a revealed NF and a 64-bit key match by a
  note the aimer deposited and gets flushed before the victim's tx1 confirms; publishing tx0 and tx1 together keeps that
  window to one confirmation.
- **Privacy** is not part of this document's claims: leaf hiding and ZK are as in T8 §11 (FRI-layer hiding not
  analysed); the anonymity set is per pool and grows in 16-leaf flushes.
- **Reorgs** are safe: every state transition is a covenant transaction that is re-validated; relayers rebuild.
- **Quantum:** collision resistance of SHA-256 and T∘P is about 85 bits generically (BHT); the 128-bit figures are
  classical (T8 §12).

## 8. Stated limits and open items

1. **SE is assumed** (L7), as in T8 §13.3.
2. **The powers-batching adaptation is unpublished** (T8 §6, §13.2); every λ here inherits the label.
3. **G and T are off-chain checks** with no standalone checker yet. Writing one (decode the two genesis transactions,
   rebuild the reference lockings and initial commitments, compare) is the natural S5 relayer/wallet task.
4. **The append correctness in L3** is argued for the algorithm and tested (17/17 over 272 deposits, edge cases at
   l0 = 29 and count = 2^30 − 16); it is not machine-checked.
5. **L6's counting step** applies knowledge soundness once per accepted withdrawal; a formal multi-proof extraction
   bound (w proofs, each at the T8 error) is not written out.
6. Unchanged from the build stages: the flush is 42 KB in one transaction under today's rules; the withdrawal is
   132,904 B in two transactions; BCHN timing was not measured.

## 9. Reproduce the evidence

```
cd research/pq-pool
node p2/test-p2.mjs                       # S0: T∘P vs p3-goldilocks
node d/test-d.mjs                         # L1, L3, L6 (14 s)
./rerun-s4.sh                             # S1 test-w and S2 grade/sweeps re-runs (L2, L4, L7)
cd node && ./run-s4.sh NAME 9 7 --wrap    # BCHN (with S2_VEC, PROVER, S4_CACHE, OPCOST_DIR set; d/README.md)
```
