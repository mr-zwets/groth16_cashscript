# chunked/bls12-381/ — BCH-native multi-transaction BLS12-381 Groth16

The Groth16 verifier on **BLS12-381** (the same curve as nchain) split across
transactions so **every step fits one BCH input** (op-cost ≤ 8,032,800,
locking+unlocking ≤ 10,000 B). The BLS12-381 counterpart of the BN254
`../pairing/` work, and the chunked form of the monolithic `../../singleton/bls12-381/`
oracle. Four benchmark entries (in the verifier repo) are produced from here:

- **`bch-vkx-bls12381-chunked-covenant`** — the public-input aggregation
  `vk_x = IC0 + in0·IC1 + in1·IC2` (G1 multi-scalar-mult), 11 chunks / 22,277 B / 6,808,579 op-cost.
- **`bch-pairing-bls12381-chunked`** — the **Miller loops + final exponentiation**:
  `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)` as one prepared-VK 4-pair Miller product →
  the BLS/Hayashida-Scott final exponentiation → verdict (== Fp12 ONE). 51 chunks / 470,061 B / 372,314,128 op-cost.
- **`bch-groth16-bls12381-chunked`** — the **complete verifier**: five stage-bound GLV vk_x
  chunks prepended to an input-validated Miller namespace. 56 chunks / 484,519 B /
  377,785,509 op-cost; ranked in the main Groth16 leaderboard against nchain (its
  BLS12-381 reference).
- **`bch-groth16-bls12381-chunked-covenant-residue`** — the source-owned standard-VM
  covenant graph: five full-stage GLV chunks -> input-validation-fused residue Miller -> the
  one-input Fp6 residue verdict. It enforces a minting-baton genesis, one mutable state
  thread, fixed P2SH32 successor pins, and an immutable terminal verdict. 27 steps /
  208,340 B / 157,706,001 op-cost.

The separate 29-chunk input-unvalidated pairing and input-validated full Miller namespaces
also feed the linked layouts assembled by the sibling `intratx/` and `grouped/` builders:

- `bch-pairing-bls12381-intratx`: 51 inputs / 465,462 B / 372,116,160 op-cost.
- `bch-groth16-bls12381-intratx`: 56 inputs / 475,310 B / 377,658,775 op-cost.
- `bch-groth16-bls12381-intratx-fs-compact`: compact Fiat-Shamir PIT candidate, 22 inputs / **69,947 B score / 69,177 B wire / 42,969,175 committed native-standard op-cost**; maximum supplied native-standard 57,059,203 (Libauth standard 56,959,761); dense observed 90,107 B score / 89,337 B wire. This is finite source/native corpus evidence, not a universal resource or live-admission claim.
- `bch-groth16-bls12381-grouped`: 56 inputs / 6 standard transactions / 475,292 B /
  377,556,467 op-cost.
- `bch-groth16-bls12381-intratx-residue`: quotient-torus frontier, 24 inputs / 192,317 script B /
  193,369 score B / 192,529 wire B / 151,427,800 op-cost. The unchanged default Fp6-tail path remains reproducible at 35 inputs /
  209,216 B / 157,700,169 op-cost.
- `bch-groth16-bls12381-grouped-residue`: 26 inputs / 3 standard transactions / 204,424 script B /
  205,734 score B / 204,894 wire B / 160,953,436 op-cost.
- `bch-groth16-bls12381-intratx-residue-large`: 3 inputs / 164,426 script B / 164,579 score B /
  164,474 wire B / 149,814,405 op-cost on the proposed 100 kB-script VM; non-standard by total size.

## Nine-input Fiat-Shamir candidate

`RPA_FUSE_COORDINATOR_HEAD=1 RPA_CACHE_COORDINATOR_PREFIX=1 RPA_PIC_ZERO_MASK=1`
selects the minimum-byte nine-input layout. The pinned scheduled compiler is
`efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4`. Set the cache mode to `fields`
for the lower-cost alternative:

| Cache mode | Total bytes | Native consensus primary | Native standard primary |
| --- | ---: | ---: | ---: |
| Combined prefix (`1`) | **60,285** | 37,816,994 | 37,986,594 |
| Separate fields (`fields`) | 60,308 | **37,719,760** | **37,889,360** |

Script/overhead splits are 59,878/407 and 59,901/407 bytes;
spend transactions are 59,970 and 59,993 bytes. Separate
fields spend 23 bytes for 97,234 fewer primary native units in either mode.
The ten- and eleven-input profiles remain reproducible with their existing flags.

The quotient head shares root input 0 with the coordinator. The root checks the
ordered eight-worker locking commitment inline before loading complete
coordinator code from four existing funding carriers and a literal First/Tail
overflow push. Imported code excludes the expected worker hash, avoiding a hash
fixed point. The root reuses the existing guarded arithmetic ABI. All 21 logical
stages and all 46 archived proof argument pushes keep their values and encodings.

Each input caches only bounded encoded root data. Mode `1` installs one literal
870-byte prefix data function under raw key `0x67`. Mode `fields` installs literal
130-byte header and 740-byte statement data functions under unused raw keys
`0x67`/`0x68`. Witness bytes never execute. Only exact bounded header/statement
reads are rewritten; full-root, quotient and predecessor reads stay unchanged.
The inline framing check and final sibling commitment protect imported code.

`RPA_PIC_ZERO_MASK` defaults off and requires coordinator-head fusion. After the
existing canonical scalar range checks, the coordinator forms the bitwise OR
of the two fixed-width 32-byte public scalars and appends a zero sign byte before
conversion to an integer. For each unsigned byte pair, their sum is zero exactly
when their OR is zero. The mask replaces repeated two-scalar extraction only in
zero-window record-length decisions. Authenticated PIC digits, payloads, roots,
challenges and all raw proof arguments remain unchanged. Coordinator code shrinks
from 4,196 to 3,855 bytes, reducing First/Tail overflow by 341 bytes. Both profiles
save 341 total bytes and 38,690/39,330 primary consensus/standard native units.
Disabling the mask reproduces the previous 60,626/60,649-byte normal primary
exports exactly. Cache bodies, function keys and shared arithmetic are unchanged.

Each profile passes ten archived source fixtures and 3,520 owning/whole rejection
checks. Actual native replay covers 1,090 contexts per profile: 20 accepted and
1,070 rejected, with all 180 positive input prices reconciled. Every matched
archived fixture improves on its previous same-profile native cost. All 173 old
invalid transactions remain represented with every direct and nested origin;
current source and all five code-carrier trust boundaries retain their controls.
Maximum sampled native consensus/standard costs are
49,462,972/49,811,132 for combined prefix and
49,365,738/49,713,898 for separate fields.
Minimum sampled per-input margins are
54,639/48,751 and
75,479/69,591, respectively.
Maximum sampled scores are 80,445 and 80,468 bytes.
These are finite corpus results, not arbitrary-proof resource bounds, a universal
soundness theorem, or a live-relay result. Existing FS-PIT, G2/G1 validation grades
and campaign limitations remain unchanged. Nine physical inputs remain required
by these layouts; no eight-input admission is claimed.

Run from this directory with the compiler above. Grouped regular inputs ignore
the legacy compact-padding map below; the grouped coordinator carriers contain
authenticated code bytes.

```sh
RPA_COORDINATOR_DENSITY_PADDING='0' \
RPA_EXPORT_RESOURCE_BYTECODES='1' \
RPA_INVERSES='off' \
RPA_PIC32='1' \
RPA_PIC_BLOCK2_DENSITY_PADDING='0' \
RPA_PIC_BLOCK4_DENSITY_PADDING='0' \
RPA_PIC_LAYOUT='regular' \
RPA_Q_TAIL_COEFFICIENTS='22' \
RPA_REGULAR_DENSITY_PADDING='{}' \
RPA_SKIP_GAMMA='1' \
RPA_TEMPLATE_FACTOR_DENSITY_PADDING='0' \
RPA_TEMPLATE_RUN='1' \
RPA_TEMPLATE_TAIL_DENSITY_PADDING='0' \
RPA_TEMPLATE_TERMINAL_DENSITY_PADDING='0' \
RPA_COMPACT_ARITHMETIC_PRIME_KEY='-1' \
RESCHEDULE='on' \
RPA_COMPACT_REGULAR_DENSITY_PADDING='{"3": 288, "5": 281, "6": 229, "7": 0, "8": 0, "9": 225, "10": 226, "11": 234, "12": 229, "13": 236, "14": 252, "16": 262, "17": 232, "18": 236, "19": 0}' \
RPA_TEMPLATE_COMMON_PRIME_POOL='on' \
RPA_PROOF_FIXTURE='committed' \
RPA_TEMPLATE_TERMINAL_PRIME_POOL='on' \
RPA_FUSE_FINAL_PAIR='1' \
RPA_SCHEDULE_COORDINATOR='1' \
RPA_GROUP_DENSITY_PADDING='0' \
RPA_FUSE_REGULAR_PAIR='1' \
RPA_SCHEDULE_PIC_AUTH='1' \
RPA_FUSE_REGULAR_PAIRS='1' \
RPA_FUSE_REGULAR_TRIPLES='1' \
RPA_FUSE_CARRIER_PAIR='1' \
RPA_FUSE_MIDDLE_PAIR='1' \
RPA_ARITHMETIC_REGULAR_CARRIER='1' \
RPA_FUSE_FIRST_TAIL_PAIR='1' \
RPA_BUNDLE_REGULAR_MAIN='1' \
RPA_LAZY_PAIR_PRODUCT='1' \
RPA_FUSE_RELATIONS='1' \
RPA_FINAL_RELATION_TOTAL='1' \
RPA_EVAL6_PAIRED='1' \
RPA_COORDINATOR_TAIL_BYTES='0' \
RPA_FUSE_COORDINATOR_HEAD='1' \
RPA_CACHE_COORDINATOR_PREFIX='1' \
RPA_PIC_ZERO_MASK='1' \
RPA_TEMPLATE_CASHC='/path/to/zk-language/packages/cashc/dist/compiler.js' \
node measure_d3_two_chart_binary.mjs
```

## FS-PIT soundness argument (intra-transaction `-fs` family)

*Added 2026-10-27 by the verifier.cash maintainers from a constructive review of the shipped
code: no exploit or forgery was attempted. The text above is unchanged. It disclaims a
universal theorem for resources, live relay and the finite corpus; this section gives the
written soundness argument for the accept decision. It does not change any resource claim.*

**Scope.** The 13 benchmark ids `bch-groth16-bls12381-intratx-fs` and `-fs-{compact,
fused-final, fused-regular, fused-regular-pairs, fused-regular-pairs-packed,
fused-regular-triples, fused-carrier-pair, fused-middle-pair, fused-first-tail,
regular-initializer, fused-coordinator-head, fused-coordinator-head-fields}`. All are produced by
`measure_d3_two_chart_binary.mjs` (below: `m:`*line*). Line numbers refer to `9c1f0fe`. The
`chunked/bls12-381/*.mjs` files are byte-identical between `9c1f0fe` and current `main`. Older
pinned revisions contain the same emitter text at other line numbers. The differences that matter
are listed in "Per-revision differences".

**Claim.** Fix the verification key and the 9 to 22 locking programs of one id. Suppose a
transaction spends the root/coordinator locking at input 0 and every input passes the BCH 2026
VM. Then, except with the probability bounded in step 5, the statement's `(A, B, C, in0, in1)`
satisfies `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) = 1` with `vk_x = IC0 + in0·IC1 + in1·IC2`. Here B is
in G2 and A, C are on-curve. Only the root is anchored: spending the worker UTXOs without the
genuine root proves nothing.

### 1. Algebra (exact)

`Fp6 = Fp[Y]/m`, `m = Y⁶ − 2Y³ + 2`, `Fp12 = Fp6[W]/(W² − Y)`. This is a field: the generator
asserts that Y is a non-square in Fp6 (`m:627-631`). `../../BLS_PROJECTIVE_GT_MATH.md:15` gives the
tower irreducibility. Let `Q = Fp12*/Fp6*`, cyclic of order `p⁶+1`. The map `[f] ↦ f^(p⁶−1)`
identifies Q with the order-`(p⁶+1)` subgroup, so `f^((p¹²−1)/r) = 1 ⇔ [f]` is an r-th power in
Q. Let `λ = p + |x|`. Then `gcd(λ, p⁶+1) = r` (`prove_miller_torus.mjs:51-53`), so the λ-power
image in Q is exactly the r-th powers. Hence **if `[F] = [c]^λ` for some c, then F lies in the
final-exponentiation kernel**.

**Relations.** Every Miller block keeps a pair `(s0, s1) ↔ s0 + s1·W`. Its in- and out-states are
canonical charts: flag 0 means `[1 : u]`, flag 1 means `[0 : 1]` with `u = 0` forced
(`m:389-425` generator; on-chain `m:1518-1521`, split `m:1568-1571`). Each block applies these
factors:
- squarings;
- line factors `1 + t·W` (`lineEval`, `m:1329-1338`);
- root folds `1 ∓ u_c·W`;
- the fixed fold `1 + u_fix·W` (`m:1772-1773`);
- projective PIC factors `D' + N'·W`. `D' ≠ 0` holds universally for every canonical parameter
  tuple (`../../BLS_PROJECTIVE_GT_MATH.md:66`; `applyCompressed`, `m:1450-1465`);
- the zero-window scale `9·Y²` (`m:1903`). This is exactly the decoder output for the
  designated identity encoding `s = t = 0`, scaled by `9ξ` (`../../BLS_PROJECTIVE_GT_MATH.md:70,83`).
  More simply, `9·Y²` is a nonzero element of Fp6, so its class in `Q = Fp12*/Fp6*` (below) is
  the identity.

All these factors are nonzero field elements, so every block state is nonzero. The block's cross
relation is `other − selected·u_out ≡ 0 (mod m)` (`m:1730-1735`). With flag 0 this forces
`s0 ≠ 0` and `[s] = [1 : u_out]`. With flag 1 it forces `s0 = 0` and `[s] = [0 : 1]`. No inverse
witness is needed (`RPA_INVERSES=off`, asserted at `m:192`). There are 24 relations: 21 block
cross relations, the two split relations of blocks 0 and 15, and the terminal relation. Together
they give `[c^(−|x|) · M · PIC · fixed] = [frob(c)]`, where:
- block 0 starts from `1 − u_c·W` (`m:1617-1620`);
- the round and fold schedule is the binary expansion of `|x| = 0xd201000000010000` (asserted
  `m:572-580`);
- the terminal is `torusFrobFlat(root)` (`m:1775-1778`).

So `[M·PIC·fixed] = [c]^λ`, and by the paragraph above the final exponentiation of `M·PIC·fixed`
is 1. Here M is the product of the runtime `(-A, B)` and fixed `(C, δ)` line classes. The line
factors are the affine line functions scaled by elements of Fp4*, which the final exponent
kills (`prove_miller_unit_lines.mjs:1-11`). PIC is the authenticated GT table product (step 3).
`fixed` is the VK constant for `e(α,β)·e(IC0,γ)` (`m:626`). Together they reproduce the four-pair
Groth16 product, up to elements killed by the final exponentiation.

**G2 / G1 domain (exact).** The coordinator range-checks every statement field
(`m:2112-2116`). It checks B on the twist (`m:2134-2141`) and A, C on the unit curve
`v = 4u³ + 16v³` (`m:2143-2150`). The unit curve is in bijection with E(Fp) because `#E(Fp)` is
odd; `(0,0)` is O. B is walked in affine coordinates with exact slope equations and nonzero
guards (`pointDoubleAffine`/`pointAddAffine`, `m:1340-1373`). A guard `x ≠ 0` decides
`x ≢ 0 (mod p)` whenever `|x| < p`, and every guarded operand satisfies this: each is a statement
limb range-checked into `[0, p)` by the coordinator (`m:2112-2116`), a predecessor `outR` limb
that is range-checked (`m:1527-1529`) and pinned by integer equality to a computed value
(`m:1729-1730`), or the result of a CashScript `% P` (`mAdd`/`mSub`/`mulFp`), which lies in
`(−p, p)`. The remaining guards are `effectiveBSum` (a sum of range-checked nonnegative fields)
and the committed β (256 bits, below p). All other checks are integer equalities, which imply
congruence. The walk
therefore computes `[|x|]B` exactly, and the terminal requires `outR = −ψ(B)`
(`m:1757-1758`), i.e. `ψ(B) = [x]B`. That implies B ∈ G2 \ {O}: `gcd(λ, h2) = 1`
(`../../qsplit_soundness_audit.mjs:42-44`, `../../psi-subgroup-degeneracy.md`). `Bidentity = 1` forces the
fixed substitute B and zeroes the `(-A)` units, so that pair contributes 1 (`m:1509`,
`m:2129-2133`). A and C are cofactor-equivalent: their cofactor components pair to 1, as already
disclosed above and in `verifiers.md`.

### 2. Transcript (what is committed before each challenge)

All transcript hashes are SHA-256 with framing `MAGIC ‖ len(tag) ‖ tag ‖ u32(len) ‖ payload`
(`m:302-307`).
- **Pre-β** (`commitmentRoot`, `m:999-1016` generator, `m:2045-2077` on-chain). This is a
  Merkle tree over 22 leaves: the 737-byte statement (`m:967-995`: `Bidentity`, effective B,
  `in0`, `in1` as 32-byte LE, the root `u_c`, and the unit coordinates of A and C, each
  fixed-width), followed by the 21 block payloads. Each leaf is `frame('leaf', u32(index) ‖
  u32(22) ‖ u32(length) ‖ payload)`; each node is `frame('node', u32(level) ‖ u32(index) ‖ L ‖
  R)`. A payload holds everything the block's residuals depend on that is not a constant: the
  out-chart, `outR`, the runtime slopes, the split chart, the PIC records, and the fixed line
  coefficients. The fixed coefficients are additionally pinned by `sha256(fixedBlob) ==
  fixedCommitment`, a redeem constant (`m:1835-1837`, `m:3211-3222`). The coordinator recomputes
  the root from the workers' raw unlocking bytes, with exact PUSHDATA2 headers and the following
  `0x30` evaluation push (`m:2154-2181`). It then requires `committedRoot == root` and
  `β = H(frame('beta', u32(21) ‖ root))`, nonzero (`m:2110`, `m:2247-2250`).
- **Pre-α**: `qroot`, a one-leaf tree over the 132 quotient coefficients. They are 48-byte,
  range-checked (`m:2013`), carried as a 110-coefficient head and a 22-coefficient tail with exact
  lengths (`m:2186-2227`). The coordinator requires `α = H(frame('alpha', root ‖ qroot))`
  (`m:2251-2252`). β and α are read as unsigned 256-bit LE integers, which are below p
  (`m:200`).
- **Fixed by exact equations, not committed**: the 48-byte running evaluation sums. Each block
  requires `previous + Σ β^e·R_e(α) == own` (`m:1603`, `m:1795`), block 0 starts at 0, and the
  final quotient check is `Q(α)·m(α) == total` (`m:2026-2036`). All workers read β and α from the
  root's 128-byte header (`m:1484-1486`).

### 3. GT table (Merkle binding, VK-derived)

Window j (0..31) uses byte j of both canonical 32-byte scalars. `in0, in1 < r` is checked by the
coordinator, the PIC helper and every Regular worker (`m:1876-1878`, `m:2544`). The leaf is
`H('BLSGTP1' ‖ 'L' ‖ block ‖ window ‖ digits ‖ factor192)`. The 16-level path with
`'BLSGTP1' ‖ 'N' ‖ level ‖ parent` nodes is walked from `globalIndex = digits ‖ window` and must
end at `globalIndex == window` (`m:2573-2591`). Each window root is grouped into one of six batch
commitments `H('BLSGTP1' ‖ 'B' ‖ first ‖ count ‖ roots)`, and these are literal constants of the
helper (`m:2502-2508`, `m:2592-2597`). Six hosts run the helper (coordinator, blocks 0, 1, 2, 15,
20). Each pushes its own constant `(first, count)`, and the six batches partition 0..31
(`m:2489-2500`, `m:3809-3900`). The window roots are VK-derived (`prove_gt_window_preimage.mjs`;
the blob hash is asserted at `m:2485`). Reviewers independently recomputed all 32 roots.
Outside the event COLL of step 5 (lemma (a)), each authenticated factor is the table entry for
(block, window, digits).

**Zero windows (from `1003775`).** A window whose two digit bytes are both zero carries a 32-byte
record instead of a 704-byte one. The length is derived three times from the committed statement:
- coordinator: `(in>>8j)%256` sums, or the OR mask `m:2154` from `9c1f0fe` (`m:2160-2171`);
- worker: `digits == 0x0000` (`m:1883-1891`);
- PIC helper: `m:2551-2559`.

These three derivations agree because byte j of the LE encoding is `(in >> 8j) mod 256`. The
coordinator puts the derived length into the leaf metadata and checks the push header. The
helper requires the 32 bytes to equal the window root itself (`root = record`, `m:2573`), so they
are fixed by the batch commitment. The worker multiplies by the identity representative `9Y²`
(step 1). This is correct because the window's GT contribution `e(0, γ)` is 1.

### 4. Degree

`segmentDegreeCeiling` (`m:816-858`) propagates the degrees in Y of the formal polynomials
evaluated on-chain:
- line, fold and fixed factors have degree ≤ 5;
- projective PIC factors have `deg D' ≤ 5` and `deg N' ≤ 4`;
- the zero-window `9Y²` is dominated by the PIC bound.

It covers both input charts. The universal maximum relation degree is 137 (asserted
`m:932-934`), so the quotient has ≤ 132 coefficients. On-chain, every residual is computed as
the evaluation at Y = α of a polynomial `R_e(Y) ∈ Fp[Y]` (`eval6`, `pairSquareEval`,
`pairMulEval`, `lineEval`, `applyCompressed`: `m:1314-1338`, `m:1450-1465`). Evaluation is a ring
homomorphism, and every coefficient comes from step-2 commitments or constants. The 24
relations get the distinct β exponents 0..23:
- split 0 → 0, cross 0 → 1;
- block k → k+1 for k = 1..14;
- split 15 → 16, cross 15 → 17;
- block k → k+2 for k = 16..20;
- terminal → 23.

Sources: `m:1062-1100` generator; `m:1391-1447` on-chain. In the Regular template, `blockIndex` is
a redeem constant (`m:3211-3215`).

### 5. Fiat–Shamir bound (random-oracle model)

**Game.** SHA-256 is a random oracle H (SHA-256 is Merkle–Damgård; as usual for Fiat–Shamir,
we idealize it as a random oracle, and no secret-prefix MAC use occurs here), sampled lazily: an
output is drawn uniformly from `{0,1}²⁵⁶` when its input is first evaluated, independently of
everything evaluated so far.
Every SHA-256 evaluation by any party is a query; `OP_HASH256` is two. There are three kinds:
- **Setup** (N₀ queries, made first): the hashes that fix the deployed anchors. These are the GT
  table (32 windows of at most 2¹⁶ leaves and 2¹⁶−1 nodes, `prove_gt_window_preimage.mjs:43-48`),
  the six batch commitments (`m:2502-2508`), the fixed-blob commitments (`m:789`), the P2SH32
  redeem hashes and the sibling-locking digest (`_coordinator_binding.mjs:2-8`). N₀ < 2²² + 2⁷.
- **Adversary** (q_A queries): adaptive, in any order.
- **Verifier** (q_V queries): every SHA-256 evaluation the VM performs on the submitted
  transaction. The transcript part is 22 leaf and 23 node hashes for `root` (22→11→6→3→2→1,
  `m:999-1016`), one leaf hash for `qroot`, β and α (`m:2246-2252`). The rest are the GT path
  and batch checks (at most 32·17 + 6, `m:2573-2597`), the fixed-blob checks (`m:1835-1837`),
  the sibling digest, and two per input for P2SH32. For the shipped transactions q_V < 2¹⁰
  (48 transcript, ≤ 550 GT, ≤ 21 fixed-blob, 1 sibling digest, 44 P2SH32), so with q_A = 0 the
  bound is below 2⁻²¹¹.

Let `q = q_A + q_V`, `N = N₀ + q`, and let `q_β, q_α ≤ q` count the distinct `beta`- and
`alpha`-frame inputs among the q queries. An accepting run has `q_β, q_α ≥ 1` even when
`q_A = 0`. A challenge or opening that the adversary never queried is evaluated by the
verifier and counted in q_V, so there is no separate guessing term (`ε_guess = 0`).

**Bound.** Pr[every input passes and the pairing equation of the Claim fails] ≤
`ε_SZ + ε_binding`, where `ε_SZ = (23·q_β + 160·q_α)/2²⁵⁶ ≤ 160·q/2²⁵⁶` and
`ε_binding = N(N−1)/2²⁵⁷ + N(N−1)/2²⁵⁶`. For example, q ≤ 2⁶⁴ gives less than 2⁻¹²⁶.

**Binding events (ε_binding).**
- **COLL**: two distinct queried inputs have the same output. Probability ≤ `N(N−1)/2²⁵⁷`.
- **LATE**: an output equals a *child* of an input queried earlier. The children of a
  transcript frame are L and R of a `node` frame, `root` of a `beta` frame, and `root`,
  `qroot` of an `alpha` frame; other inputs have none. Frames parse uniquely
  (`MAGIC ‖ len(tag) ‖ tag ‖ u32(len)`, `m:302-307`). The j-th distinct input (a fresh
  sample) has at most 2(j−1) targets, so the probability is ≤ `Σ 2(j−1)/2²⁵⁶ = N(N−1)/2²⁵⁶`.

No domain separation between hash kinds is assumed. COLL covers equal outputs across all of
them, and LATE counts the children of every input that parses as a transcript frame, whatever its
origin. The prefixes are distinct anyway: `BLS12-381-RPA-v2` (`m:162`) for transcript frames,
`BLSGTP1` (`m:466`, `m:2456-2457`) for the GT table.

**Lemma (binding and order).** Outside COLL ∪ LATE:
- **(a) Fixed anchors.** Every opening the verifier accepts against a deployed constant equals
  the setup opening. This covers the GT factor for (block, window, digits) (step 3), the fixed
  blob, the sibling lockings and the P2SH32 redeems (step 6). Walk down from the anchor. The
  verifier's input and the setup input have the same output, so they are equal (no COLL). Their
  child at the walked position is then equal too, since the position is fixed by `globalIndex`,
  level and parent index. Repeat down to the leaf. A zero-window record is the window root itself.
- **(b) Order.** Let ρ and κ be the `root` and `qroot` the coordinator accepts. The verifier
  evaluates its own fixed-shape trees over the transaction's payloads. With no COLL, the input it
  evaluates to each node value is that value's only queried preimage. With no LATE, each child value
  was first output by a query made before the parent's first query. A child c of a parent input I
  is also the output of its own verifier-evaluated preimage I_c ≠ I (a different tag, or a `node`
  frame at a different level). If c first appeared as an output at I's own first query, then
  H(I) = c = H(I_c), which is COLL; if it appeared later, that is LATE. Likewise ρ is output
  before the first query of `beta(ρ)`, and ρ and κ before the first query of `alpha(ρ, κ)`.
  So when β is first sampled, the 22 leaf payloads are fixed by earlier queries, and with them
  every `R_e(Y)` (step 4: each coefficient is a payload value or an id constant).
  When α is first sampled, both the `R_e` and Q are fixed. This holds whether or not openings
  were present when a challenge was queried, and in either query order. A challenge
  queried on a root with no queried opening can only be used later through LATE, so it gets no
  ε_SZ charge.

**Openings at challenge time.** For a value v and a time t, the *opening of v at t* is
obtained by walking down from v through the earliest-queried preimage (among queries made before
t) of each value: a `node` frame with the expected level and index recurses into L and R, and the
walk stops at `leaf` frames. It exists if the walk yields the 22-leaf shape of step 2 (for ρ) or
the one-leaf quotient shape (for κ), with payloads of the exact lengths the verifier checks. It
then determines every `R_e(Y)` (for ρ) or `Q(Y)` (for κ). It is a function of the oracle history
before t, so a challenge first sampled at t is independent of it. A β query on ρ is charged using
the opening of ρ at the moment β(ρ) is first sampled. An α query on (ρ, κ) is charged using the
openings of ρ and κ at the moment α(ρ, κ) is first sampled. A query whose openings do not exist,
or give all `R̄_e = 0`, is not charged. By (b), outside COLL ∪ LATE these are exactly the openings
the verifier evaluates in an accepting run.

**Schwartz–Zippel step (ε_SZ).** Let `T(X,Y) = Σ X^e·R_e(Y) − Q(Y)·m(Y) = Σ X^e·T_e(Y)`, with
`T_0 = R_0 − Q·m` and `T_e = R_e` for e ≥ 1. Accepting requires `T(β, α) = 0` in Fp: the block
sums give `Σ β^e·R_e(α)`, and the coordinator checks it against `Q(α)·m(α)` (`m:1603`, `m:1795`,
`m:2026-2036`). Here `deg_X T ≤ 23`, `deg_Y T ≤ 137` (step 4) and `T_e mod m = R̄_e`, where
`R̄_e = R_e mod m`. For a charged query, its openings give some `R̄_e ≠ 0`. β and α are integers
below 2²⁵⁶ < p, so a nonzero polynomial of degree d has a fresh challenge as a root with
probability ≤ d/2²⁵⁶. Each query is charged as follows:
- **β query** on ρ: `P(X) = Σ R̄_e·X^e ∈ Fp6[X]` is nonzero of degree ≤ 23 (Fp6 is a field,
  step 1, so it has at most 23 roots). The query is bad if `P(β) = 0`, probability ≤ 23/2²⁵⁶.
- **α query** on (ρ, κ) after β(ρ): β is already fixed, so `T(β, Y) = S − Q·m` with
  `S = Σ β^e·R_e` is fixed before α is sampled. The query is bad if `T(β, Y) ≠ 0` and
  `T(β, α) = 0`, probability ≤ 137/2²⁵⁶. When `P(β) ≠ 0`, `T(β, Y) mod m = S mod m = P(β) ≠ 0`,
  so `T(β, Y) ≠ 0`.
- **α query** on (ρ, κ) before β(ρ): pick e* with `R̄_{e*} ≠ 0`, so `T_{e*} ≠ 0` with degree
  ≤ 137. The query is bad if `T_{e*}(α) = 0` (≤ 137/2²⁵⁶). It is also bad if, when β(ρ) is
  later sampled, `T(β, α) = 0` while `T(X, α)` is nonzero of degree ≤ 23 (≤ 23/2²⁵⁶).

Each β query is charged at most 23/2²⁵⁶ and each α query at most 160/2²⁵⁶. This holds however
many quotient roots are tried per β, and the union bound gives ε_SZ. Suppose a run accepts, outside
COLL ∪ LATE and with no bad query. By (b), the openings used to charge the final (ρ, κ) pair are
the ones the verifier evaluates. If some `R̄_e ≠ 0`, there are two cases. If β(ρ) was sampled
first, then either `P(β) = 0` (the β query is bad), or `T(β, Y) ≠ 0` and acceptance forces
`T(β, α) = 0` (the α query is bad). If α(ρ, κ) was sampled first, then either `T_{e*}(α) = 0`, or
`T(X, α) ≠ 0` and acceptance forces `T(β, α) = 0`; both are charged to the α query. So all
`R̄_e = 0`. Step 1, with the GT factors authenticated by (a), gives the pairing equation.
The degree constants match `../../BLS_QSPLIT_TAIL22_STATUS.md:86-88`. Earlier statements of the
bound, `160/(2²⁵⁶−1)` per query plus `q(q+1)/2²⁵⁶`, are replaced by this one.

### 6. Composition across inputs

- **Count**: every program requires `tx.inputs.length == n` (`m:1481`, `m:2101`). The coordinator
  requires exactly one OP_RETURN output (`m:2102-2103`).
- **Order and sibling code**: the coordinator requires 35-byte lockings and
  `sha256(locking[1] ‖ … ‖ locking[n−1]) == digest` (`_coordinator_binding.mjs:2-8`). Each
  locking is `OP_HASH256 hash256(redeem) OP_EQUAL`, so every worker's redeem is fixed. Every worker
  requires its `activeInputIndex`. Group members use the packed physical-index map (`m:138-141`).
- **State hand-off**: the predecessor payload and evaluation are read by introspection from the
  predecessor's first two pushes, or from the altstack inside a group (`m:3205-3210`,
  `m:1908-1922`). These are the same bytes the coordinator commits as that block's leaf.
- **Root framing (`9c1f0fe`)**: `rootFrameGuard` requires the root's argument region to be exactly
  `argumentBytes` (`_root_frame.mjs:10-15`). Push-only, minimal encoding and clean stack then make
  every fixed-offset read of input 0 hit the intended argument.

**Code imports and binder order.** Every import takes the last `len(redeem)` bytes of a bound
sibling's unlocking (`SIZE <len> SUB SPLIT NIP`), which is that sibling's P2SH32 redeem
(`m:3299-3307`, `m:3527-3545`, `_coordinator_head.mjs:96-100`). Workers trust the root, and the
root trusts the binder. The order in the root differs by revision, checked in the shipped root
redeems:
- **`fused-coordinator-head`, `-fields` (`9c1f0fe`)**: binder first. Only literal push/DROP data
  and the self-frame guard precede it. The PIC batch-0 helper, the arithmetic library, the
  Regular initializer and the coordinator code pages (funding carriers 5/8/11/16 plus the
  First/Tail overflow) are all loaded afterwards (`_coordinator_head.mjs:102-106`). The prefix
  cache `0x67`/`0x68` turns a bounded slice of input 0's own first pushes into one literal data
  push. Witness bytes never execute (`_root_prefix.mjs:27-43`), and only bounded header/statement
  reads are rewritten (`_root_prefix.mjs:73-80`).
- **The other 11 ids: binder-before-loader does NOT hold literally.** The coordinator loads the
  batch-0 PIC helper from the block-4 sibling (input 3, 4 or 5) and invokes it before the
  sibling-locking check (`m:3976-3984`). The tail profile cuts only after the check
  (`_coordinator_tail.mjs:47-72`), but this helper import comes before it. This ordering is
  **fail-closed**. The binder runs unconditionally afterwards at control depth 0, and it depends
  only on `OP_UTXOBYTECODE` introspection and a literal digest. Imported code cannot end
  evaluation early with success (`OP_RETURN` is an error). It also cannot change the caller's
  control flow: in the 2026 VM (`libauth` 3.1.0-next.8) `OP_INVOKE` pushes a return frame onto
  the control stack, `OP_ELSE`/`OP_ENDIF`/`OP_UNTIL` error when that frame is on top, and a
  function body that ends with an open `IF` or loop leaves a non-empty control stack, which is an
  error. So imported code can neither close nor flip a caller conditional, and the binder always
  executes at control depth 0. Imported code also cannot redefine a function identifier, because
  `OP_DEFINE` of an existing identifier is an error in the 2026 VM (the binder itself invokes no
  function). In a valid transaction the sibling's own P2SH32 evaluation must also pass, so the
  pre-binder import is the sibling's genuine redeem. Every function the root
  invokes is defined by root-executed `OP_DEFINE`s. `OP_INVOKE` shares the caller's data
  stack and altstack: this is not a claim that arbitrary imported code preserves caller state.
  The accepted path relies on the genuine PIC helper's reviewed ABI, its immediate verdict
  check, and the binder's dependence only on introspection plus its literal digest.
  So either the block-4 sibling is genuine (and the helper is the genuine helper) or the
  transaction fails. This is an argument, not
  binder-first code. Two independent reviews (2026-10-27) accepted it after
  checking the binder span in the bytes of all 13 roots.

### 7. Per-revision differences

| revision | ids | differences relevant above |
| --- | --- | --- |
| `77ab0ac` | `-intratx-fs` | No zero windows: all 32 records are 704 B. The coordinator reads payloads at fixed offsets without raw header checks; framing rests on the workers' exact lengths plus push-only, minimal and clean-stack rules. The PIC helper is imported before the binder. |
| `1003775` … `c5c3a91` | compact, fused-final … regular-initializer | Zero windows (coordinator sums of shifted digits). Raw header checks. PIC helper imported before the binder. `c5c3a91` carries the coordinator tail after the binder. |
| `9c1f0fe` | coordinator-head, `-fields` | Fused root: binder first. OR-mask zero detection. Prefix cache. |

### 8. Provenance

- **Arithmetic cashc**: the `cashc` package resolved by `import('cashc')` (`m:2273`) must be
  CashScript `1c707c1dbf87396b30ba5e0704b1db44475ce893`. Per `COMPACT.md`, the dist entry SHA-256
  is `2ebf0b95…`. Reviewers observed that `dab3f89f` fails the generator's
  "baseline compiler differs" assert (`m:2297-2300`). The scheduled template compiler is
  `RPA_TEMPLATE_CASHC` at `efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4`. `-intratx-fs` (`77ab0ac`)
  uses only `1c707c1d`, with the default environment of `run_full_multiproof.mjs`.
- **`-intratx-fs` source**: the bench header cites `77ab0ac`. The pinned artifact hash
  `83d2b28f…` is this file at that revision, and the ids rebuild from there. The previously cited
  `d15ed70 (local candidate)` is not in this repository.
- **`-fs-compact` and `-fs-fused-final` (`1003775`)**: their vector files record no `buildFlags`.
  Reconstructed flags that rebuild both byte-identically (review 2026-10-27): start from the
  `buildFlags` of `-fs-fused-regular`. Unset `RPA_FUSE_REGULAR_PAIR` and
  `RPA_GROUP_DENSITY_PADDING`, and set the padding map:

  ```sh
  RPA_COMPACT_REGULAR_DENSITY_PADDING='{"3":334,"5":320,"6":276,"7":283,"8":266,"9":272,"10":273,"11":281,"12":276,"13":283,"14":285,"16":305,"17":279,"18":281,"19":289}'
  ```

  This gives fused-final. With `RPA_FUSE_FINAL_PAIR=1`, the generator forces entry `19` to 0
  (`m:3574` at `9c1f0fe`; line 3210 at `1003775`, where both are built). For **compact**, also unset `RPA_FUSE_FINAL_PAIR`. The padding is
  `PUSHDATA2 <zeros> DROP` before the Regular redeem (`m:3578-3597`) and is not
  soundness-relevant. Both use `RPA_PROOF_FIXTURE=committed`,
  `RPA_GT_CACHE=bls-gt-merkle-w8-position-regular-projective-v1.json` and the two compilers above.

## Optimizations (prepared batched Miller + lazy reduction)

The first two passes cut the full verifier from 196 chunks / 2.28 MB / 1.137 B op to
116 / 1.47 MB / 754 M op; later optimizations produced the current figures above:

- **Batched 4-pair Miller** — instead of four independent single-pair chains (each
  squaring `f` every step), ONE loop squares `f` once per NAF step and folds all four
  pairs' lines into the shared `f`. Eliminates 3
  of every 4 `fp12Sqr`, and the conjugated `f` after the loop IS the boundary, so there
  is **no separate combine step**.
- **Prepared VK pairs** — only `B` is a proof-derived G2 point, so only its `R_B` walk is
  performed on-chain. The fixed `γ`/`δ` trajectories contribute baked line coefficients;
  the fully fixed `e(α,β)` contributes one baked dense Miller value rather than 69 line
  folds. The flat trace falls from 340 to 272 ops and each interior hand-off carries
  `f + R_B + runtime points` (28 limbs rather than 46).
- **Fused input validation for full Groth16** — the first full-Miller chunk checks A/C
  and B on-curve after requiring canonical `[0,p)` encodings for all ten stage coordinates.
  The last reuses its existing homogeneous `R_B=[|x|]B` walk for the
  guarded `psi(B)==[-x]B` subgroup relation. This removes the separate three-input G2
  pass while keeping pairing-only in a distinct, explicitly input-unvalidated namespace.
- **Lazy reduction** — `addFp` drops its `% p` (values only grow inside a chunk; `mulFp`,
  `subFp`, and the covOut commitment reduce them back); `subFp` keeps the mod with a big
  `K·p` bias. Applied to the emitted miller + final-exp functions. The dead inverse
  functions (`fp12Inv`/…, replaced by the witness trick) are dropped from the prologue.
- **Forward final-exp packing** — the planner targets 100,000 op-cost below the per-input
  budget by default, fitting the final-exponentiation trace into 22 chunks while preserving
  the existing forward execution order.
- **GLV full-verifier aggregation** — the full verifier decomposes each canonical Fr input
  into two non-negative 128-bit scalars and uses a four-scalar Straus walk over the fixed
  endomorphism table. The covenant form embeds the exact VK table; the intra/grouped forms
  carry it once in the fifth GLV input, hash-pin it there, and let the four siblings read it
  by input introspection. The first contract derives infinity from only six scalar limbs,
  and the last emits the exact `(-A,B,C,vk_x)` stage. The standalone vk_x benchmark remains
  the existing 11-chunk full-width Shamir implementation for a like-for-like track.
- **Exact canonical handoffs** — stage-bound vk_x and validated G2 producers serialize values
  exactly once their bounds or field operations prove canonicality. The full-stage proof tuple is
  preserved byte-for-byte until the first Miller range gate, so a coordinate encoded as `x+p` is
  rejected rather than silently normalized.
- **Fp6 residue membership** — the residue construction always produces `w` in the embedded
  `Fp6*`: its A-part lies in Fp because `A | p-1`, and its root-of-unity corrector lies in Fp6.
  Since `p^6-1 | (p^12-1)/r`, the terminal witnesses only the six Fp6 limbs and fixes the upper
  Fp12 half to zero, replacing the 63-step `w^(27A)` walk. The inverse and terminal equations
  exclude zero.
- **Quotient-torus residue frontier** — the opt-in intra-transaction build works in
  `Fp12*/Fp6*`, a cyclic group of order `p^6+1`. For `lambda=p+|x|`,
  `gcd(lambda,p^6+1)=r`, so the lambda-power image is exactly the final-exponent kernel in the
  quotient. A canonical six-limb `u` carries the finite class `[c]=[1+u*W]`; the Fp6 correction
  disappears, constant folds use two Fp6 products instead of three, and the final Miller input
  checks `[fF]=[frob(c,1)]` by a nonzero projective cross-product. This removes the separate tail.
  A fixed r-torsion shift makes a finite root available for every accepting class.

Since per-step bytes are dominated (~64%) by op-cost-proportional unlocking padding,
op-cost cuts translate ~1:1 into size.

Every chunk is validated on the real BCH 2026 VM, against `@noble/curves` bls12-381,
for **two** distinct instances under the same VK (runtime-general).

The prescribed verifier.cash BLS12-381 key is synthetic and publishes its setup and IC scalars.
The bytecode evaluates the complete four-pair equation without collapsing it through those scalar
relations, but these fixtures do not establish circuit knowledge, secure application public-input
binding, arbitrary-key verification, or interoperability with an independently generated setup.

## Covenant-residue composition and deployment premises

`bch-groth16-bls12381-chunked-covenant-residue` uses the same lifecycle code as the BN254
covenant. The full argument (enforced rules, the deployment premises P1/P2, the token-provenance
lemma and the composition theorem) is in
[`../pairing/README.md`](../pairing/README.md#covenant-residue-composition-what-the-scripts-enforce-and-what-the-deployment-supplies).
It applies here with these BLS references:

- The lifecycle block is at `build_vectors_covenant_residue.mjs:102-123`. It is inserted before
  the close of the single `spend` function at `:134-141`, with the successor pin at `:137-140`.
  At genesis the input commitment check and the category-equality line are removed (`:128-133`).
- `covIn` / `covOut` (48-byte limbs) are at `_vkxmath.mjs:92-109`; `CATEGORY` is at
  `_vkxmath.mjs:86`, with the fixture value `0xbe`×32. The seam assertions are at
  `build_vectors_covenant_residue.mjs:336-343`. The builder refuses to write vectors unless every
  mutation is rejected (`:203-258`, `:718`). The shipped `verification` block counts 324
  category/capability, 81 successor/terminal-locking and 6 baton mutations.
- `N = 27`: 5 GLV, 21 fused Miller, 1 Fp6 residue verdict. The statement `(n0, n1)` is in the
  genesis (step 0) unlocking: push 6 is `in0` (`n0`) and push 5 is `in1` (`n1`), since the genesis
  `spend(.., in0, in1, k10, k20, k11, k21, zeroPadding)` pushes its arguments last-first. Pushes 4
  and 2 are the GLV witnesses `k10` and `k11`, which equal `n0` and `n1` only for small scalars;
  a consumer must not read the statement from them (the bench `publicInputs` list is a
  mutation-test list, not a statement locator). Full-stage GLV: `A, B, C` enter as witnesses at the last GLV step
  (`GLV vk_x [103,128) bind (-A,B,C,vk_x)`). From there, that step's output commitment binds
  them together with `vk_x`.
- The same opcode census holds for all 27 shipped redeems (genesis / forward / terminal counts as
  in the BN table).

P1 (category genesis creates only `L_0` batons, `C` regenerated for the deployment) and P2 (the
verdict is an unspendable, empty-commitment immutable NFT read off-chain through its unique
one-input ancestry) are deployment-supplied, exactly as for BN254.

## How it works

A GENERIC (proof-agnostic) covenant: each chunk carries **no baked proof**; only VK
constants are prepared. The
running state — vk_x's Jacobian accumulator, the Miller `f` (Fp12, 12 limbs) + running
G2 point `R` (6 limbs), or the live final-exp Fp12 values — plus the proof-derived
points ride in the spent/created token's **NFT commitment** as `hash256` of their
**48-byte** little-endian limbs (a 381-bit BLS field element needs 48 bytes, vs 40 for
BN254's 254-bit field). Each chunk verifies the incoming commitment, recomputes its
window, and re-commits the outgoing state under the same token category, so one fixed
set of lockings verifies any proof. The full chain is sequential: public inputs → vk_x →
`(-A,B,C,vk_x)` → input-validated Miller → final exponentiation. vk_x range-checks
canonical Fr inputs; Miller derives `f=1` and `R=B`. Every stage emits
the exact next-stage state, and every nonterminal covenant pins the actual successor
locking bytecode. Within a chunk the work is **unrolled straight-line
with fresh SSA variables** (the NAF digit baked per Miller step), so the body compiles
once and **op-cost binds, not size**. Windows are sized by measuring real-VM op-cost.

### BLS-specific notes (vs BN254)

- **Miller loop** (`miller_ref.mjs` blueprint): multiplicative twist → the line uses
  `mul014` (not `mul034`); the ate loop is the NAF of `|x|` (x = −0xd201000000010000),
  64 digits, with **no 6x+2 and no Q1/Q2 postPrecompute**; because x is negative the
  batched `f` is **conjugated** once at the end of the loop (that conjugated `f` is the
  boundary — no combine).
- **Final exponentiation** is the BLS/Hayashida-Scott hard part over `|x|`, traced as
  the same Fp12 op-DAG primitives as BN254 (cycSqr/mul/conj/frob1-3/inv) with liveness
  carrying only the live Fp12 values. The easy-part **381-iteration Fermat inverse**
  would alone exceed one input's op-cost budget, so `f⁻¹` is supplied as an **unlocking
  witness** and verified by `fp12Mul(f, f⁻¹) == ONE` (the same trick as vk_x's `zInv`).
- vk_x is **full-width / magnitude-independent** (worst-case-sized windows over all 255
  scalar positions) — see the dedicated note below.

## Regenerating (everything in `generated/` is git-ignored)

```
VERIFIER_DIR=/path/to/zk-verifier-bench node generate.mjs
```

The covenant-residue track has its own one-command source-to-vector path:

```
VERIFIER_DIR=/path/to/zk-verifier-bench node generate_covenant_residue.mjs
```

The current-BCH intra-transaction quotient frontier has a deterministic one-command path. It
also runs the quotient-group proof and full valid/invalid dual-VM gates before writing the vector:

```
VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
```

The quotient path is opt-in. Running the original four unflagged GLV, Miller, final-residue, and
builder commands still reproduces the 35-input artifact byte-for-byte.

Individual pieces (all reproducible artifacts; only the generators are committed):

```
node gen_vkx.mjs                    # standalone vk_x covenant chunks
node gen_vkx.mjs full               # legacy full-stage Shamir generator
node gen_vkx_glv.mjs                # GLV planner; full builders emit the audited stage-bound layout
node gen_miller.mjs                 # pairing-only prepared Miller (input-unvalidated)
node gen_miller.mjs full            # full prepared Miller with fused input validation
node gen_finalexp.mjs               # final exponentiation -> verdict
node build_vectors.mjs             # -> verifier vkx-bls12381-chunked-covenant-vectors.json
node build_vectors_pairing.mjs     # -> verifier pairing- + groth16-bls12381-chunked-vectors.json
```

### Residue-plan ownership

The residue verifier has two deployment-owned chunk plans. They intentionally do not share a
manifest:

- `generated/manifest_{millerres,finalexpres}.json` is the covenant plan. Its chunks retain the
  incoming/outgoing NFT commitment hashes and are measured as independent token transactions.
  `generate_covenant_residue.mjs` regenerates this namespace in its exact full-stage layout before
  assembling the lifecycle-bound P2SH32 graph.
- `generated/linked-residue/manifest_{millerres,finalexpres}.json` is the hash-free linked plan,
  consumed only by `chunked/intratx/build_vectors_residue_bls.mjs` and
  `chunked/grouped/build_vectors_residue_bls.mjs`. Those builders remove the boundary hashes and
  validate the wider windows in their real sibling-input contexts on both consensus and standard
  BCH 2026 VMs.

Regenerate the linked namespace before either linked vector:

```
node gen_miller_residue.mjs linked
node gen_finalexp_residue.mjs linked
```

Do not point the covenant or proposed-large builders at `generated/linked-residue/`. Several linked
windows exceed the covenant density limit before the boundary hashes are removed; the proposed-large
track has a separate 100 kB/bch-spec plan.

Fast probes (no planner): `node gen_miller.mjs 0 probe`, `node gen_finalexp.mjs probe`,
`node gen_vkx.mjs probe <lo> <hi>`.

### Why it takes a few minutes

The runtime is the chunk *planner*, not the cryptography: there is no formula for "how
many steps fit one BCH input", so each chunk is sized empirically — the generator grows
a window and, for every candidate, compiles the contract with the custom `cashc` and
evaluates it on the real BCH 2026 VM (through a synthetic token tx) to measure exact
op-cost. `build_vectors*` then re-compiles, pads, and evaluates every chunk twice (valid
+ tampered) for **two** distinct instances. Fully deterministic.

## vk_x is full-width / magnitude-independent

The vk_x MSM tiles **all 255 scalar-field bit positions** and the windows are sized
against two **canonical complementary Fr scalars** whose bitwise union sets every
position, so every planning iteration executes its add path. One fixed locking therefore
aggregates **any** public input in `[0,r)` (EVM ecMul-equivalent), not just small inputs;
the first chunk rejects negative or out-of-range scalars rather than silently truncating them.

## Files

| file | role | committed |
|------|------|:--------:|
| `_vkxmath.mjs` | shared Fp/Jacobian math, 48-byte serialization, covenant emitters, real-VM measurer, planner | ✅ |
| `_pairingmath.mjs` | shared noble Miller/finalExp math, op-DAG trace, instance pairs, fnExtractor | ✅ |
| `_residue_linked_plan.mjs` | audited hash-free Miller/tail boundaries and stress fixture, shared by grouped + intra-tx | ✅ |
| `gen_vkx.mjs` | plan + emit the standalone worst-case-sized Shamir vk_x chunks | ✅ |
| `gen_vkx_glv.mjs` | emit the hardened five-window GLV layout used by full-verifier builders | ✅ |
| `gen_miller.mjs` | plan + emit separate pairing-only and input-validated full prepared-Miller namespaces | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness, lazy) | ✅ |
| `build_vectors.mjs` | assemble the vk_x covenant vectors | ✅ |
| `build_vectors_pairing.mjs` | assemble the pairing + full-groth16 vectors | ✅ |
| `build_vectors_covenant_residue.mjs` | assemble and gate the BLS covenant-residue lifecycle | ✅ |
| `generate_covenant_residue.mjs` | one-command BLS covenant-residue vector reproduction | ✅ |
| `generate.mjs` | one-command orchestrator | ✅ |
| `generated/` | generated `.cash` chunks + manifests (derived) | ❌ git-ignored |
| `generated/linked-residue/` | hash-free residue chunks + manifests for grouped/intra-tx only (derived) | ❌ git-ignored |

The instance + IC/VK points come from `../../singleton/bls12-381/bls_instance.mjs`; the
singleton oracles are `../../singleton/bls12-381/{vkx,miller,finalexp}.cash`.
