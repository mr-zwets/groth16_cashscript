# SI-MX3: a sound-by-construction BN254 Groth16 verifier for current BCH (bch-2026), three inputs

**Status:** design record (designer 1 of 2, angle: minimize total bytes). It is **not** a built verifier and
**not** a zk-verifier-bench entry. The scores below are estimates. The Miller-loop op cost comes from a VM run
of the full event loop, the setup cost from a real three-input bch-2026 transaction, and the rest from the
measured SI-GLS profile. Every number can be re-derived from `prototypes/` (see Reproduce).

**Target:** current BCH (libauth `BCH_2026`), standard and one transaction:

- several P2SH32 inputs, each with an unlocking bytecode of at most 10,000 B (redeem included);
- per-input op-cost budget `(41 + unlockingLen) × 800`;
- standard locking ≤ 201 B, standard tx ≤ 100,000 B.

**Result (estimate): 26,884 B over 3 inputs** (unlocking 26,628 B + 3 × 35 B locking + 151 B tx overhead).
Op cost is 20.97M (standard mode), and every input has a 2.0% op margin at fixture 0.

For reference:

| entry | category | bytes | status |
|---|---|---|---|
| **SI-MX3 (this design)** | bch-2026, 3 inputs | **≈ 26.9 kB (estimate)** | design; sound by construction (argument below) |
| crown8-rawchain | bch-2026, 8 inputs | 77,193 | unreviewed, someone else's (current best non-withdrawn BN native) |
| intratx-residue | bch-2026, 11 inputs | 86,950 | unreviewed |
| densless-msm-slim | bch-2026 | 35,143 | withdrawn (#32 F6) |
| sound-si-gls | bch-spec, 1 input | 21,915 | reviewed |

## The budget couples bytes and op cost

On bch-2026 an input's op budget is 800 per unlocking byte, plus a 32,800 credit (the 41-byte base). Data
placement is free (any input can read any other input's unlocking bytes with `OP_INPUTBYTECODE`). So the
score is, up to tx overhead, `max(content bytes, total op / 800)`. Measured in the same units:

- 1 byte of witness or constant is worth 800 op;
- a 32-byte field word must replace at least 25.6k op of computation to pay for itself;
- conversely, op beyond `800 × bytes` has to be paid for with filler bytes.

A straight split of SI-GLS (projective B, no B witness) needs 25.7M op against 21.8 kB of content. That is
op-bound at about 33 kB with 8.3 kB of filler (see "Alternatives"). The design below reaches the balance
point instead, with three choices:

1. **Code and constants exist once in the transaction.** The redeem `R` is the same 57 bytes in every input.
   It loads the code blob from one input's unlocking bytes (`OP_INPUTBYTECODE`, fixed byte range), checks its
   SHA256 against a constant, and runs it with `OP_DEFINE` / `OP_INVOKE`. The code blob authenticates the
   constants blob and the δ-slope slices by their digests.
2. **Affine B walk with a witnessed inverse norm (32 B per step).** A doubling or addition with a witnessed
   `t = 1/N(den)` costs 101k / 93k op, against 123k / 154k for the SI projective kernels. That trades
   2,816 B of witness for 3.9M op (1,413 op/B). A full 64-byte slope witness saves more op, but at a
   worse rate per byte (it would leave the design bytes-bound, see "Alternatives").
3. **Per-input commitments.** A 96-byte digest list `D = d0‖d1‖d2` sits in input 0, and
   `h0 = SHA256(TAG ‖ D)`. Each input checks only its own `d_i` against its own stack items, so no input
   hashes another input's data.

The SI-GLS identities, GT-GLS folding, residue argument, chunking (2-event chunks, 33 states), quotient
batching and degree cap (NQ_MAX = 132) are unchanged.

## Protocol

Notation and all unchanged parts are as in [`chunked/bn254/sound-si-gls/README.md`](../../chunked/bn254/sound-si-gls/README.md):

- `Fp12 = Fp[X]/M`, `M = X¹² − 18X⁶ + 82`; `Φ`, `η`, `γ1` as there;
- `λ = 6x+2+p−p²+p³ = m·r`;
- the NAF digits `d_0..d_64`, i.e. 65 events with 21 additions;
- chunks of 2 events (the last one has 1), with states `S_1..S_33` after events 2, 4, …, 64, 65.

`N(a0 + a1·u) = a0² + a1²` is the Fp2 norm. Since `p ≡ 3 (mod 4)`, `N(a) = 0 ⟺ a = 0`.

### Roles and event ranges

The design uses three inputs with roles 0, 1, 2. The role equals the input index.

| role | events | chunks | states committed |
|---|---|---|---|
| 0 | [0, 24) | 0–11 | S_1..S_12 |
| 1 | [24, 48) | 12–23 | S_13..S_24 |
| 2 | [48, 65) + terminal + binding + quotient | 24–32 | S_25..S_33 |

### Witness

All words are fixed-width 32-byte little-endian and decoded unsigned (`BIN2NUM(w ‖ 0x00)`).

- `STMT` (642 B), as in SI-GLS `WS[0, 642)`:
  - `x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C, n0, n1`;
  - the GT-GLS nibble strings `N_0`, `N_1` (65 B each);
  - the residue root `s^c` (6 words).
- **Stream `S_i` of role i**, in consumption order, chunk by chunk:
  - per B step of each event, the inverse-norm witness `t` (32 B);
  - then the chunk's state (6 words);
  - role 2 appends `t_ψ` and `t_{−ψ²}` for the two terminal additions.
  - Sizes: 3,328 / 3,328 / 2,496 B.
- `D` (96 B): `d0 = SHA256(STMT ‖ S_0)`, `d1 = SHA256(S_1)`, `d2 = SHA256(S_2)`.
- `WQ`: the odd quotient coefficients, highest first (`32·n_q` B, `1 ≤ n_q ≤ 132`, leading word ≠ 0), as in SI-GLS.
- `HAND_i` (i = 1, 2; 224 B): the state handed from role i−1 to role i, as the 7 words
  `x_T.c0, x_T.c1, y_T.c0, y_T.c1, F+, F−, R`.
- `FILL_i`: zero bytes, 0 ≤ length ≤ F_MAX. This is a liveness filler; it is not used by any computation.

**Inverse-norm witnesses.** For a doubling at `T = (x, y)`: `t = (2·N(y))⁻¹`. For an addition of `Q` at `T`:
`t = N(x − x_Q)⁻¹`, where `Q ∈ {B, −B, ψ(B), −ψ²(B)}`.

### Constants (VK, authenticated by digest)

- **Code blob** (≈ 4.9 kB): every function, the role programs, and `K_consts`.
- **Constants blob** (≈ 1.8 kB):
  - the SI-GLS field constants: `R_{k,i}`, `Rconst`, `γ1`, `η`, `δ`, `b'`, the digit schedule, `r` and `p`;
  - the δ-recursion start states of roles 1 and 2;
  - the three δ-slice digests `K_DS[i]`.
- **δ-slope slices** `DS_0, DS_1, DS_2`: the 88 baked SI δ slopes (64 B each), split by role (2,048 / 2,048 / 1,536 B).

Every constant is regenerated from the VK and asserted against noble at build time, exactly as `math.mjs` does for SI-GLS.

### Unlocking layouts

All pushes are minimally encoded, and `R` is always the last push. The blob hosting below is the model's
optimum. Any hosting works, provided every byte range is fixed.

```
input 0: [D 96] [STMT 642] [S_0] [CODE]                   [FILL_0] [R]
input 1: [S_1] [HAND_1 224] [CONSTS] [DS_1] [DS_2]        [FILL_1] [R]
input 2: [S_2] [HAND_2 224] [DS_0]                        [FILL_2] [WQ] [R]
```

`ZT` (the "z-tail") is the raw bytes of input 2's `FILL_2` and `WQ` pushes, i.e. its unlocking bytecode from a
fixed offset up to the start of the redeem push.

### The redeem R (57 B, identical in all three inputs)

```
<h_code> OP_INPUTBYTECODE <o_code> OP_SPLIT OP_NIP <len_code> OP_SPLIT OP_DROP
OP_DUP OP_SHA256 <K_code> OP_EQUALVERIFY <len_body> OP_SPLIT OP_DROP <1> OP_DEFINE <1> OP_INVOKE
```

Function 1 is the library's main body:

1. it defines every other function;
2. it runs the common setup;
3. it dispatches on `OP_INPUTINDEX` to the role program.

### Program of role i (steps 1–8 are common)

1. **Pin the own layout.**
   - Check `DEPTH`, and the size of every fixed push.
   - `WQ` (role 2): `SIZE ≡ 0 (mod 32)`, `32 ≤ SIZE ≤ 32·132`.
   - `FILL_i` is all zero and `≤ F_MAX`.
   - The raw unlocking size `SIZE(OP_INPUTBYTECODE(i))` equals the sum of the minimal encodings of the own
     pushes plus `|push(R)|`. So every push is minimal, and every byte offset that the other inputs read is
     determined.
2. **Pin the graph.**
   - `OP_TXINPUTCOUNT == 3`.
   - For j = 0, 1, 2: `OP_UTXOBYTECODE(j) == OP_UTXOBYTECODE(OP_INPUTINDEX)`. All three spent outputs are
     `P2SH32(R)`.
3. **Load the constants.**
   - Read `CONSTS` from its host by fixed range and require `SHA256 == K_consts`.
   - Read `DS_i` and require `SHA256 == K_DS[i]`.
4. **Transcript.**
   - Read `D` (input 0) and `ZT` (input 2) by fixed ranges.
   - `d_i = SHA256(own committed data)`, computed from the own stack items, and require `D[32i, 32i+32) == d_i`.
   - `h0 = SHA256(TAG ‖ D)`, `ρ_raw = SHA256(h0 ‖ "rho")`, `z_raw = SHA256(h0 ‖ ρ_raw ‖ ZT)`.
   - `ρ, z = BIN2NUM(· ‖ 0x00) mod p`, and `z ≠ 0`.
5. **Statement.**
   - Read `STMT` from input 0 by fixed range and decode `A, B, C, s^c` unsigned.
   - Role 0 additionally checks:
     - every word `< p` and `n_k < r`;
     - the nibble mask (`& 0x0f…` is the identity);
     - `y_A² = x_A³ + 3` and `y_C² = x_C³ + 3`;
     - `y_B² = x_B³ + b'`.
6. **Setup**, as in SI-GLS: powers of `z` and `ηz`, `c_j = Φ(γ1^j)(z)`, `S_c(±z)`, the GT-GLS tables `TP/TM`, and
   the loop environment (`y_P = −y_A`, `x_A·z`, `x_C·z`, …).
7. **Start state.**
   - Role 0: `T = B`, `F± = S_c(∓z)`, `R = 0`, δ state `(x_δ, y_δ, 0)`.
   - Role i > 0: `(T, F±, R)` from `HAND_i` (unsigned, every word `< p`); the δ state is the role's constant.
8. **Event loop** over the role's events. Each event `e`:
   1. **Doubling.** Read `t` from the stream (`< p`). Set `λ = 3x²·conj(y)·t` and **require
      `t·2N(y) ≡ 1`**. Then `T ← (λ² − 2x, λ(x − x') − y)`. The line is `(1, −λ, c = λx − y)`, and
      `F± ← F±² · (y_P ± o)`, with `o = z³Φ(c)(z) − x_A z Φ(λ)(z)`.
   2. **δ step**, unchanged from SI-GLS (baked `λ_j` from `DS_i`, the `c_j` recursion).
   3. **Addition, if `d_e ≠ 0`.**
      - Read `t` and set `λ = (y − y_Q)·conj(x − x_Q)·t`, with `Q = d_e·B`. **Require `t·N(x − x_Q) ≡ 1`.**
      - `T ← (λ² − x − x_Q, λ(x − x') − y)`, with the line as above.
      - Multiply `F±` by `S_c(∓z)` or `S_c(±z)` as in SI-GLS, then do the δ step.
   4. **GT-GLS.** `F± ·= TP/TM_0[N_0[e]] · TP/TM_1[N_1[e]]`.
   5. **Chunk boundary.** Read the state `S'` (6 words, `< p`). Then `R ← Rρ + F+·S'(−z) − F−·S'(z)` and
      `F± ← S'(±z)`.
9. **Roles 0 and 1: outgoing handover.** Encode `(x_T, y_T, F+, F−, R) mod p` canonically and require it to
   equal `HAND_{i+1}`, read from input i+1 by fixed range.
10. **Role 2: terminal.**
    1. `T += ψ(B)`, then `T += −ψ²(B)`, each with a witnessed `t` and its line. Then the two δ Frobenius lines.
    2. Require `T == −ψ³(B)` exactly (affine, reduced).
    3. `F± ·= Rconst(±z)·S_c(±ηz)`, then `R ← Rρ + F+·W(−z) − F−·W(z)`.
    4. **Binding.** `acc_k = Σ_e 2^{64−e}·TB[N_k[e]]`, and require `(acc_k − 2^64Σπ_i − n_k) mod r == 0`.
    5. **Quotient.** `WQ` comes from `ZT`; every word `< p` and the leading word `≠ 0`. `Q(z) = z·q(z²)` by
       Horner, and **accept iff `(R − Q(z)·M(z)) mod p == 0`.**
11. Leave exactly one `TRUE` (clean stack).

## Soundness argument

The policy requires every value the accept decision depends on to have an owner. Here are the owners:

| value | owner |
|---|---|
| code, field constants, δ slopes, δ start states | **VK constants**, authenticated by `R ∋ K_code → K_consts → K_DS[i]` and by `P2SH32(R)` on every spent output |
| `A, B, C, n0, n1, N_0, N_1, s^c` | **committed** (in `d0`, then `h0`, before ρ). Canonical unsigned decoding, ranges, nibble mask and curve/twist checks are in role 0 |
| states `S_1..S_33` | **committed** (in `d_i`, then `h0`, before ρ); `< p` when read |
| inverse norms `t` | **fixed by the exact equation** `t·N(den) ≡ 1` (and `< p`). They are also committed (harmless) |
| B trajectory `T_e`, slopes `λ`, every line | **computed on-chain** |
| `ρ`, `z` | **computed on-chain** from `D` and `ZT` |
| `WQ` | **committed** in `z`'s preimage after ρ; word ranges, the cap and the nonzero leading word are checked |
| GT-GLS tables, powers, `F±`, `R`, `S(±z)` | **computed on-chain** |
| `HAND_i` | **exact equality** with the values role i−1 computed on-chain |
| `acc_k` | **computed on-chain** from the committed nibbles; binding by the exact mod-r equation |

1. **Every input runs exactly this verifier, in this role.**
   - Each spent output is `P2SH32(R)`. `R` executes only a code blob with digest `K_code`.
   - The code pins the input count to 3, and all three spent outputs to the same `P2SH32(R)`. So the
     transaction contains exactly three inputs, each running the same authenticated code, and the role is the
     input index.
   - This pins the count, the order (role = index) and each sibling's code and locking (introspection).
   - The transaction is valid iff the three role programs accept. That conjunction is the verifier.
   - The code-blob digest is not circular: `R` contains `K_code`, and the code never contains a digest of `R`
     (sibling identity is checked by locking equality, not by an embedded hash).
2. **Shared values are identical in every input.**
   - `D`, `STMT` and `ZT` are read by all inputs from fixed byte ranges of pinned-layout unlockings
     (step 1 makes every offset exact).
   - `OP_INPUTBYTECODE` returns the same bytes in every evaluation. So all inputs derive the same `ρ` and `z`
     and the same statement.
   - The owner input's own stack items are the same bytes, by the minimal-push size check.
3. **The transcript is injective and ordered.**
   - `h0 = SHA256(TAG ‖ d0 ‖ d1 ‖ d2)`, and each `d_i` is checked on the owner's items. So `h0` determines
     `(STMT, S_0, S_1, S_2)` up to a SHA256 collision.
   - All of these have fixed widths per role, so the encoding is injective.
   - `ρ` depends only on `h0`. `ZT` (the filler and `WQ`, length-ruled) enters only `z`. So every polynomial
     `D_k` is fixed before `ρ`, and `Q` is fixed before `z`. This is SI-GLS's order.
4. **The B walk is an exact group computation.**
   - `t·N(den) ≡ 1` forces `N(den) ≠ 0`, hence `den ≠ 0` (the norm is anisotropic) and `t = N(den)⁻¹`. Then
     `λ = num·conj(den)·t = num/den` exactly.
   - A doubling therefore requires `y ≠ 0` and an addition requires `x ≠ x_Q`. Then the formulas are the
     affine group law, so every `T_e` is the correct multiple of the curve-checked `B`. An exceptional step
     cannot pass.
   - The endpoint `T_end = −ψ³(B)` gives `λ(ψ)(B) = O`, hence `B ∈ G2`. This is SI-GLS's argument (`math.mjs`
     FACTS).
   - Honest completeness: no step is exceptional for `B ∈ G2`, since `facts.mjs` checks every partial scalar
     of the fixed schedule.
5. **Lines and degrees are unchanged.**
   - The affine line `(1, −λ, λx − y)` at `P = −A` is the SI line times an Fp2 scalar: same class, `ℓ0 = 1`
     (so a nonzero polynomial), degree ≤ 9.
   - So the per-event degrees, `NQ_MAX = 132` and the degree bound 275 are SI-GLS's.
   - The states are the same classes as in SI-GLS. Only `Q` changes.
6. **The handovers are exact.** Role i+1 starts from the values role i computed, encoded canonically (reduced,
   32-byte LE). They are post-challenge but feed no challenge. They are determined by the committed data and
   the challenges, so each identity `D_k` is exactly SI-GLS's single-input `D_k`. `R` is accumulated in the
   same Horner order across inputs, so the final check is SI-GLS's batched check.

Everything else (the chunk identities, the residue `[f′] = [c]^λ ⇒ FE(f′) = 1`, GT-GLS binding, batching) is
SI-GLS verbatim. **Soundness error:** `ε ≤ q_H · 1.134·(33 + 275)/p ≈ q_H · 2^−245`, as in SI-GLS. The extra
hash layer adds only a SHA256 collision term.

**Checklist against the policy:**

- canonical unsigned decoding everywhere (`0 ≤ v < p`, `n < r`);
- curve checks on A and C;
- twist check on B plus the endpoint argument for the G2 subgroup;
- every `≠ 0` and equality guard on reduced values (`(a − b) mod p`, as in SI-GLS);
- pinned push layout and minimal pushes, clean stack;
- input count, order, code and locking pinned by every input;
- the inter-input state bound by exact equality.

## Input layout and costs (fixture 0, n_q = 114, standard mode)

| | input 0 | input 1 | input 2 | total |
|---|---|---|---|---|
| events | 0–23 (12 chunks, 8 adds) | 24–47 (12 chunks, 8 adds) | 48–64 (9 chunks, 5 adds) + terminal | 65 / 21 + 2 |
| redeem push + push headers | 70 | 70 | 70 | 210 |
| states | 2,304 | 2,304 | 1,728 | 6,336 |
| inverse-norm witnesses | 1,024 | 1,024 | 768 | 2,816 |
| handover | – | 224 | 224 | 448 |
| STMT + D | 738 | – | – | 738 |
| hosted: code blob | 4,932 | – | – | 4,932 |
| hosted: constants blob | – | 1,812 | – | 1,812 |
| hosted: δ slices | – | 3,584 (DS_1, DS_2) | 2,048 (DS_0) | 5,632 |
| hosted: WQ | – | – | 3,648 | 3,648 |
| filler | 19 | 19 | 18 | 56 |
| **unlocking bytes** | **9,087** | **9,037** | **8,504** | **26,628** |
| setup (measured) | 0.87M | 0.87M | 0.87M | 2.61M |
| event loop (measured) | 6.22M | 6.23M | 4.32M | 16.77M |
| terminal + binding + quotient + final | – | – | 1.47M | 1.47M |
| owner checks, remote reads | 0.07M | 0.02M | 0.05M | 0.13M |
| **op (standard)** | **7.16M** | **7.12M** | **6.70M** | **20.97M** |
| budget `(41 + L)·800` | 7.30M | 7.26M | 6.84M | |
| margin | 2.0% | 2.0% | 2.0% | |

**Score ≈ 26,628 + 3 × 35 (locking) + 3 × 43 (outpoint, sequence, varint) + 22 (envelope, OP_RETURN output) = 26,884 B.**

Other constraints:

- The tx is about 27 kB (≤ 100,000).
- The largest stack item is one `OP_INPUTBYTECODE` result (≤ 9.1 kB ≤ 10,000).
- Every unlocking is ≤ 9,100 B, which leaves at least 900 B of filler room per input for liveness.
- The locking is 35 B (≤ 201).

### Where each number comes from

| item | source | value |
|---|---|---|
| affine/projective kernels | `kernels.mjs`: VM runs on real points, outputs checked against noble | see the table below |
| event loop per range | `loop.mjs`: the full SI loop structure (δ steps, GT-GLS, boundaries, the stream on the altstack), fixture 0's real B trajectory and real witnesses, every check passing | 65 events: projective 20.67M (SI-GLS measured 20.9M with acc: calibrated), affine slope 15.40M, **affine inverse-norm 16.78M** |
| per-input setup | `setup2.mjs`: a real 3-input bch-2026 tx, all three inputs valid (standard). It runs R, library load, layout and graph pins, digest list, challenges, own δ slice, statement decode, owner checks and both handovers. It excludes the GT-GLS tables, powers and environment | 0.32–0.36M |
| powers, GT-GLS tables, loop environment | SI-GLS `profile.mjs` (in situ) | 0.119M + 0.358M + 0.046M |
| terminal | SI-GLS profile 0.707M, with the two projective additions replaced by affine ones | ≈ 0.54M (estimate) |
| binding (acc_k outside the loop) | estimate | ≈ 0.13M |
| quotient Horner | SI-GLS profile, per word | 6.47k × n_q |
| code blob size | SI-GLS code by section (`info.sections` minus data): powers ≈ 0.35k, GT-GLS tables ≈ 0.54k, loop setup ≈ 0.3k, terminal ≈ 0.8k, final ≈ 0.16k; the affine loop with its functions measured at 1.18k (SI-GLS 1.60k); the setup by introspection ≈ 1.4k (setup2 measures 2.0 kB unshared for all three roles); handover and dispatch ≈ 0.3k | ≈ 4.9 kB (estimate, ±0.6 kB) |
| witness, constant, δ bytes | exact | |

| kernel (standalone, VM op) | op | bytes | witness |
|---|---|---|---|
| SI projective doubling (kBDbl) | 123,198 | 434 | – |
| SI projective mixed addition (kBAdd) | 154,194 | 584 | – |
| affine doubling, witnessed slope | 80,800 | 256 | 64 B |
| affine addition, witnessed slope | 80,410 | 278 | 64 B |
| **affine doubling, witnessed inverse norm** | **101,096** | 269 | **32 B** |
| **affine addition, witnessed inverse norm** | **92,803** | 276 | **32 B** |
| projective + witnessed-slope addition | 113,259 | 387 | 64 B |
| SI δ step (kDStep) | 37,753 | 152 | – |
| affine doubling + δ, merged | 119,872 | 465 | no gain over separate |

**Estimate uncertainty:** about ±1 kB. The unbuilt parts are the code-blob size (±0.6 kB), the terminal and
binding op (±0.15M, i.e. ±0.2 kB) and setup tuning (the v1 → v2 change alone saved 0.09M per input).

## Alternatives weighed (same model, same measurements; `model.mjs`, `model-result.txt`)

| design | inputs | score (B) | bound by |
|---|---|---|---|
| **affine B, inverse-norm witnesses (SI-MX3)** | 3 | **26,884** | balanced |
| same, 4 inputs | 4 | 27,943 | balanced (one more setup + overhead) |
| affine prefix (inverse norm) to event 60, SI projective after | 3 | 27,865 | balanced (both kernel sets in the code) |
| affine prefix (slopes) to event 40, SI projective after | 3 | 28,121 | balanced |
| affine B, slope witnesses on doublings, inverse norm on additions | 3 | 28,908 | bytes |
| affine B, slope witnesses throughout | 3 | infeasible (content too large for 3 × 10 kB at the margin) | bytes |
| straight SI-GLS split (projective B, no B witness) | 4 | 33,003 | op (8.3 kB of filler) |
| residue family (intratx-residue style) | 11 | 86,950 today | op |

- **The residue family is not competitive.** It evaluates the Miller loop in a six-limb quotient-torus
  representation on-chain; its 86,950 B buy a budget of about 69M op. SI-style evaluation at ±z costs about 0.25M
  per event. Making the residue family competitive would mean adopting the single-identity evaluation, at
  which point it is this design.
- **Not 2 inputs.** Two inputs give at most 2 × 8.03M = 16.06M op, which is below the 20.97M needed.
- **Not 4 inputs.** A fourth input costs one more setup (0.87M ≈ 1.1 kB) plus a redeem and 78 B of tx
  overhead.
- **Not transcript digests for everything.** Version 1 of the setup (`setup.mjs`: every input reads and hashes
  every input's data) costs 0.41–0.44M per input, against 0.32–0.36M for version 2.
- **Not a shared z-table.** Precomputing the GT-GLS tables once and sharing them through bytes saves about 0.5M
  per extra input for about 2.9 kB, i.e. about 345 op/B. That is worse than the 800 op/B break-even.
- **Not baked δ inverse norms.** Baking the δ trajectory as inverse norms (32 B per step instead of the 64 B
  slope) costs about 4M op more for 2.8 kB less, i.e. about 1,400 op/B in the wrong direction.

## Liveness

- **Op variation is small.** The op cost is almost statement-independent. In SI-GLS's sweep the spread across
  423 witnesses is +0.2M / −0.36M in total, and it splits about evenly over the three ranges. The fixture-0
  margin is 2% per input (0.14–0.15M).
- **The filler absorbs everything else.** Every input may carry a zero filler, sized by the honest prover.
  After the filler every input stays ≤ 10,000 B at the worst case:
  - n_q = 132: input 2 gains 576 B of `WQ` and 0.12M of Horner work;
  - n_q = 60: input 2 loses up to 1,728 B of budget, which the filler replaces;
  - every nibble 15 or 1, and the review's "zeros at addition-first events" witness.
- **Required in the build phase:** port SI-GLS's `sweep.mjs` to three inputs. Every listed case must accept
  with a margin of at least 1% in both consensus and standard mode, with the filler the prover would use.
  Record the minimum per-input margin.

## Open risks and what a build must verify

- **Unbuilt parts are estimates:** the code-blob size, the terminal, the binding and the role dispatch. A build
  could land between 26 and 28 kB.
- **The library-by-introspection pattern is new to this benchmark.** The redeem runs code read from another
  input's unlocking bytes, authenticated by SHA256. A reviewer should confirm that it reads as "the verifier's
  code" and not as "a witness". Every spent output commits to `R`, and `R` commits to the code digest.
- **Filler policy.** The zero filler is outside every computation and is checked all-zero. It enters the
  z-hash only as part of `ZT`, which is harmless. The bench owner should accept prover-sized filler. Otherwise
  fix `WQ` at 132 words: that costs +576 B on fixture 0 and makes the filler unnecessary for n_q.
- **No formal equivalence proof**, as in SI-GLS. The affine formulas are tested against noble (`kernels.mjs`)
  and run along the real trajectory (`loop.mjs`). A build needs SI-GLS's red-team suite extended with:
  - multi-input layout rejection tests (wrong count, foreign or reordered input, non-minimal push, altered
    HAND, altered D, wrong ZT host);
  - inverse-norm rejection tests (`t + p`, `t = 0`, a wrong `t`).
- **Public inputs bind through GT-GLS.** This is the same open decision for the benchmark owner as in SI-GLS.

## Reproduce

From the repository root, with the repository's dependencies (@noble/curves 2.2.0, @bitauth/libauth 3.1.0-next.8):

```sh
node research/sound-bn254-native/prototypes/facts.mjs        # affine-walk facts (no exceptional step, anisotropic norm)
node research/sound-bn254-native/prototypes/kernels.mjs      # kernel op costs (VM), outputs checked against noble
node research/sound-bn254-native/prototypes/loop.mjs affineN 0 65    # full event loop, fixture 0 (also: proj | affine | affineAN, any [a b))
node research/sound-bn254-native/prototypes/ranges.mjs > research/sound-bn254-native/prototypes/ranges.json   # per-chunk op, all modes
node research/sound-bn254-native/prototypes/setup2.mjs       # per-input setup in a real 3-input bch-2026 tx (v2 layout)
node research/sound-bn254-native/prototypes/setup.mjs        # v1 (every input hashes everything), for comparison
SPLITLIB=1 CAP=9800 node research/sound-bn254-native/prototypes/model.mjs   # layouts and scores (~10 min; 4-input runs dominate)
```
