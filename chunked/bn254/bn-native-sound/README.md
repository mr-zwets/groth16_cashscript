# BN254 Groth16 on current BCH (bch-2026), sound by construction: SI-MX3, one transaction with 3 inputs

A full Groth16 verifier for the fixed BN254 VK of the densless fixtures (`../densless-recovered/public-fixtures.json`,
public inputs `n0, n1`) that runs on **current BCH** (libauth `BCH_2026`): one standard transaction with three
P2SH32 inputs, each unlocking at most 10,000 B, each with the per-input op-cost budget `(41 + unlocking length) × 800`.
Bench entry id: `bch-groth16-bn254-sound-native` (status `unreviewed`).

The mathematics is the reviewed single-input SI-GLS verifier (`../sound-si-gls/README.md`): one batched torus
identity at ±z, GT-GLS folding of `e(vk_x, γ)`, a torus residue root, 33 committed monic states. This build changes
two things (design SI-MX3, `research/sound-bn254-native/`, with eight items merged from MSI-GLS-5,
`research/bn-native-msi-d2/`; the judged design is `work/bn-native-sound-DESIGN.md` in verifier.cash):

1. **The B walk is affine.** Every doubling and addition reads one 32-byte inverse-norm witness `t`, fixed by
   the exact equation `t·N(den) ≡ 1`. The lines are the affine lines `(1, −λ, λx − y)`, which are Fp2 multiples of
   SI-GLS's projective lines.
2. **The program runs as 3 roles, one per input.** Each role covers a range of the 65 Miller events, cut at
   chunk boundaries (events [0,24), [24,48), [48,65)). The roles chain their state through byte-exact canonical
   handovers.

**Every value that the accept decision depends on is computed on-chain, is a baked VK constant, is hash-committed
before any challenge it meets, or is fixed by an exact field or integer equation.** No prover-supplied evaluation is
used anywhere.

## Results (fixture 0; `node build.mjs`; bench `tools/bench-one.mts`)

| | |
|---|---|
| **score** (scripts + tx overhead) | **27,624** = 27,475 (3 × 35 locking + 27,370 unlocking) + 149 |
| unlocking per input | 9,316 / 9,262 / 8,792 (fillers 96 / 41 / 67 zero bytes, prover-sized) |
| op cost, standard | 7,036,431 / 6,995,632 / 6,642,322 = 20.67M (margins 6.00% / 6.00% / 6.00% of 7,485,600 / 7,442,400 / 7,066,400) |
| op cost, consensus | 7,002,127 / 6,961,328 / 6,609,426 (margins 6.46% / 6.46% / 6.47%) |
| code | 7,310 B: one blob, hosted as pieces of 3,767 B (input 0) and 3,543 B (input 1) |
| redeem `R` | 65 B, identical in all three inputs (locking `aa20 d9ba…a11a 87`) |
| worst-case op per input (sweep, cap rule) | 7.06M (every nibble 15), 12.1% below the 10,000-byte cap budget 8,032,800 |
| tx | ≈ 27.6 kB (standard ≤ 100,000); every locking 35 B, every unlocking ≤ 10,000 B |

For comparison (bench, same VK): crown8-rawchain 77,193 B (8 inputs, unreviewed), intratx-residue 86,950 B
(11 inputs, unreviewed). The design estimate was ≈ 28.0 kB (27–29 kB).

Gates: valid accepted; 24/24 invalid vectors rejected; 4/4 proofs runtime-general; cross-stage staple: 2/2 seams
bound; public inputs bound (9/9 mutated claims rejected); layout gate: 3 pads, none malleable; worst-case proof
accepted; BCH-compatible (consensus) and standard; P2SH32 packaging; maintainer red-team file: all runs rejected (see
Verification).

Op cost profile (fixture 0, standard, `node profile.mjs`):
- **Input 0** (input 1 is the same within 1%), 7.04M in total:
  - event loop 6.15M:
    - affine doublings 2.58M (24 × 108k);
    - δ steps 1.57M (32 × 49k);
    - affine additions 0.80M (8 × 100k);
    - loop body 0.62M (GT-GLS, digits, flags);
    - chunk boundaries 0.33M;
  - setup 0.47M (powers of z, the four GT-GLS tables, loop environment);
  - redeem and code loading 0.11M;
  - remote reads 0.09M;
  - statement decoding and checks 0.09M.
- **Input 2**, 6.64M in total:
  - event loop 4.27M;
  - quotient 0.75M (114 words);
  - terminal 0.53M;
  - setup 0.47M;
  - binding 0.32M.

## Protocol

Notation: as in SI-GLS:
- Fp12 = Fp[X]/M(X), M = X¹² − 18X⁶ + 82;
- Φ, η and γ1 as there;
- λ = 6x+2+p−p²+p³ = m·r;
- d_0..d_64 is the NAF of 6x+2 (65 events, 21 additions);
- chunks of 2 events (the last has 1), with states S_1..S_33 after events 2, 4, …, 64, 65;
- N(a0 + a1u) = a0² + a1² is the Fp2 norm. Because p ≡ 3 (mod 4), N(a) = 0 ⟺ a = 0.

### Roles

| role = input | events | chunks | states | B steps (`t` witnesses) | δ slopes |
|---|---|---|---|---|---|
| 0 | [0, 24) | 0–11 | S_1..S_12 | 32 | 32 |
| 1 | [24, 48) | 12–23 | S_13..S_24 | 32 | 32 |
| 2 | [48, 65) + terminal + binding + quotient | 24–32 | S_25..S_33 | 22 + 2 terminal | 22 + 2 Frobenius |

### Witness items (all words 32-byte little-endian, decoded unsigned: `BIN2NUM(w ‖ 0x00)`)

- `STMT` (642 B), the same layout as SI-GLS `WS[0, 642)`:
  - `x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C, n0` (offset 256), `n1` (offset 288);
  - the GT-GLS nibble strings `N_0, N_1` (65 B each);
  - the residue root `s^c` (6 words).
- `S_i`, role i's stream (3,328 / 3,328 / 2,496 B). It is one record per chunk: the inverse norm `t` of each B step of
  the chunk's events, then the chunk's state (6 words). Role 2 then appends `t_ψ` and `t_{−ψ²}`.
  - Doubling at T = (x, y): `t = 1/(2N(y))`.
  - Addition of Q: `t = 1/N(x − x_Q)`.
- `DG` (96 B) = `d0 ‖ d1 ‖ d2`, where `d0 = SHA256(S_0)`, `d1 = SHA256(S_1)`, `d2 = SHA256(STMT ‖ S_2)`. Each `d_i` covers
  the committed items hosted in input i.
- `HAND_i` (i = 1, 2; 224 B): the 7 words `x_T.c0, x_T.c1, y_T.c0, y_T.c1, F+, F−, R` after event `cut_i − 1`, in
  canonical residues.
- `WQ`: the odd quotient coefficients, highest first (`32·n_q` B, 1 ≤ n_q ≤ 132, leading word ≠ 0). This is SI-GLS's rule.
- `FILL_i`: 0 ≤ L_i zero bytes. It buys op budget. No computation reads it, except that `FILL_2` is inside the z-tail
  hash.
- `DS_i` (2,048 / 2,048 / 1,536 B): role i's slice of the 88 baked δ slopes. It is a VK constant, authenticated by
  `SHA256(DS_i) == K_DS[i]`.
- `C_0, C_1`: the two pieces of the code blob.

### Unlocking layouts (every push minimal, R last)

```
input 0: [S_0 3,328] [DS_0 2,048] [C_0 3,767]                                  [FILL_0] [R]
input 1: [S_1 3,328] [HAND_1 224] [DS_1 2,048] [C_1 3,543]                     [FILL_1] [R]
input 2: [DG 96] [STMT 642] [S_2 2,496] [HAND_2 224] [DS_2 1,536]       [FILL_2] [WQ] [R]
```

Every range another input reads (`C_0`, `C_1`, `HAND_1`, `DG`, `STMT`, `HAND_2`) lies before every variable-length
push. The z-tail `ZT` is the raw bytes of input 2 from offset 5,007 (the `FILL_2` push header) up to the start of the
redeem push, i.e. `push(FILL_2) ‖ push(WQ)`.

### Transcript

- `h0 = SHA256(TAG ‖ DG)`;
- `ρ_raw = SHA256(h0 ‖ "rho")`;
- `z_raw = SHA256(h0 ‖ ρ_raw ‖ ZT)`;
- `ρ, z = BIN2NUM(· ‖ 0x00) mod p`, and `z ≠ 0` is required.

`TAG = "BNMX3/1" ‖ VK digest`, where the VK digest is the SHA256 of the 32-byte LE coordinates of α, β, γ, δ and IC0..IC2.

### The redeem R (65 B, the same in every input)

```
<0> OP_INPUTBYTECODE <5385> OP_SPLIT OP_NIP <3767> OP_SPLIT OP_DROP
<1> OP_INPUTBYTECODE <5611> OP_SPLIT OP_NIP <3543> OP_SPLIT OP_DROP OP_CAT
OP_DUP OP_SHA256 <K_code> OP_EQUALVERIFY <1> OP_DEFINE <1> OP_INVOKE
```

Function 1, the code blob:
- defines the shared functions (ids 2–21) and the three role programs (ids 22–24);
- then runs `OP_INPUTINDEX <22> OP_ADD OP_INVOKE`.

So each input runs only its own role. An input index without a role program fails as an undefined function.
Dispatching by function id instead of IF/ELSE matters on bch-2026: every instruction of an unexecuted branch still
costs 100.

### Role programs

**Common steps (every role).**
1. **Own layout.**
   - `DEPTH` equals the item count, and every fixed item has its exact size.
   - `FILL_i` is all zero: it is compared with `NUM2BIN(0, SIZE)`, never with a BIN2NUM test (a run with 0x80
     bytes is in the red team), and `SIZE ≤ 10,000`.
   - The own raw unlocking size `SIZE(OP_INPUTBYTECODE(OP_INPUTINDEX))` equals the fixed part plus the minimal push
     lengths of the variable pushes.
   - Role 2 only, on `WQ`: `SIZE ≡ 0 (mod 32)`, `32 ≤ SIZE ≤ 4,224`, and the leading word is nonzero (unsigned).
   - Role i: `DS_i` has its size and `SHA256(DS_i) == K_DS[i]`.
2. **Graph.** `OP_TXINPUTCOUNT == 3`, and `OP_UTXOBYTECODE(j) == OP_UTXOBYTECODE(OP_INPUTINDEX)` for j = 0, 1, 2.
3. **Remote reads.**
   - Role 0 reads `HAND_1` from input 1, and `DG`, `STMT` and `ZT` from input 2.
   - Role 1 reads `DG`, `STMT`, `HAND_2` and `ZT` from input 2.
   - Role 2 reads only its own bytecode (for `ZT`).
   - Before every remote range, the push header bytes in front of it are checked against their expected
     encoding.
4. **Transcript.**
   - Role i computes `d_i` from its own stack items and requires `DG[32i, 32i+32) == d_i`.
   - It then derives `h0`, `ρ` and `z` itself (`z ≠ 0`). No challenge is ever handed over.
5. **Statement (every role).** Every coordinate word and `s^c` word is decoded unsigned and checked `< p`;
   `n_k < r`; every nibble is ≤ 0x0f (130-byte mask).
   - Role 0 also checks `y_A² = x_A³ + 3`, `y_C² = x_C³ + 3`, and `y_B² = x_B³ + b'` (twist).
6. **Setup** (a shared function), as in SI-GLS:
   - z², …, z⁶ and (ηz)¹, …, (ηz)⁵;
   - `S_c(±z)`;
   - the GT-GLS tables `TP_k/TM_k` (16 entries each);
   - the loop environment (`y_P = −y_A`, `x_A·z`, `x_C·z`, …).
7. **Start state.**
   - Role 0: `T = B`, `F± = S_c(∓z)`, `R = 0`.
   - Roles 1, 2: `(T, F±, R)` from the own `HAND_i`, each word decoded `< p`.
   - Every role: the baked δ recursion state `(x_j, c_{j−1}, λ_{j−1})` at `j = J_AT[cut_i]`.
8. **Event loop** (a shared function), driven by the role's baked schedule. Per event it uses a digit string `SCH`
   and an explicit boundary flag string `BND`; both are asserted at load time against the single-input schedule.
   Each event:
   1. **Doubling.** Read `t` (`< p`). Set `λ = 3x²·conj(y)·t` and **require `t·2N(y) ≡ 1`**. Then
      `T ← (λ² − 2x, c − λx')` with `c = λx − y`. The line is `(1, −λ, c)`, and `F± ← F±²·(y_P ± o)` with
      `o = z³Φ(c)(z) − x_A z Φ(λ)(z)`.
   2. **δ step.** The baked slope comes from the δ pile; this is the reviewed SI-GLS kernel, verbatim.
   3. **Addition, if `d_e ≠ 0`.** `Q = d_e·B`.
      - Read `t`. Set `λ = (y − y_Q)·conj(x − x_Q)·t` and **require `t·N(x − x_Q) ≡ 1`**.
      - `T ← (λ² − x − x_Q, c − λx')`, with the line as above.
      - `F± ·= L(±z)·S_c(∓z)` (or `S_c(±z)` for `d_e = −1`).
      - A δ step.
   4. **GT-GLS.** `F± ·= TP/TM_0[N_0[e]]·TP/TM_1[N_1[e]]`.
   5. **At a boundary.** Read the state `S'` (6 words, `< p`; the record must then be empty). Then
      `R ← Rρ + F+·S'(−z) − F−·S'(z)` and `F± ← S'(±z)`, and take the next record.
9. **Clean stack**, leaving exactly `TRUE`.

**Roles 0 and 1, after the loop.**
- Require that every δ slope and every stream byte has been consumed.
- Encode `(x_T, y_T, F+, F−, R)` canonically, as `w = (v + p) mod p` with the top byte of `NUM2BIN(w, 33)` required to
  be 0x00, then its 32-byte LE.
- Require byte equality with `HAND_{i+1}`, read from input i+1.

**Role 2, after the loop.**
1. `T += ψ(B)` and `T += −ψ²(B) = (ω·x_B, y_B)`, each with its witnessed `t`, its line and the exact equation. Then
   the two δ Frobenius lines.
2. Require that every δ slope and witness byte has been consumed.
3. **Endpoint:** `T == −ψ³(B) = (ω·x_ψ, y_ψ)`, exactly (affine, every difference reduced and required to be 0).
4. `F± ·= Rconst(±z)·S_c(±ηz)`.
5. `c_j = Φ(γ1^j)(z)`, and `R ← Rρ + F+·W(−z) − F−·W(z)` with `W(x) = Frob(S_c)(x)·Frob(S_c)(ηx)`.
6. **Binding:** `acc_k = Σ_e 2^{64−e}·TB[N_k[e]]` over the integers, from the full nibble strings. Require
   `(acc_k − 2^64Σπ_i − n_k) mod r == 0`.
7. **Quotient:** Horner over `WQ`, 4 words per step, every word `< p`. Accept iff `(R − z·q(z²)·M(z)) mod p == 0`.

## Spec rules (the builder's checklist, design §4)

| rule | implementation |
|---|---|
| cuts at chunk boundaries; explicit per-range schedules | `CUTS = [0, 24, 48, 65]`, each asserted to be a chunk bound. Per-role `SCH` (digits) and `BND` (boundary flags) are baked and asserted against `DIGITS` and `isBoundary` (`protocol.mjs`, at load). The role-split value-level run equals one uninterrupted run (R, F±) on fixtures 0 and 4, and the 33 states equal the reviewed SI-GLS prover's states (`build.mjs`). |
| code identity | R hashes exactly the item it defines: `C_0 ‖ C_1`, at fixed ranges, `OP_DUP OP_SHA256 <K_code> OP_EQUALVERIFY <1> OP_DEFINE`, and nothing is re-pushed in between. Function ids are asserted distinct (`build.mjs`). Nested `OP_DEFINE` inside function 1 runs on libauth `BCH_2026` (3.1.0-next.8). |
| framing | Every role pins its own layout (`DEPTH`, every size, raw unlocking size) and checks the push header at every remote offset. `ZT` runs from a fixed offset to `len − |push(R)|`. Minimal pushes and push-only unlockings are consensus rules. |
| decoding | Every word is decoded unsigned (`BIN2NUM(w ‖ 0x00)`) and required `< p`; `n_k < r` and the nibble mask hold in every role (local decoding). `t < p`. The handover is canonical and compared byte-exactly. |
| filler | All zero (byte-exact), ≤ 10,000, and read by nothing except the `ZT` hash (`FILL_2`). |
| challenges | `z ≠ 0`; every input derives ρ and z itself. |
| graph | `TXINPUTCOUNT == 3` and every `UTXOBYTECODE(j)` equals the own one. Outputs are unconstrained: applications that release funds add output rules in role 2. |
| margins | Fillers are prover-sized to a ≥ 6% standard-mode margin per input (fixture 0: 6.00/6.00/6.00% standard, 6.46/6.46/6.47% consensus). Cap rule: the forced worst case per input is ≤ 0.94 × 8,032,800 (see Liveness). |
| reduced values before guards | Every equality or ≠0 guard tests a value reduced mod p (or mod r): the inverse-norm equations, curve checks, endpoint, binding, final identity. `z` is tested in [0, p). |
| nonzero line factors | Every B line has ℓ0 = 1 (affine), so its polynomial is nonzero. δ lines have ℓ0 = 1. Every other factor is monic. |

## Soundness argument (constructive: an owner for every value)

**Claim.** Suppose a transaction spending outputs locked `P2SH32(R)` is valid. Then `(A, B, C, n0, n1)` in `STMT`
satisfies Groth16 for the baked VK, except with probability `≤ q_H·2^−245` plus a SHA256 collision term.

1. **Pinning, without a hash cycle.**
   - A spent output forces `R`. `R` runs only a code blob with digest `K_code`.
   - That code requires exactly 3 inputs, all spending the same locking. So every input runs the same
     authenticated code, and the role equals the index.
   - The transaction is valid iff all three role programs accept. This pins the input count, the order, and every
     sibling's locking and code.
   - `R` contains `K_code`, and the code contains no digest of `R` (sibling identity is checked by locking equality).
2. **One transcript.**
   - Every role reads `DG`, `STMT` and `ZT` from the same consensus bytes, at offsets made exact by:
     - the owner's own layout pin;
     - the header checks in every reader;
     - push-only, minimal-push unlockings.
   - Each `d_i` is checked by the owner of its preimage. So `h0` determines `(S_0, S_1, STMT, S_2)` up to a SHA256
     collision; all of these are fixed width.
   - `ρ` depends only on `h0`. `WQ` (length-ruled, with a canonical leading word) enters only `z`, after ρ. So every
     polynomial `D_k` is fixed before ρ, and `Q` before z, as in SI-GLS.
   - Each role derives the same `(h0, ρ, z)`.
3. **Value owners.**

| value | owner |
|---|---|
| code, field constants (`R_{k,i}`, `Rconst`, `γ1`, `η`, `b'`, `p`, `r`, `TAG`), δ start states, schedules | VK constants in the code: `P2SH32(R) → R ∋ K_code`. Each one is regenerated from the VK and asserted against noble when `../sound-si-gls/math.mjs` loads. |
| δ slopes `DS_i` | VK constants, `SHA256(DS_i) == K_DS[i]` (in the code) |
| A, B, C, n0, n1, N_k, s^c | hash-committed (`d2`, then `h0`) before ρ. Canonical decoding in every role; curve, twist and nibble checks in role 0 (the nibble mask in every role). |
| the 33 states | hash-committed (`d_i`) before ρ; `< p` when read |
| `WQ` | hash-committed through `ZT` before z; `< p`; length rule and nonzero leading word |
| inverse norms `t` | the exact equation `t·N(den) ≡ 1` with `t < p`. The solution is unique and forces `den ≠ 0` (anisotropic norm). They are also committed (harmless). |
| the B trajectory, λ, lines, ±z evaluations, tables, F±, R, acc_k | computed on-chain |
| `HAND_i` | byte equality with the canonical encoding of the values that role i−1 computed (top byte checked: never a negative value), and decoded `< p` by role i |
| `FILL_i` | outside every computation; all zero; only in `ZT` (harmless) |

4. **Handover induction.**
   - Role i's computation is deterministic from the constants, the committed data, the challenges and `HAND_i`.
   - Role i requires `HAND_{i+1}` to equal its own results.
   - So role i+1 starts from exactly the single-run state after event `cut_{i+1} − 1`, in canonical residues.
   - Splicing in an input from a second proof changes some `d_i` or a handover and fails. The bench staple gate and
     the red team test every seam.
5. **The B walk.**
   - Every accepted step is the exact affine group law. A doubling requires `N(y) ≠ 0`, i.e. `y ≠ 0`. An addition
     requires `x ≠ x_Q`. Then `λ = num/den` exactly.
   - An exceptional step (doubling a 2-torsion point, adding ±T) cannot satisfy its equation. This replaces
     SI-GLS's "Z = 0 is absorbing" argument.
   - The endpoint `T == −ψ³(B)` gives `λ(ψ)(B) = O`. With `gcd(N(λ(ψ)), 2p − r) = 1` (asserted in SI-GLS
     `math.mjs`), `B ∈ G2`.
   - Honest completeness: no step of the fixed NAF schedule (65 doublings, 21 additions, 2 terminal additions) is
     exceptional for `B ∈ G2` (`research/sound-bn254-native/prototypes/facts.mjs`).
6. **Reduction to SI-GLS.**
   - Each affine B line is SI-GLS's projective line divided by an Fp2 scalar. Fp2 ⊂ Fp6, so it is in the same class
     in G = Fp12*/Fp6*.
   - The line slots `(y_P·Φ(ℓ0) + x_P X Φ(ℓ1) + X³Φ(ℓ3))` have the same degrees (≤ 9). So the per-event degrees,
     `NQ_MAX = 132` and the degree bound 275 are SI-GLS's.
   - The states are the same classes; `build.mjs` asserts that they equal SI-GLS's on fixtures 0 and 4.
   - Each `D_k` uses the on-chain line polynomials and is chained into `R` in the same Horner order with the same ρ
     weights, so the conjunction of the 3 roles is SI-GLS's batched check, term for term.
   - The rest follows verbatim:
     - `D ≡ 0 mod M` gives `[P_k] = [S_{k+1}]`;
     - `[f'] = [c]^λ` gives `FE(f') = 1`;
     - the mod-r binding of the hashed, range-checked nibbles gives the Groth16 product `e(vk_x, γ)`.

**Soundness error** per random-oracle query: `ε ≤ 1.134·(33 + 275)/p ≈ 2^−245.15`, as in SI-GLS, plus a SHA256
collision term for the extra digest layer.

### Code-as-witness checklist (design merge item 7)

- The item that is hashed is the item that is defined. R concatenates the two fixed ranges, then does
  `OP_DUP OP_SHA256 … OP_EQUALVERIFY <1> OP_DEFINE`.
- The pieces sit before every variable-length push of their host. The hosts' own layout pins and R's fixed ranges
  coincide. A flipped code byte in either piece is rejected in every input (red team).
- Function ids: 2–21 for the shared functions, 22–24 for the role programs, 1 for the body. They are asserted
  distinct, and no id is redefined (`OP_DEFINE` of an existing id fails in the VM).
- Dispatch: `OP_INPUTINDEX + 22`. An index ≥ 3 has no function (it fails), and `GRAPH` pins the count anyway.

## Liveness

- **The fixture is sized with margin.** The honest prover sizes each filler so that the input's standard-mode op cost
  is at most 94% of its budget (`transaction.mjs`, `sizeFills`). The unlocking is capped at 10,000 B.
- **Cap rule.** Each input's op cost is almost statement-independent (fixed schedule, table-based GT-GLS); only role
  2's quotient length varies (n_q 60–132). So the binding condition is the cap: at 10,000 B the budget is
  8,032,800. The build passes only if every input of every swept case stays ≤ 0.94 × 8,032,800 = 7,550,832 in both
  modes.
- **Sweep** (`sweep.mjs`, both modes, every case accepted and the cap rule met): see `sweep.json` and Verification.
  - The fixtures.
  - Special inputs.
  - The forced GT-GLS witnesses:
    - every nibble 15 (n_q 132);
    - every nibble 0 (n_q 60);
    - every nibble 1;
    - the review's worst case (nibble 4, and 0 at the addition-first events 20, 26, 34, 50, 54).
  - The 8 lowest-n_q statements of a 20k search.
  - A lattice-shifted valid witness.
  - 400 random proofs.

## Deviations from the design text (and why)

- **No constants blob, and no `K_consts`.** The field constants are inline pushes in the code. The code is split
  into two pieces, hosted in inputs 0 and 1, and concatenated by R (+8 B of R). This removes the remote constants
  reads and their parsing (about 80k op per role), and the bytes are the same.
- **`DG` and `STMT` live in input 2, and `d2 = SHA256(STMT ‖ S_2)`.** Each `d_i` still covers exactly what input i
  hosts. Role 2 needs no remote read; role 1 needs one; role 0 needs two.
- **`DS_i` is hosted in input i itself.** It is an own item, hash-checked, with no remote read.
- **Dispatch by function id, and the loop's add-step and boundary bodies as functions.** On bch-2026 an unexecuted
  branch costs 100 per skipped instruction. Together these cut about 0.9M op.
- **The binding is computed once in role 2,** from the full nibble strings, instead of being accumulated in the loop
  and handed over.

## Compiler and tooling

- `asm.mjs`: the SI-GLS symbolic assembler, copied and extended. The kernels are a DAG local-search scheduler on the
  exact op model. The changes against the reviewed copy:
  1. Bound functions are matched on a window: the top items, down to the deepest item that the body touches. This
     lets the three roles, which keep different items lower on the stack, share one loop.
  2. Function ids above 16 are allowed.
  3. Kernels can read items below a pile of known size.
  4. `roll` splices by symbolic index (fixed: physical depth ≠ index below a pile).
  5. `arrange` no longer keeps a prefix that is not adjacent (fixed).
  6. An optional lazy-reduction pass. It is off: the static cost model is not accurate enough for it.
- `kernels.mjs`: the affine inverse-norm kernels (`kADblN`, `kAAddN`), plus `kDStep`, `kEval` and `kTable` verbatim
  from SI-GLS.
- `protocol.mjs`: roles, schedules, δ slices and start states (asserted), the transcript, the affine prover (exact
  divisibility of every identity is asserted), and a value-level mirror (handovers, final identity).
- `script.mjs`: the shared functions, the three role programs, the body, R and the layout.
- `transaction.mjs`: unlockings and prover-sized fillers. `vm.mjs`: the bch-2026 runners for the 3-input tx.
- `build.mjs`: a deterministic double build plus every assert listed above, and a smoke spend.
  `export.mjs`: the bench vectors. `redteam.mjs`: the rejection suite, locating the guard that fires. `sweep.mjs`:
  liveness. `profile.mjs`: op cost by section and function.

## Reproduce

```sh
# in this directory, with the repository's dependencies (@noble/curves 2.2.0, @bitauth/libauth 3.1.0-next.8)
node build.mjs                                             # code 7,310 B sha256 75c780ae…78d7; R 65 B; writes build.json
node export.mjs vectors.json                               # bench vectors (fixtures 0-4, 24 invalid runs)
node redteam.mjs vectors.json redteam.json redteam-report.json   # every run rejected; bench red-team file
SWEEP_N=400 node sweep.mjs sweep.json                      # liveness, both modes, cap rule (SWEEP_SHARD=k/n to split)
node profile.mjs                                           # op cost by section / function (FIX=, MODE=)
```

In zk-verifier-bench:
- copy `vectors.json` to `src/bch/groth16-bn254-sound-native-vectors.json`;
- copy `redteam.json` to `src/bch/redteam/bch-groth16-bn254-sound-native.json`;
- then run `npx tsx tools/bench-one.mts bch-groth16-bn254-sound-native`, the exact-id gate driver.

## Verification

- **Red team** (`redteam.mjs`, rejection tests only). Every run is rejected in consensus and standard mode, and
  `redteam-report.json` names the input and the guard that fires.
  - **How the runs are built.** Committed items are tampered *with `DG`, the challenges and the handovers
    recomputed*, so that the specific guard has to reject, not just a hash check.
  - **What they cover:**
    - public-input claims with an otherwise honest witness (rejected at the binding);
    - `n + r` and top-bit encodings;
    - off-curve, off-twist, identity and negated points, and `+p` aliases;
    - nibble range, negative zero and bit flips;
    - lattice-shifted digits with stale identities;
    - residue-root tampering;
    - states, their aliases and swaps;
    - inverse norms (`t + p`, `t = 0`, a wrong `t`; doubling, addition and both terminal additions);
    - quotient words, aliases, length, the 133-word cap, a leading zero and another proof's quotient;
    - handover words (+1, +p alias, bit flip, shifted, another proof's);
    - whole-input staples from a second valid proof;
    - layout (extra, missing or swapped pushes; a nonzero or 0x80 filler; an oversize unlocking; redeem, code and
      δ-slice bytes; non-minimal pushes that shift remote offsets; a non-push opcode; swapped inputs);
    - graph (2 or 4 inputs, a foreign P2SH32 input, run locally only).
  - **Positive controls:** fixture 0, and a valid lattice-shifted GT-GLS witness.
- **Liveness** (`sweep.json`, 424 cases, 4 shards):
  - every case is accepted in both modes; n_q ranges over 60–132;
  - the minimum per-input margin with prover-sized fillers is 6.00 / 6.00 / 6.00% standard and 6.45 / 6.46 / 6.46%
    consensus;
  - the cap rule holds everywhere. The worst op per input is 7,058,054 / 7,014,010 / 6,793,381 standard, all at
    "every nibble 15". That leaves 12.13 / 12.68 / 15.43% below the 10,000-byte cap budget (the rule needs ≥ 6%).
- **Determinism:** `build.mjs` builds twice and compares the bytes. Code sha256 `75c780ae…78d7`, vectors sha256
  `2fa0a45a…1014`, red-team file sha256 `86084f1a…3dcc`.
- **Bench gates:** see Results.

## Open risks

- **Not independently reviewed.** The affine kernels, the 3-input glue, and the assembler extensions are new code.
  Formula correctness is tested, not machine-proved:
  - exact divisibility of every honest identity in the prover;
  - noble cross-checks of all constants and of the δ recursion;
  - every swept proof accepted;
  - the red team.

  There is no formal equivalence proof of the generated bytecode.
- **Owner decisions** (as listed in the design):
  - **Prover-sized zero filler.** If it is rejected, fix `WQ` at 132 words. That is about +576 B at fixture 0;
    injectivity holds by the fixed width, and the degree argument holds with leading zeros.
  - **Code read from inputs 0 and 1's unlocking bytes** and authenticated by `R ∋ K_code`. This pattern is new to
    the bench and needs the owner's OK to count as verifier code.
  - **Public inputs bind through the GT-GLS fold and the mod-r check,** as already accepted for SI-GLS.
- **Margins are thin by design.** The fixture is at 6.00% standard (6.46% consensus). The worst swept case at the
  10,000-byte cap leaves 12.1%. Any later change that adds op cost must re-run `sweep.mjs`.
- **Outputs are unconstrained** (as for SI-GLS). An application that releases value must add output rules (for
  example in role 2), or anyone holding a valid proof can redirect the spend.
