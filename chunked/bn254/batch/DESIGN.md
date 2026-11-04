# Track 13: batch Groth16 verification on BCH (design note, not built)

Status: **design and cost model only.** No verifier code exists. This note is for review before any code is written.
Branch `wip/g16-batch`, 2026-11-04. Base: the reviewed sound-native verifier `../bn-native-sound` (SI-MX3, 27,624 B,
3 inputs, 20.67M op, bench id `bch-groth16-bn254-sound-native`).

## 0. Summary

- **The check.** N proofs under one VK. The verifier derives random 128-bit coefficients `r_i` on chain, with SHA-256
  over all N proofs, all public inputs and the VK. It then checks one pairing-product equation:

  `Π e(r_i·A_i, B_i) = e(α,β)^{Σ r_i} · e(Σ r_i·vk_x_i, γ) · e(Σ r_i·C_i, δ)`.

  This is the small-exponents batch test (Bellare–Garay–Rabin). It runs inside the base verifier's residue/torus
  machinery, so the δ loop, the GT-GLS fold, the residue root, the 33 states and the quotient are paid once per batch.
- **What it costs (MODELLED from MEASURED per-phase costs; section 4).** Batching saves about 11.2M op per extra
  proof: everything except that proof's own B walk. It spends about 7.9M op per extra proof on the two G1 scalar
  multiplications by `r_i` (one for `r_i·A_i`, one for the `C` MSM), plus the overhead of the extra inputs. With
  128-bit `r_i`:

  | N | 1 (base, measured) | 2 | 3 | 4 | 5 | 6 |
  |---|---|---|---|---|---|---|
  | tx bytes | 27,559 | 62,788 | 88,065 | 114,969 | 140,446 | 167,630 |
  | per proof | 27,559 | 31,394 | 29,355 | 28,742 | 28,089 | 27,938 |

  N ≥ 4 does not fit one 100 KB standard tx.
- **Largest N in one standard tx: 3** (≈ 88.1 KB, 9 inputs).
  - Per proof that is 29.4 KB, **more than the 27.6 KB of one unbatched verifier**.
  - With a GLV-split `r_i` (an option that needs one extra checked lattice fact), N = 3 is ≈ 81.1 KB, 27.0 KB per
    proof (−2%). N = 4 is ≈ 105 KB and does not fit.
- **The survey's hypothesis is not confirmed.** It predicted N = 5 in ≈ 92 KB, 18.5 KB per proof. The model gives
  N = 5 at ≈ 140 KB, or ≈ 129 KB with GLV.
  - The survey priced one ~3M scalar mult per proof. The batch needs two per proof (`r_i·A_i` and `r_i·C_i`), each
    over a 128-bit scalar: ≈ 6.2M + 1.8M.
  - It also left out the shared 128 doublings of the C MSM (4.4M) and the per-input overhead of the 4–6 extra inputs
    (≈ 0.9M each).
- **The comparator needs no new math.** It puts N independent copies of the base verifier in one tx: 27.5 KB per
  proof, N ≤ 3 per tx (82.6 KB). This needs only a graph/dispatch change: role = index mod 3, an instance offset,
  and an input count of 3N. That change still needs its own review.
- **Recommendation for the review.** Do not build the baseline batch. It is new soundness-relevant code (G1 scalar
  multiplication, a third GT-GLS table, an N-wide Miller loop, an r-transcript, ≥ 9-input glue) and it buys nothing
  per proof. The review has three ways forward:
  - (a) stop Track 13 here;
  - (b) take the co-located comparator, if "several proofs in one tx" is the actual goal;
  - (c) build only the GLV-128 variant, and only if a per-proof saving of about 2% at N = 3 (one tx) or about 7% at N = 6 (two txs,
    which would also need a cross-tx design) is worth the review cost.

  The design below is complete enough for the review to judge (c). It is also the starting point if the cost picture
  changes, for example cheaper multiplication under a VM-limits change.

## 1. The batched check

### 1.1 Equation and how it maps onto the base verifier

The base verifier proves `FE(f) = 1` for one Miller product. In the notation of `../bn-native-sound/README.md`:

`f = m(−A, B) · m(C, δ) · m(α,β)·m(IC0,γ) · m(IC1,γ)^{n0} · m(IC2,γ)^{n1} · corr`

- `m(C, δ)` is the fixed-G2 δ loop with baked slopes.
- `m(α,β)·m(IC0,γ)` is the baked constant `mConst`, folded into `Rconst` together with the GLS offset correction
  `corr`.
- The two `m(IC_k,γ)^{n}` factors are the GT-GLS fold. Each uses a 4-way Frobenius split with 65 nibbles, bound by a
  mod-r check.

Proof: `FE(f) = 1` ⇔ `[f'] = [c]^λ` for the committed residue root `c`. This is checked by a batched polynomial
identity at ±z over 33 committed states and one quotient.

The batched product is the same shape, with N variable pairings and three GT exponents:

```
f_batch = Π_{i=1..N} m(P_i, B_i) · m(C*, δ) · mConst^{s_0} · m(IC1,γ)^{s_1} · m(IC2,γ)^{s_2} · corr'
    P_i = −(r_i·A_i)            (affine, computed on chain)
    C*  = Σ_i r_i·C_i           (affine, computed on chain)
    s_0 = Σ_i r_i mod r,  s_1 = Σ_i r_i·n0_i mod r,  s_2 = Σ_i r_i·n1_i mod r
```

`e(Σ r_i·vk_x_i, γ) = e(IC0,γ)^{Σ r_i}·e(IC1,γ)^{Σ r_i n0_i}·e(IC2,γ)^{Σ r_i n1_i}`, and `e(α,β)` has the same
exponent `Σ r_i` as `e(IC0,γ)`. So the whole fixed part is **three GT-GLS exponentiations of baked GT constants**:
- base `mConst = m(α,β)·m(IC0,γ)`, which is today's constant part, now raised to `s_0`;
- `m(IC1,γ)`;
- `m(IC2,γ)`.

No `vk_x_i` is ever formed. The public inputs enter only through Fr arithmetic and the GLS binding. `corr'` is the
GLS 2^64-offset correction over all three tables. It replaces `corr`, and `Rconst' = monicRep(corr')`.

`FE(f_batch) = 1` is exactly the batched equation above, with `A_i` negated as in the base. It is checked by the
unchanged mechanism:
- one residue root `c` for the whole product;
- the same 65-event NAF schedule;
- the same 33 states (chunks of 2 events);
- one quotient.

Each event now multiplies in N B-lines (one per proof) instead of one, and three GT-GLS table entries instead of two.
The δ lines, the residue-root factors at addition events, the squarings, the boundaries and the terminal (`Rconst'`,
`W`, `c_j`) are shared.

### 1.2 Where the `r_i` come from (Fiat–Shamir, on chain)

```
TAG_B   = "BNBATCH/1" ‖ VK_DIGEST ‖ byte(N)        (VK_DIGEST as in bn-native-sound)
STMT*   = for i = 1..N: x_A, y_A, x_B.c0, x_B.c1, y_B.c0, y_B.c1, x_C, y_C, n0, n1   (320 B per proof, 32-byte LE words)
h_r     = SHA256(TAG_B ‖ STMT*)
r_1     = 1
r_i     = BIN2NUM(SHA256(h_r ‖ byte(i))[0..16) ‖ 0x00)        for i = 2..N; require r_i ≠ 0
```

- **Computed on chain, after every proof is fixed.** `STMT*` is the complete statement: all proofs, all public
  inputs, the VK (through `VK_DIGEST`) and N. Every role that uses an `r_i` derives it itself from `STMT*`. No `r_i`
  is ever pushed or handed over. This is the base rule "no challenge is ever handed over".
- **`r_1 = 1`** is the standard trick, and it saves one scalar multiplication. The bound below does not need `r_1` to
  be random. If only proof 1 is invalid, the batch equation fails deterministically.
- **`r_i ≠ 0`** is a completeness rule: `0·A_i` is the point at infinity, which has no affine form. The honest prover
  re-randomizes a proof if it ever hits 0 (probability 2^−128 per index). It is not needed for the soundness bound.
- **After the r-transcript,** the prover computes everything that depends on `r`:
  - `P_i` and `C*`;
  - the GT-GLS nibble strings for `s_0, s_1, s_2`;
  - the residue root;
  - the states;
  - the quotient.

  The base transcript then runs unchanged on top. `DG` covers `STMT*`, the published points `PT`, the GLS item and
  every stream, so `h0 = SHA256(TAG_B ‖ DG)` fixes all of them before ρ, and the quotient before z.

### 1.3 Bit length and soundness error

- **Parameter.** ℓ = 128: `r_i` is uniform on `[0, 2^128)`. Every value is a distinct residue mod r, because
  2^128 < r.
- **Bound.** The small-exponents test (Bellare, Garay, Rabin, *Fast Batch Verification for Modular Exponentiation and
  Digital Signatures*, EUROCRYPT 1998, §3) carries over to pairing-product equations in prime-order groups
  (Ferrara, Green, Hohenberger, Pedersen, *Practical Short Signature Batch Verification*, CT-RSA 2009). Write each
  proof's defect as `X_i = e(A_i,B_i)·(e(α,β)e(vk_x_i,γ)e(C_i,δ))^{−1} = g_T^{x_i}`. The batch accepts iff
  `Σ r_i x_i ≡ 0 (mod r)`.
  - If some `x_j ≠ 0` with `j ≥ 2`, fix all other `r_i`. At most one residue of `r_j` satisfies the congruence, so
    the probability is `≤ 2^−128`.
  - If only `x_1 ≠ 0`, the batch rejects.
  - With Fiat–Shamir, each random-oracle query returns a fresh `(r_2..r_N)` for a fixed statement. A union bound
    gives `≤ q_H · 2^−128`.
- **Precondition: group membership.** The bound needs every `A_i, C_i ∈ G1` and every `B_i ∈ G2`. Then each `X_i`
  lies in the order-r group μ_r. Small-exponent batching without membership checks is unsound (Boyd, Pavlovski,
  *Attacking and Repairing Batch Verification Schemes*, ASIACRYPT 2000). So the per-proof checks of section 2 are
  part of the batch argument, not only of each proof.
- **Total.** Fiat–Shamir error `q_H·2^−128`, plus the base residue-machinery error `q_H·1.134·(K_IDS + deg)/p`, plus
  SHA-256 collision terms.
  - The base term grows only through the degree bound: about 2^−244 at N = 3 (deg ≈ 437, n_q ≤ 213).
  - The batch term dominates. The batch is a 128-bit construction on a ~100-bit curve, so it is not the weakest
    link.
- **Lower ℓ.** ℓ = 100 would match BN254's estimated security level. Section 4 prices it. It is an owner decision
  (section 6), not the default.
- **GLV option.** `r_i = a_i + b_i·λ_φ mod r`, with `a_i, b_i` 64-bit values from the hash and `λ_φ` the eigenvalue of
  the G1 endomorphism `φ(x,y) = (β_3·x, y)`. Then `r_i·A = a_i·A + b_i·φ(A)` needs only 64 shared doublings.
  - The same bound holds **if and only if** `(a,b) ↦ a + bλ_φ mod r` is injective on `[0,2^64)²`. That holds iff the
    lattice `{(a,b) : a + bλ_φ ≡ 0}` has no nonzero vector with both `|a|, |b| < 2^64`.
  - The reduced basis of that lattice has vectors of length ≈ 2^127, so this is expected to hold. It must be asserted
    in code at load time, from the reduced basis, before the option is used.
  - This is a checkable fact, not new math. Until it is checked, the option is a hypothesis.

## 2. What stays per proof

Each check below exists in the base verifier for its single proof. **Each must run for every proof `i`**, and the
batch argument depends on it (section 1.3).

| check | how bn-native-sound does it today | batch rule |
|---|---|---|
| `A_i` on curve, hence in G1 | role 0: `G1C` (`y² = x³ + 3`) on canonical words `< p`. G1 has cofactor 1, so on-curve means in G1. An affine encoding cannot be the identity: (0,0) is not on the curve. | `G1C` on every `A_i`, in the statement host |
| `C_i` on curve, hence in G1 | same (`G1C`) | `G1C` on every `C_i` |
| `B_i` on the twist | role 0: `y² = x³ + b'` on canonical Fp2 words | twist check on every `B_i` |
| `B_i ∈ G2` | the B walk itself. Every affine step meets its exact inverse-norm equation, and the terminal requires `T == −ψ³(B)`. That gives `λ(ψ)(B) = O`, and with `gcd(N(λ(ψ)), 2p − r) = 1`, `B ∈ G2`. | **unchanged per proof.** Each `B_i` has its own walk `T_i`, its own two terminal additions and its own endpoint equality `T_i == −ψ³(B_i)` in the terminal role. This is the costly per-proof part (≈ 9.2M op), and it is also the G2 subgroup check: it cannot be shared. |
| canonical words | every word decoded `BIN2NUM(w ‖ 0x00)` and `< p` (coordinates) or `< r` (public inputs) | every role that reads a word range-checks it (local decoding, as in the base) |
| public inputs `n0_i, n1_i < r` | `n_k < r` in every role | `< r` for all 2N words, in every role that reads them (the binding role and the statement host) |
| nonzero line factors | the X^0 coefficient of a B line is `y_P = −y_A ≠ 0`, because A is on a curve without 2-torsion | `y_{P_i} ≠ 0`: `P_i` is checked on curve (`G1C` on the computed point, section 3), and it is not O (`r_i ≠ 0`, `A_i ≠ O`, and `t·Z ≡ 1` at the affine conversion). The same holds for `C*` and the δ lines. |

**Binding.** Groth16 proofs are re-randomizable, so nothing may depend on proof bytes. Binding goes through the
public inputs only. In the batch, proof `i`'s public inputs `(n0_i, n1_i)` enter only through `s_1, s_2` and the GLS
binding. This proves `Π X_i^{r_i} = 1`, which (section 1.3) means every statement `(n0_i, n1_i)` has a valid proof.
How those statements tie to the transaction is the caller's choice. There are two supported modes:

1. **Left to the caller (core build).** As in the plain base build, `n_{k,i}` come from the spender's `STMT*`. A
   valid batch for any N statements is accepted. Outputs are unconstrained. Do not fund such a covenant with value.
2. **Track 12 pattern, per proof.** The `setCovenant` hook generalizes to `setCovenant(fn, i)`, run by the statement
   host for each i. It sits after `STMT*` is decoded and range-checked, and before any challenge-dependent step.
   - Proof i's public values are rebuilt from transaction introspection, for example output group `i` (outputs
     `[o_i, o_{i+1})` with application-defined bounds), the way `../pinned/template.mjs` rebuilds PV from all
     outputs.
   - `n_{k,i}` must equal the values computed from them (NUMEQUALVERIFY). The spender's `STMT*` copy is only
     compared.
   - Track 12's limits carry over: one funding per instance, no tokens on outputs, no self-payment. Replay across
     fundings is still possible.
   - A batch also needs one decision Track 12 did not: **whether two slots may carry the same statement.** See
     section 6. The default proposed here is that the hook requires the N statements to be pairwise distinct (an
     O(N²) comparison of 64-byte tuples, < 10k op at N ≤ 6).

## 3. Owner table and cross-input layout

### 3.1 Roles

Each input runs one role. The role is chosen by `OP_INPUTINDEX + base_id` from one code blob, authenticated by
`R ∋ K_code`, exactly as in the base.

| role | runs | count (N = 3, baseline) |
|---|---|---|
| **M_j** (Miller) | an event range `[cut_j, cut_{j+1})`. Per event: the shared F± squaring, N affine B steps (doubling, plus an addition if `d_e ≠ 0`), the δ step(s), 3 GT-GLS products and the boundary. Every M role pays the full per-role setup (z powers, `S_c(±z)`, 3 × 2 GT-GLS tables, the env for each `P_i` and for `C*`). | 6 |
| **M_last** (also the statement host H) | the last event range, plus: the terminal (N × (`+ψ(B_i)`, `+(−ψ²(B_i))`, endpoint), the 2 δ Frobenius lines, `Rconst'`, W), the binding (`s_k`, the 3 GLS accumulators), the quotient | (1 of the 6) |
| **S_j** (scalar mult) | either `r_i·A_i` for one or two i (4-bit fixed windows from the bytes of `r_i`, a Jacobian accumulator, an affine table built by witnessed additions, and a final affine conversion), or a window range of the Straus MSM for `C*` | 3 |

**Hosting.**
- H hosts `DG`, `STMT*`, `GLS` (3 × 65 nibble bytes + the 6-word residue root) and `PT`. `PT` is `N − 1` points
  `P_i` (i ≥ 2) plus `C*`, 64 B each, affine canonical; `P_1 = −A_1` is not published.
- Every range another input reads lies before every variable-length push, as in the base.
- The code blob (≈ 10 KB modelled) is hosted as two pieces in M_0 and M_1, read by `R` at fixed ranges, as today.

### 3.2 Owner table

| value | owner (which input, which code) | how it crosses inputs |
|---|---|---|
| code, field constants, 3 × 4 GT-GLS factor polynomials `R_{k,i}` (k = 0 is new: `mConst`), `Rconst'`, δ start states, schedules, `N`, `TAG_B` | VK constants in the code: `P2SH32(R) → R ∋ K_code`. Each is regenerated from the VK and asserted against noble when the math module loads (the base rule, extended to table k = 0 and `corr'`) | every input loads the same authenticated blob |
| δ slopes `DS_j` | VK constants, `SHA256(DS_j) == K_DS[j]` | own item |
| `A_i, B_i, C_i, n0_i, n1_i` (in `STMT*`) | **hash-committed**: in `h_r` (before every `r_i`) and in `d_H`, then `h0` (before ρ). **Canonical decoding** by every reader. **Curve and twist checks** in H for every i. **G2 membership** by the `B_i` endpoint in M_last for every i. **`n_{k,i} < r`** in every reader. | M and S roles read the `STMT*` ranges they need from H by introspection, after checking the push header (the base remote-read pattern) |
| `r_i` | **computed** from `h_r` by every role that uses it: the S roles that hold `r_i·A_i` or a `C*` window range, and M_last (for `s_k`). `r_1 = 1` is a constant, and `r_i ≠ 0` is required. | never crosses inputs. Each role recomputes it from the same `STMT*` bytes |
| window digits of `r_i` | **computed** by splitting `r_i`'s 16 bytes into nibbles. No digit witness. | — |
| G1 table entries `j·A_i`, `j·C_i` (j = 2..15) | **exact equations**: each is a witnessed affine addition `t·(x − x_Q) ≡ 1`, `t < p`, so `λ` is the exact chord slope and an exceptional addition cannot be satisfied (the B-walk argument, in Fp) | own stream of the S role |
| Jacobian accumulator `(X, Y, Z)` across S roles (the C* MSM, when split) | **computed**; byte equality of the canonical residues with the next S role's `HAND_S` (the base `HAND` pattern) | introspection read of `HAND_S` by the previous S role |
| `P_i` (i ≥ 2) and `C*` in `PT` | **computed** by the S role that holds them. Final conversion: witness `t`, exact `t·Z ≡ 1` (which forces `Z ≠ 0`), then `x = X t²`, `y = Y t³`, then `G1C` on `(x, y)`, then byte equality with its `PT` slot. Also hash-committed in `d_H`, hence before ρ (belt and braces: it is already determined by `STMT*`). | M roles read `PT` from H. The owner's equality check makes every accepting tx carry the computed value. |
| exceptional Jacobian steps | `madd` with `T = ±Q` gives `H = 0` and `Z3 = 0`. `dbl` of O gives `Z3 = 0`. `Z = 0` is absorbing (`Z3 = 2YZ`, `Z3 = 2ZH`), so the final `t·Z ≡ 1` fails. This is the "Z = 0 is absorbing" argument of the reviewed SI-GLS walk, now in G1. The accumulator starts from the first nonzero table entry (affine, Z = 1), never from O. A valid run's only cost is completeness, with negligible probability. | — |
| `s_0, s_1, s_2` | **computed** in M_last from `STMT*` and the `r_i` (Fr arithmetic, every `n < r`) | — |
| GT-GLS nibble strings `N_0, N_1, N_2` | **hash-committed** in `GLS` (in `d_H`, before ρ). Every nibble ≤ 0x0f (mask) in every reader. **Exact mod-r binding** in M_last: `acc_k − 2^64·Σπ_i ≡ s_k (mod r)` for k = 0, 1, 2. Any valid GLS witness is acceptable; the base binding argument is unchanged. | M roles read `GLS` from H |
| GT-GLS exponent sums `s_k` vs the folded tables | the per-event table products are **computed** from the committed nibbles. Table values are evaluations of baked polynomials at ±z (computed). | — |
| residue root `s^c` | hash-committed (`GLS` ∈ `d_H`) before ρ; `< p` | read from H |
| the 33 states | hash-committed (`d_j`) before ρ; `< p` | own stream |
| inverse norms `t` of every B step (N per step) | exact equation `t·N(den) ≡ 1`, `t < p` (unchanged kernel) | own stream |
| `HAND_j` = `(T_1..T_N, F+, F−, R)`, (4N + 3) words | byte equality with the canonical encoding that M_{j−1} computed (top byte checked); decoded `< p` by M_j | introspection, as in the base |
| `WQ` | hash-committed via `ZT` before z; length rule `32 ≤ |WQ| ≤ 32·NQ_MAX(N)` with `NQ_MAX(3) = 213`; nonzero leading word; every word `< p` | own item of M_last |
| F±, R, lines, ±z evaluations, the `B_i` trajectories, the δ recursion | computed on chain | via `HAND_j` |
| `FILL_j` | outside every computation, all zero. `FILL_last` is inside `ZT`. The others are free (txid only), as in the base. | — |
| graph | `TXINPUTCOUNT == n_in(N)` and every `UTXOBYTECODE(j)` equals the own one | — |

**What changes from the base pattern, and what does not.**
- Unchanged:
  - code-as-witness;
  - layout pins;
  - remote reads with header checks;
  - `d_j`/`h0`/ρ/z;
  - canonical handovers;
  - the δ pile;
  - the quotient Horner.
- New:
  - the r-transcript `h_r` (a second, earlier challenge stage, derived from `STMT*` only);
  - the `PT` item and its owners (the S roles);
  - the S roles themselves;
  - `HAND` widened to N walks;
  - a third GT-GLS table;
  - the N-wide terminal.
- One rule tightens: in the base, every role decoded the whole `STMT`. Here each role decodes only the words it uses,
  each with the same range rule. Every proof's curve and twist checks run in exactly one place (H).

### 3.3 Degree bound

The SI-GLS structural bound extends without new argument.
- **Per event:** N B lines (degree ≤ 9 each), one δ line (≤ 9). An addition event adds N more B lines (≤ 9 each), a
  δ line (≤ 9) and the c factor (6). GT-GLS adds 6 per set nibble bit (≤ 12 bits for 3 tables).
- **Per chunk:** `d ← 2d + eventDeg`, from `d = 6`.
- **Terminal:** `76 + 18(N−1) + 6`.

The model reproduces the base `NQ_MAX = 132` for N = 1 with 2 tables. Values with 3 tables:

| N | NQ_MAX |
|---|---|
| 2 | 191 |
| 3 | 213 |
| 4 | 236 |
| 5 | 258 |
| 6 | 281 |

Chunks of 1 event (65 states) give a smaller quotient (n_q 69–105). The extra states cost more than they save
(+0.1–0.6 KB of tx at N = 2..6), so chunks stay at 2.

## 4. Cost model

### 4.1 MEASURED inputs (the base verifier)

Source: `node profile.mjs` in `../bn-native-sound` (fixture 0, standard mode, BCHN accounting). Rerun for this note:
input 0 7,036,431, input 1 6,995,632, input 2 6,642,322, **total 20.674M**.

| phase | measured | unit |
|---|---|---|
| affine B doublings (`BDBL`) | 7.000M | 107.7k × 65 |
| affine B additions (`BADD`, incl. 2 terminal) | 2.275M | ≈ 99k × 23 |
| B-step witness reads (`RD`) | ≈ 0.15M | 1.73k per word × 88 |
| **variable-B walk, total** | **≈ 9.44M** (2,816 B of witnesses) | |
| δ steps (`DSTEP`) | 4.317M | 49.1k × 88 (5,632 B of baked slopes) |
| loop body (GT-GLS products, digit/flag dispatch) | 1.688M | ≈ 26k per event |
| GT-GLS tables (`TM`) | 0.582M | 2 per table per role |
| binding | 0.320M | 2 tables |
| boundaries (`BNDSTEP` + `EV` + state reads) | ≈ 1.24M | ≈ 37.7k per state × 33 |
| quotient | 0.753M | 6.6k per word × 114 |
| per-input setup | 1.41M | 0.47M × 3 (z powers, `S_c`, tables, env) |
| redeem and code loading | 0.33M | 0.109M × 3 |
| other per-input (layout, transcript, remote reads, statement, slices, post) | ≈ 0.9M | ≈ 0.3M × 3 |

Notes on the brief's survey numbers:
- B walk ~9.3M: confirmed (9.44M with witness reads).
- δ loop ~4.3M: confirmed.
- e(vk_x,γ) via GT-GLS ~1.3M: the measured split is different. GT-GLS-related work is ≈ 2.6M (loop body, tables,
  binding), but the loop body also carries digit dispatch.
- Fixed overhead ~5M: confirmed in total.

Bytes (fixture 0):

| item | bytes |
|---|---|
| code | 7,310 |
| states | 6,336 |
| δ slopes | 5,632 |
| quotient | 3,648 (n_q 114; ≤ 4,224) |
| B witnesses | 2,816 |
| STMT | 642 |
| HAND | 448 |
| DG | 96 |

Fillers are 96 / 41 / 67 B. **The base is both content-bound and op-bound.** The batch is op-bound: about half of its
unlocking is zero filler bought for op budget.

### 4.2 MODELLED inputs (new work)

**Calibration (MEASURED vs static).** The new G1 kernels are scheduled with `asm.mjs`'s own static op model, for the
EFD formulas `dbl-2009-l` and `madd-2007-bl` and a witnessed affine addition. The same model gives:
- `kADblN` 104.2k (measured `BDBL` 107.7k);
- `kDStep` 43.9k (measured `DSTEP` 49.1k).

So kernel estimates are scaled by **×1.1** for loop overhead.

| item | static | modelled (×1.1) | bytes |
|---|---|---|---|
| Jacobian doubling | 30.2k | 33.2k + 1k step overhead | |
| mixed addition | 44.6k | 49.1k | |
| witnessed affine addition | 16.4k + read | 19.9k | 32 B |

| per-proof and per-batch item | op | bytes | notes |
|---|---|---|---|
| `r_i·A_i`, ℓ = 128 | **6.15M** | 480 | 128 doublings, 30 mixed additions, 14-entry affine table, affine conversion |
| `r_i·A_i`, GLV-128 | 4.30M | | |
| `C*` per point | 1.78M (GLV 2.11M) | 448 | windows and table only |
| `C*` shared doublings | 4.40M (GLV 2.21M) | | 128 or 64 doublings, once |
| extra B walk per proof | **9.18M** | 2,816 | measured units, less the shared F± squaring (7.4k per doubling) and plus 3k per event of stack handling |
| third GT-GLS table | 0.81M once, + 157k per M role | 65 + per-table words | |
| per-proof misc | 65k | 320 + 64 | curve/twist checks, `r_i`, `s_k`, `PT` publish and compare |
| per-proof, per-role | 30k | | decode, env, handover words |
| quotient growth | 6.6k per word | 32 per word | `NQ_MAX(N)` (worst case) instead of fixture 0's 114 |
| per M input fixed | 0.88M + 0.157M + 30k·N | | |
| per S input fixed | 0.41M | | no Miller setup |

**Packing.**
- Each input may use at most 94% of `(41 + 10,000)·800 = 8,032,800`, i.e. 7.55M. This is the base's margin and cap
  rule.
- M inputs are counted from the Miller work. Their spare budget absorbs scalar-mult work first. S inputs take the
  rest.
- Unlocking is `op / (0.94·800) − 41·n_in`.
- tx bytes are unlocking `+ 43·n_in + 60` (outpoints, sequences, length prefixes, one output, header).

### 4.3 Results (`node cost-model.mjs`; N = 1 is MEASURED, every other row is MODELLED)

**Baseline: ℓ = 128, no GLV.**

| N | op | inputs (M + S) | unlocking | **tx bytes** | **per proof** | one 100 KB tx? |
|---|---|---|---|---|---|---|
| 1 (base) | 20.7M | 3 | 27,370 | 27,559 | 27,559 | yes |
| 2 | 47.2M | 7 (5 + 2) | 62,427 | 62,788 | 31,394 | yes |
| 3 | 66.2M | 9 (6 + 3) | 87,618 | **88,065** | **29,355** | **yes (largest)** |
| 4 | 86.4M | 12 (8 + 4) | 114,393 | 114,969 | 28,742 | no |
| 5 | 105.5M | 14 (9 + 5) | 139,784 | 140,446 | 28,089 | no |
| 6 | 126.0M | 17 (11 + 6) | 166,839 | 167,630 | 27,938 | no |

**Option: GLV-split `r_i`, ℓ = 128** (needs the injectivity fact of section 1.3).

| N | op | inputs | tx bytes | per proof | one tx? |
|---|---|---|---|---|---|
| 2 | 43.0M | 6 | 57,313 | 28,657 | yes |
| 3 | 60.9M | 9 | **81,118** | **27,039** | yes (largest) |
| 4 | 79.2M | 11 | 105,458 | 26,365 | no |
| 5 | 96.9M | 13 | 128,915 | 25,783 | no |
| 6 | 115.8M | 16 | 154,081 | 25,680 | no |

**Sensitivity: ℓ = 100** (owner decision, section 6).

| N | no GLV: tx bytes (per proof) | GLV: tx bytes (per proof) |
|---|---|---|
| 3 | 82,532 (27,511) | 76,949 (25,650) |
| 4 | 106,762 (26,691), no | 99,796 (24,949), **yes**, 10 inputs, no margin to spare |

**Comparator: N independent base verifiers co-located in one tx** (no shared math; glue change only).

| N | tx bytes | per proof | one tx? |
|---|---|---|---|
| 1 | 27,559 | 27,559 | yes |
| 2 | 55,058 | 27,529 | yes |
| 3 | 82,557 | 27,519 | yes |
| 4 | 110,056 | 27,514 | no |

**Reading the tables.**
- The marginal cost of the 6th proof is about 27.2 KB (baseline) and 25.2 KB (GLV), against 27.56 KB for an
  unbatched proof.
- The fixed batch overhead takes many proofs to amortize: the shared `C*` doublings, the third table in every M role,
  the quotient growth and the r-transcript. The one-tx cap stops at N = 3.
- **The largest N in one standard tx is 3 for every variant priced, except GLV with ℓ = 100, which reaches N = 4 at
  99.8 KB with no slack.**
- Uncalibrated kernels (`KMUL=1.0`) move the baseline N = 3 row to 85.7 KB (28.6 KB per proof). That does not change
  the conclusion.

**What would change the conclusion.** The two G1 scalar multiplications per proof (≈ 7.9M) cost about as much as the
shared work they let us skip (≈ 11.2M minus the new per-input overheads). Batching starts to pay only if one of these
changes:
- the scalar mults get much cheaper, under about 3M per proof in total (for example under a VM change that prices
  wide multiplication more cheaply);
- the per-input overhead falls (for example by handing over the z powers instead of recomputing them: this helps the
  base equally);
- the per-tx cap rises.

## 5. Implementation plan (if the review chooses to build)

### 5.1 Reused unchanged

- **Assembler:** `asm.mjs` (the symbolic assembler and kernel scheduler).
- **Kernels:**
  - `kDStep`, `kEval` and `kTable` (verbatim; `kTable` now runs for 3 tables);
  - `kADblN` and `kAAddN` for the first proof's B steps. The other proofs use the same kernels with a one-flag variant
    of `affineTail` that skips the F± squaring, because the squaring is shared.
- **Script functions** (`script.mjs`):
  - `P`, `RD`, `FILL`, `PLEN`, `G1C`, `TRANS`;
  - `DSTEP`, `BNDSTEP`, `EV` and `TM`;
  - `HENC` and `HDEC`, generalized from a 7-word to a (4N + 3)-word handover;
  - the redeem `R`, with two code pieces;
  - the code-as-witness pattern, dispatch by function id, the layout pins and the remote-read header checks.
- **Math:**
  - `../sound-si-gls/math.mjs` (all constants, `glsDecompose`, `psiK`, `linePoly`, the degree rules);
  - `protocol.mjs`'s affine prover helpers (`affDbl`, `affAdd`) and the value-level mirror pattern;
  - `transaction.mjs`'s filler sizing and `vm.mjs`'s runners (generalized to n inputs).

New constants go in a new module, `batch/math.mjs`, that imports the reviewed one and changes nothing in it:
- the k = 0 GT-GLS factors `R_{0,i}` from `mConst`;
- `corr'` and `Rconst'`;
- `λ_φ` and `β_3`, with the GLV injectivity assertion if that option is chosen.

### 5.2 New

1. **r-transcript.** `h_r`, `r_i` (i ≥ 2), `r_i ≠ 0`. It runs in every S role and in M_last.
2. **Fr arithmetic.** `s_0, s_1, s_2` in M_last, and the third GLS accumulator in the binding.
3. **G1 scalar multiplication:**
   - `jdbl`, `jmadd`, and a witnessed affine add for the table (the Fp analogue of `kAAddN`);
   - the window loop with nibble extraction from `r_i`;
   - the affine conversion `t·Z ≡ 1`, then `G1C`;
   - the Straus MSM for `C*` with a canonical Jacobian handover between S roles;
   - `PT` publishing and byte equality.
4. **N-wide Miller loop.** Per event, N B steps reading N inverse norms, with per-proof env (`yP_i`, `x_{P_i}z`,
   `x_{P_i}z(z⁶−9)`, and `Q = d_e·B_i` for additions). Stack depth grows by about 4N + 6 items. The scheduler's
   window-matched bound functions must be re-checked for every N.
5. **N-wide terminal.** N × (two terminal additions + endpoint), then the shared δ Frobenius lines, `Rconst'` and W.
6. **The batch prover** (`batch/protocol.mjs`):
   - r, `P_i`, `C*`, and GLS decompositions of `s_k`;
   - the combined factor schedule and the 33 states;
   - the per-identity exact divisibility asserts (as `proveCore`);
   - the quotient;
   - streams, `DG`, the handovers.

   It also includes a noble cross-check that the batched equation holds with the same `r_i`, and that `FE(f_batch) = 1`.
7. **Layout and graph.**
   - The `n_in(N)` roles, the role table and cuts. Cuts for M roles are at chunk boundaries; S roles are cut at
     window boundaries.
   - The `WQ` cap `32·NQ_MAX(N)`.
   - A `GRAPH` input count of `n_in(N)`.

   N is baked: one code per N.

### 5.3 Test plan (plain acceptance and rejection; no forgery search)

Every rejection run recomputes `DG`, the challenges and the handovers, so that the named guard rejects, not a hash
check. That is the base red-team method, and the report names the guard that fires.

**Acceptance and liveness**
- Accept N valid proofs (N = 2, 3) on fixtures, on freshly minted proofs, and on re-randomized proofs.
- A worst-case op vector: every GLS nibble 15, every window nonzero, n_q at `NQ_MAX(N)`. It must meet the cap rule
  (≤ 0.94 × 8,032,800 per input) in consensus and standard mode, under BCHN accounting.
- A sweep of ≥ 400 random batches.
- The value-level mirror: the role-split run equals one uninterrupted run, and the noble batched pairing check agrees.

**Rejection, batch-specific**
- **One bad proof among N, at every index** i = 1..N (i = 1 has `r_1 = 1`). The bad proof is a valid proof with a
  mutated public input. Expected: the final identity or the GLS binding rejects.
- **Swapped public inputs** between proofs i and j, with everything downstream recomputed. Expected: rejected.
- **Duplicated proof:**
  - a valid `(proof, inputs)` in two slots: the core accepts, and this is documented as a positive control; with the
    pairwise-distinct hook it is rejected by the hook;
  - an invalid proof in two slots: rejected.
- **Wrong N:** a tx carrying N−1 or N+1 proofs. Expected: rejected by the `STMT*` size pin, the layout pins and
  `GRAPH`.
- **`r_i` not matching the transcript:**
  - `PT` holding `r'_i·A_i` for `r'_i = r_i + 1`, or `r` from another batch's transcript;
  - `C*` built with a wrong `r_i`;
  - `s_k` nibbles for a wrong `r`.

  Expected: S-role byte equality on `PT`, or the binding, rejects.
- **`PT` tampering:** `P_i ± G`, `P_i` and `P_j` swapped, the `+p` alias, an off-curve `PT` point. Expected: S-role
  equality or `G1C` rejects.
- **Per-proof subgroup and curve checks, for each i separately:**
  - `A_i` off curve;
  - `C_i` off curve;
  - `B_i` off twist;
  - `B_i` on the twist but outside G2, with its inverse norms recomputed (the `T_i == −ψ³(B_i)` guard must fire);
  - identity and negated encodings;
  - `+p` aliases of every coordinate;
  - `n_{k,i} ≥ r` and `n + r` aliases.
- **G1 table and accumulator:** a wrong table witness `t`, `t + p`, `t = 0`, and a tampered S-role Jacobian handover.

**Rejection, inherited and generalized from the base suite**
- Inverse norms for every proof's steps.
- States and their aliases, quotient words and length.
- Handover words for every `T_i`.
- Whole-input staples from another valid batch.
- Every layout run (extra, missing or swapped pushes; non-minimal pushes; filler content; code and δ-slice bytes).
- Graph runs (count, a foreign locking at each index).
- Nibble range and alias runs for all three tables.

## 6. Open questions and risks

**Top risks**

1. **No byte gain (economic risk; it decides whether to build).** The baseline costs more per proof than the unbatched
   verifier at every N ≤ 6. GLV-128 saves 2% at N = 3, the largest N in one tx. Larger gains need N ≥ 4, i.e. two
   transactions, and the base pattern has no reviewed cross-tx commitment (Track 10's per-tx cap layer is measured,
   not reviewed). Model error is about ±5%: the ×1.1 calibration, the 3k-per-event stack handling and the per-role
   costs are estimates. That does not flip the sign at N = 3.
2. **New soundness-relevant code across about 9 inputs.**
   - G1 scalar multiplication with Jacobian exceptional cases (the "Z = 0 absorbing" argument and a start point that
     is not O);
   - the second challenge stage `h_r` (it must cover all of `STMT*`, N and the VK, and nothing derived from `r` may
     enter it);
   - `PT` ownership;
   - a third GT-GLS table with a new `corr'`/`Rconst'`. This repeats the base's open "GT-GLS constants not recomputed
     from noble by the reviewer" risk, for one more table.
   - (4N + 3)-word handovers over ~5 seams, and the scheduler's stack-window matching at depth growing with N.

   Each needs a written owner argument. The table in section 3 is the draft.
3. **Per-proof membership checks are load-bearing.** Small-exponent batching is unsound without them (Boyd–Pavlovski).
   The G2 check is the `B_i` endpoint, and it must run for every proof. A refactor that shares or skips one proof's
   terminal breaks the batch, not just that proof. The red team must cover the "outside G2" run at every index i.

**Open questions for the owner**

- **Security parameter ℓ.**
  - 128, the default: the batch term `q_H·2^−128` dominates the base's `2^−245`.
  - 100: matches BN254's ~100-bit estimate and saves 5–6%.
  - GLV halves the doublings, but needs the injectivity assertion.
- **Duplicates.** Should the core reject identical statements in two slots, or only the application hook? Proposed:
  the hook, with a pairwise-distinct rule in the Track-12-style template.
- **Binding mode.** Caller-supplied (the core) or the per-proof Track 12 pattern. Which output grouping per proof?
  Replay and one-funding limits are inherited from Track 12.
- **Fixed N per covenant.** One code per N. A variable N would need padding with dummy proofs, which cost a full B walk
  each, or several codes.
- **Fillers.** About half of the batched tx is zero filler (op-bound). The base's owner decision on prover-sized
  fillers (txid malleability of the free filler lengths) applies to every input.
- **Comparator first?** Should co-located independent verifiers (27.5 KB per proof, N ≤ 3 per tx, no new math) be
  reviewed and built instead?
- **Accounting.** The numbers use BCHN `OP_DEFINE` accounting (body bytes charged, `build.json`). The batch code
  (≈ 10 KB modelled) is defined in every input. This adds ≈ 3k op per input against the base (included in the
  per-role term).

## Reproduce

```sh
cd chunked/bn254/bn-native-sound && node profile.mjs      # MEASURED per-phase costs (section 4.1)
cd ../batch && node cost-model.mjs                         # MODELLED tables (section 4.3); KMUL=1.0 for raw kernel estimates
```

`cost-model.mjs` imports the reviewed `asm.mjs`, `kernels.mjs` and `math.mjs` read-only. It contains no verifier code.

## Addendum (2026-11-04): independent cost check

An independent reviewer reran `profile.mjs`. Its measured per-phase costs match the ones this note uses, and so does the op-cost to bytes conversion. The note's pricing of the G1 scalar multiplications (Jacobian dbl/madd) is not the cheapest one available. A witnessed affine G1 kernel uses the exact `t·2y ≡ 1` / `t·Δx ≡ 1` checks, the same argument as the B walk, and statically estimates at about 23.0k per doubling and 16.4k per addition, against 34.2k and 49.1k for Jacobian. These are static estimates with the ×1.1 factor, not measured. Model: `cost-model-affine.mjs`.

| variant | N = 3 (tx / per proof) | N = 4 |
|---|---|---|
| Jacobian-128 (this note) | 88.1 KB / 29.4 KB (−7%) | does not fit |
| Jacobian-128 + GLV | 81.1 KB / 27.0 KB (+2%) | does not fit |
| affine-128 | 79.8 KB / 26.6 KB (+3%) | 103.4 KB, does not fit |
| affine-128 + GLV | 74.4 KB / 24.8 KB (+10%) | 95.9 KB / 24.0 KB (+13%), fits |
| affine-100 + GLV | 72.1 KB / 24.0 KB (+13%) | 92.7 KB / 23.2 KB (+16%) |

Savings are relative to the unbatched 27,559 B tx. Saving 20% or more per proof needs 100-bit coefficients, GLV, the affine kernel and N ≥ 7, which comes to about 153 KB: several transactions, or a raised tx limit plus a cross-tx design.

**Decision (2026-11-04):** not built for now. The best one-transaction variant saves about 13% per proof, at N = 4 with about 2 KB of slack. It would add soundness-critical code to about 12 inputs: G1 scalar multiplication, GLV injectivity, a second challenge stage, and a third GT-GLS table. That is a poor trade against the review burden. Reopen if a user needs many same-key proofs per transaction, or if the standard tx size is raised.
