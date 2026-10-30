# Soundness of the Track 6 / Track 7 verifier-side changes

Status: **a written argument, not independently reviewed, not machine-checked.** It covers the places where this
verifier departs from gnark v0.16.4's `plonk.Verify`:
1. the t'-fold of the witnessed linearised commitment Λ';
2. the batching scalar u = u1 + λ·u2;
3. the today's-rules chain (`multi.mjs`), Lemma 3, rewritten for Track 7's hand-overs;
4. **Track 7:** the GT fold of the fixed MSM bases (`gt.mjs`), Lemma 4, with the A6 changes it needs.

**Track 7 changes in one place** (2026-10-30, branch `wip/plonk-usable-msm`):
- The fixed bases B_i ∈ {Ql, Qr, Qm, Qo, Qk, S3, S1, S2, [1]_1} (8 for mul2, 9 for merkle16) leave the G1 MSM. The MSM
  computes P*_var over the 10 variable bases only. Their scalars s_i are applied in GT, inside the SI pairing check
  (Lemma 4).
- The SI identities gain per-event monic factors and one terminal factor. The degree cap grows from 60 to 348 / 384
  quotient words (A6). The GT nibbles NB are part of WS, so h0 hashes them, and every nibble byte must be < 16.
- Chain: ST also computes h0, ρ, z, the quotient Horner value QZ and (mul2) the GT binding, and publishes ρ, z and QZ
  (and, for merkle16, the s_i) in G0.
  - WQ = WQa ‖ WQb is split over two inputs; WQb is a variable-size push.
  - One SI role publishes GZ (the 8m values R_{i,j}(±z)), checked against its own computation.
  - The code is three hash-checked blobs.
  - The fixed-base table TF is gone.
  - Lemma 3 is rewritten below.
- The FOLD=0 build (`parseVK(hex, {fold: false})`) is the Track 6 design. For it, the Track 6 text of Lemma 3 (kept
  below the Track 7 version) applies unchanged, apart from the LOADT decoding note in the Track 7 step 6.

Everything else reduces to gnark PLONK soundness. The numbers below are checked by
[`soundness/lattice.mjs`](soundness/lattice.mjs) (`node soundness/lattice.mjs`).

File references are to this directory: `plonk.mjs` (value-level verifier), `script.mjs` (single-input build), `multi.mjs`
(chain), `si.mjs`. gnark refers to `backend/plonk/bn254/verify.go` (v0.16.4) and gnark-crypto `ecc/bn254/kzg/kzg.go`
(FoldProof, deriveGamma, BatchVerifyMultiPoints).

## 0. Setting and notation

- G1 = E(Fp), y² = x³ + 3, has prime order r and cofactor 1. An affine point that passes the curve check is in G1.
  For P ∈ G1, w(P) ∈ Z_r is its discrete log to base [1]_1.
- The pairing is e = FE ∘ Miller (optimal ate). It is bilinear and non-degenerate. The SRS gives [1]_1, [1]_2 and
  [τ]_2 = τ·[1]_2. τ exists as a fixed constant; nobody needs to know it for the argument.
- φ(x, y) = (β·x, y) is the G1 endomorphism with φ = [λ], λ² + λ + 1 ≡ 0 (mod r). The pair (β, λ) is the one in
  `math.mjs:138-146` (re-checked by the script).
- **Scope.** The VK has no BSB22 commitments (`Qcp` empty, no `api.Commit`), and k ≥ 1 public inputs is the tested
  case. The references are gnark v0.16.4 and gnark-crypto v0.21.1-0.20260913224755-1409fe592052.
- H = SHA-256. Q is the total number of H evaluations, including those made while checking the adversary's output.
- `LE(b)` / `BE(b)` is the unsigned integer of the bytes b, read little- / big-endian. In script, the LE path is
  `SPLIT`, then `CAT 0x00`, then `BIN2NUM`, which gives exactly the unsigned value. The BE path (`DBP`/`DBR`, `BMR`)
  first applies `REVERSEBYTES`, then does the same (`script.mjs:83, :89`; `multi.mjs:77, :82`).

**Hash inputs, exactly as implemented.** "PROOF" is the 768-byte proof, in the FORMAT.md layout. "X[0..64)" is Λ' as
gnark raw bytes (BE x ‖ BE y).

| query | input bytes (length) | value used | single input | chain (ST / SI) | reference |
|---|---|---|---|---|---|
| q_γ | `"gamma"` ‖ VK S1..Qk (512) ‖ PI ‖ PROOF[0,192) (709 + 32k) | γ = BE mod r | script.mjs:132 | multi.mjs:320 | plonk.mjs:64 |
| q_β | `"beta"` ‖ γRaw (36) | β | :133 | :321 | :65 |
| q_α | `"alpha"` ‖ βRaw ‖ PROOF[544,608) (101) | α | :134 | :322 | :65 |
| q_ζ | `"zeta"` ‖ αRaw ‖ PROOF[192,384) (228) | ζ | :135 | :323 | :65 |
| q_v | `"gamma"` ‖ BE32(ζ) ‖ X[0,64) ‖ PROOF[0,192) ‖ VK S1 ‖ S2 ‖ BE32(r0) ‖ PROOF[384,544) ‖ PROOF[608,640) (645) | v = BE mod r | :171-176 | :346-351 | :94 |
| q_u | `"u"` ‖ vRaw ‖ PROOF[640,768) = Wζ ‖ Wζω (161) | u1 = LE uRaw[0,8), u2 = LE uRaw[8,16), t' = LE uRaw[16,32) | :177-180 | :352-355 | :98-99 |
| q_h0 | TAG `"PLONKKZG-SI/1"` ‖ uRaw ‖ WS (13 + 32 + 6,528) | h0 | :291 | :395 (uRaw from G0[0,32), :392) | si.mjs:64 |
| q_ρ | h0 ‖ `"rho"` (35) | ρ = LE mod p | :292, :301 | :396, :401 | |
| q_z | h0 ‖ ρRaw ‖ WQ (64 + 32·n_q) | z = LE mod p, z ≠ 0 | :297, :300 | :397, :400 | |

q_v is gnark-crypto `deriveGamma`: the transcript named "gamma", binding ζ, the digests [Λ', L, R, O, S1, S2], the claimed
values [r0, l, r, o, s1, s2] and `zu.Marshal()`. With Λ' = Λ, this is byte-for-byte gnark's v (`verify.go` FoldProof call).
Every query type has a distinct length (709 + 32k ≥ 741 for k ≥ 1; 32·n_q + 64 ≡ 0 mod 32 matches none of the others).
So the type of a query, and the positions of the earlier digests inside it, follow from its length.

**The MSM scalars** (`plonk.mjs:102-104`, `script.mjs:186-192`, `multi.mjs:359-365`) give, with X_1..X_5 = L, R, O, S1,
S2, z̄ = z(ζω) and Λ = gnark's linearised commitment (PROTOCOL.md step 4, `plonk.mjs:85-87`):

  P* = Σ_q S_q·B_q = F + (1 + t')·(Λ' − Λ),
  F  = D − e·[1]_1 + ζ·Wζ + u·(Z − z̄·[1]_1 + ζω·Wζω),   D = Λ + Σ_{i=1..5} vⁱ·X_i,
  P_R = −(Wζ + u1·Wζω + u2·φ(Wζω)) = −(Wζ + u·Wζω).

Here F is gnark's folded KZG point, computed with the true Λ but with v taken from q_v, which hashed Λ'. The final
check is e(P*, [1]_2)·e(P_R, [τ]_2) = 1. Taking discrete logs, it is equivalent to

  (E)  A0 + u·A1 + (1 + t')·δ ≡ 0 (mod r),

where
- A0 = w(D) − e − (τ − ζ)·w(Wζ);
- A1 = w(Z) − z̄ − (τ − ζω)·w(Wζω);
- δ = w(Λ') − w(Λ).

A0 = 0 is the KZG opening check of D at ζ with value e and proof Wζ. A1 = 0 is the opening check of Z at ζω with value
z̄ and proof Wζω.

**gnark-valid.** (vk, x, π̃) is gnark-valid if gnark's `Verify` accepts it for every value of the random batching scalar
in `BatchVerifyMultiPoints`. Here π̃ is π with `ClaimedValues[0] := r0`. Equivalently, the decode checks pass,
`constLin == ClaimedValues[0]` holds (true by construction), and A0 = A1 = 0 with D built from gnark's own v.

## 1. Assumptions

- **A1 (ROM).** SHA-256 is a random oracle. This also covers HASH256 in P2SH32.
- **A2 (PLONK).** ε_PLONK(Q) is the probability that a Q-query adversary outputs (x, π̃), gnark-valid, with x ∉ L_vk.
  - This is an **assumption about gnark's Fiat–Shamir instantiation**, not a consequence proved here. That
    instantiation has three parts:
    - the transcript γ, β, α, ζ;
    - the verifier-recomputed opening r0 of the linearised polynomial, in place of a proof value;
    - v from gnark-crypto `kzg.deriveGamma`, which binds ζ, the six digests and the six claimed values (plus z̄).
  - It differs in these details from the protocol analysed by Gabizon–Williamson–Ciobotaru, "PLONK" (IACR ePrint
    2019/953, latest version). That paper proves soundness in the AGM under q-DLOG, with Fiat–Shamir in the ROM. It
    is supporting evidence for A2, not a proof of it.
  - A gnark-valid proof passes the batched check for every batching scalar. So A2 concerns exactly the proofs that
    satisfy both KZG equations.
  - For knowledge soundness, read "x ∉ L_vk" as "the AGM extractor fails".
  - Its non-computational terms are Q·O(n)/r. For n ≤ 2^28 that is roughly Q·2^-220. This order of magnitude is not
    re-derived here.
- **A3 (SRS).** [τ]_2 = τ·[1]_2 for a τ unknown to the adversary, i.e. an honest ceremony. The vectors now use Aztec Ignition
  (176 contributions plus a seal; one honest contributor suffices). The first vectors used a test SRS with public τ,
  which violated this on purpose. The load checks are in the prover's FORMAT.md "SRS".
- **A4 (implementation).** The arithmetic kernels compute the field formulas written in `script.mjs` / `multi.mjs`.
  The baked constants (VK points, TF blob, both G2 line chains, the SI schedule) equal their definitions; the build
  asserts them against noble. This is tested, not proved (README "Not verified"). Given A4, the curve operations are
  exact:
  - an affine add requires x2 ≠ x1 and λ(x2 − x1) = y2 − y1 (`script.mjs:95`);
  - an affine doubling requires 2yλ = 3x², with y ≠ 0 on G1 (`:96`);
  - Jacobian exceptional steps end at Z = 0, which is absorbing, and every conversion checks Z·zi = 1 (`:99`);
  - the TV entries satisfy exact chord/tangent equations with Δx ≠ 0 (`multi.mjs:96-103`);
  - the digit offsets keep s' < 2^255 = 32^51 and u_i' < 2^70 (script);
  - so an accepted MSM equals Σ S_q·B_q exactly. P* and P_R are finite, affine G1 points.
- **A5 (CashVM).** These rules are enforced by consensus, and an accepted transaction satisfies them:
  - every unlocking bytecode is well-formed and push-only (libauth `bch-2023-instruction-set.js:51-56`; BCH 2018-11);
  - every push uses its minimal encoding (`common/push.js:97-104`, both modes; BCH 2019-11 MINIMALDATA);
  - P2SH32 runs the last push as the redeem on the remaining stack;
  - `OP_INPUTBYTECODE(i)` returns input i's unlocking bytecode.
  - libauth 3.1.0-next.8 was checked. A BCHN node was not run.
- **A6 (SI, cited).** This is the SI-GLS argument (`chunked/bn254/sound-si-gls/README.md`, "Soundness argument")
  instantiated with two fixed G2 chains (both "δ-chains"). The cited argument needs four conditions; this fork meets
  them as follows.
  - **P* and P_R are affine G1 points with y ≠ 0.** They are finite and affine by A4 (every MSM ends in an affine add or
    a checked conversion). y ≠ 0 because G1 has odd order, so it has no 2-torsion.
  - **Every line factor is a nonzero polynomial.** Both chains are baked δ-chains. Their lines are
    `linePoly(x_P, y_P, 1, −λ_j, c_j)` (`si.mjs:29`, `math.mjs:134-135`), i.e. y_P·Φ(1) + x_P·X·Φ(−λ_j) + X³·Φ(c_j).
    The y_P coefficient is 1; SI-GLS's README calls it ℓ0. Its degree-0 coefficient is y_P ≠ 0.
  - **The terminal W is nonzero.** W = Fr1(X)·Fr1(ηX), with Fr1 = `frob1Monic(S_c)`, whose X⁶ coefficient is −1
    (`math.mjs:92`, `si.mjs:57`). A product of nonzero polynomials is nonzero. The states are monic of degree 6.
  - **The degree and the quotient cap** come from this build's schedule (`si.mjs:18-21`), as listed below. The cap is
    enforced: exactly 60 words in the chain (size pinned in `multi.mjs:229`), 1–60 words in the single-input build
    (`script.mjs:293-296`). Every word is < p.

  - **Track 7 (fold, default):**
    - P* above is P*_var, the variable-base MSM; it is finite and affine by the same argument.
    - Each event's factor list gains G_e = Π_i Π_{j ∈ N_i[e]} R_{i,j}(X). R_{i,0}, R_{i,1} are baked monic degree-6
      polynomials, and R_{i,2/3}(X) = R_{i,0/1}(ηX) are monic too, since η⁶ = 1. The terminal gains the monic Rconst(X).
      All of these are nonzero.
    - The schedule degree (`si.mjs` `chunkDegP(k, m)`, `nqMax(m)`, with up to 4 factors of degree 6 per base and event)
      gives max deg D_k = 708 / 780 and NQ = 348 / 384 for m = 8 / 9.
    - The cap is enforced:
      - single input: 1–NQ words with a nonzero leading word (`script.mjs` si);
      - chain: ST checks 256 ≤ |WQb| ≤ 32·NQ − 4096 and |WQb| ≡ 0 (mod 128), so |WQa ‖ WQb| ≤ 32·NQ (`stTranscript`).
    - The error term becomes 1.134·(33 + 780)/p ≈ 2^-243.75 for m = 9 (2^-243.88 for m = 8; `soundness/lattice.mjs`).
    - The nibbles are in WS, hence in q_h0's input, so every factor is fixed before ρ and z.
    - Every nibble byte is checked to be in [0, 15] before it selects a factor: `gtNibCheck`, on the whole NB; in the
      chain this is the binder's read of ST's WS, and every SI role's lookups use the same bytes (Lemma 3 step 3). So
      the table entry picked is exactly TP_i[n] = Π_{j∈n} R_{i,j}(z) (resp. TM_i[n] at −z). This check was missing in
      the first Track 7 build and was found while writing this section (§7).

  Fix the input of q_h0. This fixes P*, P_R, S_c and
  S_1..S_33. If FE(Miller(P*, [1]_2)·Miller(P_R, [τ]_2)) ≠ 1, the SI checks pass with probability at most
  1.134·(33 + 132)/p ≈ 2^-246.05 over (ρ, z), for any WQ of at most 60 words:
  - 34 identities;
  - max deg D_k = 132 (`si.mjs:18-21`);
  - deg Q·M ≤ 2·60 − 1 + 12 = 131;
  - 1.134 is the SHA-256 → Fp bias.

## 2. Lemma 0: transcript extraction (ROM bookkeeping)

Let Bad be the union of three events:
- **B1:** two distinct queries have outputs that are congruent mod r. Equal outputs are a special case.
- **B2:** a query's output, or its residue mod r, equals a digest field of an earlier query. The fields are γRaw, βRaw,
  αRaw, BE32(ζ), vRaw, uRaw, h0 and ρRaw, at most 2 per query and located by its length.
- **B3:** some query hits one of 7 fixed targets on an input other than the intended one. These are second preimages:
  - for the P2SH32 hash, two targets: a query on an input ≠ R that returns SHA256(R) (the inner hash), and a query on
    an input ≠ SHA256(R) that returns HASH256(R) (the outer hash);
  - the SHA-256 constants of C0, C1 and TF, and of the two DS slices.
  
  Bounding by 8 targets leaves slack.

Each residue mod r has probability at most ⌈2^256/r⌉/2^256 = 6/2^256. Hence:
- Pr[B1] ≤ 3Q²·2^-256;
- Pr[B2] ≤ 12Q²·2^-256;
- Pr[B3] ≤ 8Q·2^-256;
- Pr[Bad] ≤ 15Q²·2^-256 + 8Q·2^-256 ≈ Q²·2^-252.09.

**Lemma 0.** Assume ¬Bad and let the verifier accept. Then the queries q_γ, q_β, q_α, q_ζ, q_v, q_u, q_h0, q_ρ, q_z of
this verification were made in that order. Each is the unique query with its output (mod r for ζ). The input of q_u
therefore determines x, PROOF and Λ' before uRaw is drawn: q_γ gives PI and L, R, O; q_α gives Z; q_ζ gives H0..H2;
q_v gives Λ', the five evaluations and z̄; q_u gives Wζ and Wζω. Likewise the input of q_h0 determines everything in
q_u, plus uRaw and WS, before h0 is drawn.

*Proof.* Each field is matched to the unique earlier query with that output (¬B1). That query is earlier by ¬B2. The
ζ field holds a residue, and ¬B1 is stated mod r for that reason. ∎

So (A0, A1, δ) is a function of the q_u input. P*, P_R and the SI identities D_k are a function of the q_h0 input.

## 3. Lemma 1: the t'-fold

**Lemma 1.** Fix a q_u input with δ ≠ 0, and fix any value of uRaw[0,16), so u is fixed. Over the uniform
uRaw[16,32), (E) holds with probability at most 2^-128.

*Proof.*
- t' = LE(uRaw[16,32)) is uniform on [0, 2^128) and independent of uRaw[0,16), because the byte ranges are disjoint
  (`script.mjs:178-180`).
- With δ ≠ 0, (E) says 1 + t' ≡ −(A0 + u·A1)·δ⁻¹ (mod r), which is one residue class.
- 1 + t' ranges over [1, 2^128], and 2^128 < r ≈ 2^253.6, so these values are pairwise distinct mod r.
- So at most one t' satisfies (E). ∎

This holds whatever Λ' the adversary picked, including Λ' = −Λ, 2Λ, Λ + G (tested adaptively in `test.mjs`). Λ' is
fixed in q_v, before uRaw (Lemma 0). If Λ = O, then no Λ' equals Λ (Λ' passes the curve check, so it is not (0,0)).
An honest proof with Λ = O is therefore always rejected: A0 + u·A1 = 0 while (1 + t')·δ ≠ 0. This happens with
negligible probability and affects completeness only.

## 4. Lemma 2: batching with u = u1 + λ·u2

**Lemma 2a (injectivity).** The map [0, 2^64)² → Z_r, (u1, u2) ↦ u1 + λ·u2 mod r, is injective.

*Proof.*
- Suppose two pairs collide. Their difference (a, b) is nonzero, has |a|, |b| ≤ 2^64 − 1, and lies in
  L = {(a, b) ∈ Z² : a + λb ≡ 0 (mod r)}.
- L has basis (r, 0), (−λ, 1) and determinant r. Lagrange–Gauss reduction (script) gives the reduced basis
  - v1 = (147946756881789319000765030803803410728, −9931322734385697763),
  - v2 = (9931322734385697763, 147946756881789319010696353538189108491),
  with 127/64-bit components and ‖v1‖ ≈ ‖v2‖ ≈ √r ≈ 2^126.80. The norms are not exactly equal.
  - The basis is nearly orthogonal: cos ∠(v1, v2) ≈ −4.5·10^-39.
  - For comparison, the general bounds on λ1 are Hermite √(2r/√3) = 2^126.90 and Minkowski √(4r/π) = 2^126.97.
- v1 of a Lagrange-reduced basis is a shortest nonzero vector, so λ1(L) ≈ 2^126.80.
- But ‖(a, b)‖ < √2·2^64 = 2^64.5 < λ1(L). Contradiction. ∎

So u takes 2^128 distinct, equally likely values.

**Lemma 2b (batching error).** Fix a q_u input with δ = 0 and (A0, A1) ≠ (0, 0). Over uniform uRaw, (E) holds with
probability at most 2^-128.

*Proof.*
- (E) becomes A0 + u·A1 ≡ 0, which has degree 1 in u.
- If A1 = 0, then A0 ≠ 0 and (E) never holds.
- Otherwise exactly one residue u* = −A0/A1 satisfies (E). This is Schwartz–Zippel for a degree-1 polynomial.
- By Lemma 2a, at most one of the 2^128 equally likely pairs (u1, u2) maps to u*. ∎

**Corollary (KZG step).** Assume ¬Bad. For each q_u, the probability that (E) holds although
¬(δ = 0 ∧ A0 = 0 ∧ A1 = 0) is at most 2^-128 (Lemma 1 if δ ≠ 0, Lemma 2b otherwise). Over all queries this is at most
Q·2^-128.

**Composition with gnark.** In the remaining case:
- Λ' = Λ as points. Both are canonically encoded (coordinates < p), so the bytes hashed into q_v are gnark's
  `Marshal(Λ)`, and v is gnark's v.
- A0 = A1 = 0 means both KZG opening equations hold separately. So gnark's `BatchVerifyMultiPoints` accepts for every
  value of its random scalar.
- gnark's other checks also hold:
  - subgroup: on-curve with cofactor 1, and the identity is rejected here, which is stricter;
  - `constLin == ClaimedValues[0]`: ClaimedValues[0] := r0;
  - the public-input Lagrange terms: the batch inverse is checked (`script.mjs:149,165`).
- So (x, π̃) is gnark-valid.

Our batching therefore replaces gnark's batching error (1/r for a uniform scalar) by 2^-128 per hash query. KZG's own
binding is used only inside A2.

## 4b. Lemma 4 (Track 7): the GT fold of the fixed bases

Notation:
- The folded bases are B_1..B_m. e_i = e(B_i, [1]_2) ∈ μ_r, and m_i = Miller(B_i, [1]_2), so FE(m_i) = e_i
  (asserted for every base in `gtConsts`).
- π_j = p^j mod r, for j = 0..3.
- s_i ∈ [0, r) is the plan-B MSM scalar of B_i (§0). It is computed on chain exactly as the unfolded build computes it,
  in `fr2` (single) or ST's scalar kernel (chain).

The verifier, after A6, has established [f'] = [c]^λ in G = Fp12*/Fp6*, where

  f' = Miller(P*_var, [1]_2) · Miller(P_R, [τ]_2) · Rconst · Π_{e=0..64} Π_i Π_{j ∈ N_i[e]} R_{i,j}^{2^{64−e}}.

The factor of event e is raised to 2^{64−e} because each of the remaining 64 − e events squares F once, and the
terminal factors are not squared. It has also checked the binding

  (B)  acc_i − 2^64·Σ_j π_j − s_i ≡ 0 (mod r),   with acc_i = Σ_e 2^{64−e}·TB[N_i[e]] = Σ_j u_{i,j} π_j,

where u_{i,j} = Σ_e bit_j(N_i[e])·2^{64−e} ∈ [0, 2^65) and TB[n] = Σ_{j∈n} π_j. acc_i is computed by `gtBindLoop`, or
in the single-input loop by `gtStep`, from the same range-checked nibble bytes that select the factors.

**Lemma 4.** Then e(P*_var + Σ_i s_i·B_i, [1]_2) · e(P_R, [τ]_2) = 1. This is (E) for P* = P*_var + Σ_i s_i B_i, which
is the unfolded build's P* (same scalars, same bases).

*Proof.*
- [f'] = [c]^λ gives FE(f') = 1 (A6, residue step).
- FE kills Fp6*, so only classes matter.
- By construction (asserted against noble in `gtConsts`):
  - [R_{i,0}] = [m_i] and [R_{i,1}] = [Frob(m_i)];
  - [R_{i,2}] = [Frob²(m_i)] and [R_{i,3}] = [Frob³(m_i)], because Frob² acts on these polynomials as X ↦ ηX;
  - [Rconst] = [Π_{i,j} Frob^j(m_i)^{−2^64}].
- Frob^j is a field automorphism that commutes with FE, and FE(m_i) ∈ μ_r. So FE(Frob^j(m_i)) = e_i^{p^j} = e_i^{π_j}.
- Hence FE(f') = e(P*_var,[1]_2) · e(P_R,[τ]_2) · Π_i e_i^{n_i}, with n_i = Σ_j u_{i,j} π_j − 2^64·Σ_j π_j.
- By (B), n_i ≡ s_i (mod r), so e_i^{n_i} = e(s_i·B_i, [1]_2). Bilinearity gives the claim. ∎

Remarks.
- (B) is exact mod r, so any nibble string whose u's satisfy it works: the decomposition is malleable (lattice
  shifts within range), with no soundness effect. glsDecompose's Babai rounding is only how the honest prover finds
  one: |e| < 2^64, so u fits 65 bits (`soundness/lattice.mjs` §6; the column-sum bound is asserted in `gt.mjs`).
- Without the nibble range check, a byte ≥ 16 (or ≥ 0x80, negative after BIN2NUM) would make the factor and TB
  lookups read other stack items. The factor applied and the term added to acc_i would then not correspond to the
  same bits, and (B) would no longer pin n_i. Because [1]_1 is one of the folded bases (its discrete log is known), a
  free n_G would absorb any error in (E). The range check closes this.
- Lemmas 1–2 and the Corollary of §4 are unchanged: they are statements about (E) and the transcript, which Lemma 4
  restores.

## 5. Lemma 3: the today's-rules chain implies the single-input checks

*Track 7 version (default, folded build).* Role names: input 0 = MJ (code C0, MSM windows 50..41, Jacobian), input 1 =
ST, input 2 = MJ (host of TV, windows 40..37), inputs 3–5 = MA (windows 36..0, affine), inputs 6–9 = SI (events
0–16, 16–34, 34–52, 52–65 + terminal). Input 6 hosts GZ and C1, input 7 hosts C2, input 8 hosts WQa, input 9 hosts WQb.
The windows, event cuts and blob hosts come from `plans.json`; `makePlan` asserts that windows and events are
contiguous and cover everything once.

**Lemma 3 (Track 7).** Assume ¬B3. Then the single-input verifier's value-level checks hold on the one value set
(x = PI, π = PROOF, Λ' = X[0,64), inverse = X[64,96), WS (s^c ‖ NB ‖ states), WQ = WQa ‖ WQb). Its challenges,
scalars, P*_var, P_R, nibbles and binding are those of §0, §2 and Lemma 4, and the SI final identity holds for them.
The WQ length rule differs from single input: leading zero words are allowed, and the size is a multiple of 4 words
(≥ 136 words). A6 needs only the cap.

*Proof.* Steps 1–3 are as in Track 6, with these changes:

1. **Code.** R loads C1 (input 6), C2 (input 7) and C0 (input 0) at fixed offsets. It checks their SHA-256 against
   constants, then defines and invokes them (`buildMulti`, `load`). The graph pin is the shared function PIN
   (TXINPUTCOUNT = 10, every UTXOBYTECODE = own). By ¬B3 the executed code is the built code. C0 dispatches on
   INPUTINDEX.
2. **Layout.**
   - As in Track 6, every fixed push has its planned size, except the code pushes and WQb.
   - Each blob is the last fixed push of its host and is hash-checked. No role code embeds an offset that depends on a
     blob's size.
   - WQb is the last fixed push of input 9. Its size is not pinned by its host. Nothing after it is read remotely
     (`offsetOf` throws on such a read).
   - Its encoding is still unique: ST requires 256 ≤ L ≤ 65,535, so the minimal push is PUSHDATA2, 0x4d ‖ LE16(L).
     ST reads that header (`rreadVar`: byte 0x4d checked, then L bytes), so it gets exactly input 9's stack item.
3. **Remote reads.** `rread` as before. ST's read of the Wζω slice of TV is still not header-checked (§7). New reads:
   - WQa (ST), GZ (`GZD`), WS and G0 (SI roles): all by `rread`;
   - WQb by `rreadVar`.
4. **ST** runs Track 6's steps on its own pushes, and in addition (`stTranscript`):
   - reads WQa ‖ WQb and checks the WQ size rule;
   - computes h0 = SHA256(TAG ‖ uRaw ‖ WS), ρ and z (z ≠ 0) byte-exactly as q_h0, q_ρ, q_z of §0;
   - computes QZ = Σ_w q_w·z^{2(n−1−w)} over WQ's words (each < p, `DLP`);
   - (bindST, mul2) runs `gtNibCheck`, `gtBindLoop` and `gtBind` on NB = WS[192, 192 + 65m) and its own s_i.
   
   It requires G0 = uRaw ‖ LE32(s'_q)_{q ∈ var} ‖ ENC(P_R) ‖ ENC(ρ) ‖ ENC(z) ‖ ENC(QZ) [‖ LE32(s_i)_i, merkle16].
5. **Readers of G0:**
   - the MSM roles get s'_q;
   - the SI roles get P_R, ρ and z (`siPre`);
   - the last SI role also gets QZ, and for merkle16 the s_i, decoded < r (`DLR`).
   
   These are ST's computed values (step 3, ENC injective). So every SI role uses §0's ρ and z.
6. **Tables.**
   - TV is unchanged, checked by its host with the unsigned decoding (< p).
   - LOADT now decodes the published pieces with a SPLIT tree and BIN2NUM(w) without the 0x00 sign byte.
     - Every TV word is < p < 2^255, so its high bit is 0 and BIN2NUM(w) equals the host's unsigned value.
     - The tree consumes exactly 960·count bytes (size check), and every leaf is 32 bytes.
     - TF does not exist in the folded build.
   - GZ: its host computes R_{i,j}(±z) from the baked R coefficients (`GTZ`/`GTV`) and requires GZ = ENC of these
     8m values.
     - The other SI roles decode GZ. Its words are < p because they equal ENC outputs, so BIN2NUM without the sign
       byte is exact.
     - Every SI role builds TP_i/TM_i from them (`GTT`/`GTP`) and TB from π_1..π_3 (`TBC`).
7. **Hand-over.**
   - As in Track 6 (ENC, byte-exact HAND, `DLP` < p).
   - SI → SI hands over P*_var, both chain states, F± and R; the GT accumulators are not handed over.
8. **The MSM** is Track 6's over the variable bases, with these differences:
   - Role 0 runs Jacobian windows 50..41, role 2 runs 40..37. Role 3 converts with ZI, roles 3–5 are affine, and role 5
     adds the correction.
   - The point handed to role 6 is the single-input program's P*_var (A4).
9. **SI.**
   - Every SI role:
     - takes ρ and z from G0 (step 5) and WS from ST;
     - checks its DS slice by SHA-256;
     - builds EVS from its constant schedule bytes and its NB slice WS[192 + m·e0, 192 + m·e1) (`EVSB`). Each Miller
       record takes m nibble bytes, terminal records take none, and both strings must be consumed exactly.
   - SIL keeps WSs, R and EVS on the altstack. Per event it runs the doubling, the optional addition and `gtStep` on
     the event's m bytes (F+ ·= TP_i[n], F− ·= TM_i[n]), then the boundary. D, EVS and WSs are checked empty at the end.
   - The cuts are at chunk boundaries and hand over (step 7).
   - The last role:
     - runs the two terminal steps, F ·= S_c(±ηz)·Rconst(±z) and the W step;
     - (merkle16) runs the nibble check and binding on NB from WS with the s_i from G0;
     - checks the final identity R ≡ z·QZ·M(z) with ST's QZ, which is exactly the single-input Horner value (step 4).
   - So the SI computation and the binding are the single-input ones, split at chunk boundaries. Together with
     Lemma 4 this gives (E). ∎

*Track 6 version (FOLD=0 reference build), kept for reference:*

Let T be a transaction that is valid under A5, and one of whose inputs spends a UTXO locked by P2SH32(R), with R the
redeem built by `buildMulti`. Write (G0, X, PI, PROOF, WS) for input 1's (ST's) first five pushes and WQ for input 8's
WQ push.

**Lemma 3.** Assume ¬B3. Then the single-input verifier's value-level checks hold on the one value set
(x = PI, π = PROOF, Λ' = X[0,64), inverse = X[64,96), WS, WQ). Its challenges, scalars, P* and P_R are exactly those of
§0 and §2, and the SI final identity holds for them. The only difference is the WQ length rule: here WQ is exactly
60 words with leading zeros allowed, while the single-input build requires 1–60 words and a nonzero leading word.
A6 holds for either rule.

*Proof.*

1. **Every input runs its own role.**
   - Each role first checks TXINPUTCOUNT = N = 10, and UTXOBYTECODE(j) = own for every j < N (`multi.mjs:230-231`).
   - So all N inputs spend P2SH32(R). By ¬B3, each one's redeem is R.
   - R loads C1 from input 9 and C0 from input 0 at fixed offsets, checks their SHA-256 against constants, then defines
     and invokes them (`multi.mjs:301-302`). By ¬B3 the executed code is the built C1 and C0, whatever else those
     inputs push.
   - C0 invokes role `roleBase + INPUTINDEX` (`:298`). So input i runs role i, for every i < N. An input with index
     ≥ N would invoke an undefined function.

2. **Layout.**
   - Role i checks, in `own` (`:223-232`):
     - FILL is all-zero and sits on top;
     - the slope pieces, if any, are nonzero multiples of 32 bytes;
     - after those are moved, DEPTH equals the number nf of fixed pushes;
     - every fixed push has its planned size L (CODE and C1 are exempt; each is the last fixed push of its role and is
       hash-checked).
   - By A5 the unlocking is a sequence of minimal pushes, whose stack items are, in order, the nf fixed pushes, the
     slope pieces, FILL and the redeem.
   - A minimal push of L bytes has a unique encoding whenever L = 0 or L ≥ 2:
     - L = 0 is `OP_0`, h = 1;
     - otherwise h(L) is 1 byte if L ≤ 75, 2 if L ≤ 255, 3 if L ≤ 65,535.
     
     Every fixed push has L ≥ 32, except PI when k = 0, which is empty and pushed as `OP_0`. So the encoding of every
     fixed push is fixed by its size. Only L = 1 could have two encodings, through `OP_1..OP_16`.
   - So fixed push n of role i occupies exactly the bytes [off_n, off_n + L_n) of input i's unlocking bytecode, with
     off_n = Σ_{m<n}(h(L_m) + L_m) + h(L_n). This is `offsetOf`, `:66`.

3. **Remote reads return the owner's stack item.**
   - By step 2, `rread` (`:117-119`) returns exactly the owner's stack item for that push.
   - `rread` also re-checks the header; this is redundant given step 2.
   - The same holds for ST's offset read of the Wζω slice of TV (`:372-373`), which does not check the header (§7).

4. **ST** runs, on its own pushes (`statement`, `:307-388`), the single-input verifier's steps 2–6:
   - the size checks;
   - decoding with ranges, and the curve checks on all nine points and Λ' (`:309-317`);
   - the transcript q_γ..q_u with the byte ranges of §0 (`:320-355`);
   - the batch-inverse check (`:344`);
   - the scalars s'_q = S_q mod r + C (`:356-367`);
   - P_R (`:371-385`), with the Wζω table taken from TV (step 6).
   
   It then requires its G0 push to equal uRaw ‖ LE32(s'_q)_q ‖ ENC(P_R) (`:370, :386-387`).

5. **Every reader of G0** gets ST's computed uRaw, s'_q and P_R (step 3):
   - the MSM roles in `scalars`, `:241`;
   - the SI roles in `siPre`, `:392-393`.

6. **Tables.**
   - Every MSM role and ST take base points from ST's PROOF and X[0,64) (`tables`, `:242-247`; `LOADT`, `:131-149`).
     These are the same bytes ST curve-checked.
   - **TV** (variable bases, entries 2..16) is checked in its host, input 2: each word is < p, 2B by the tangent and
     (k+1)B = kB + B by the chord, with Δx ≠ 0 (`tvCheck`, `:277-286`; `CHK15`, `:105-113`). So TV[b][k] = k·B_b.
   - **TF** is SHA-256-checked against the built blob in its host, input 3 (`:265`). So TF[b][k] = k·B_b by A4 and ¬B3.
   - All readers get the same bytes (step 3), and `LOADT` requires them to be consumed exactly.

7. **Hand-over.**
   - Each chain role encodes its end state canonically: ENC is (x mod p + p) mod p as 32-byte LE (`:83`).
   - It requires that encoding to equal its successor's HAND push (`handOut`, `:237-239`).
   - The successor decodes HAND as LE words < p (`handIn`, `:240`), and its HAND size is pinned (step 2).
   - ENC is injective on Fp. So the successor's start state equals the predecessor's end state, as field elements.
   - The order is 0 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 (`:44-45`). Role 0 starts from the constant offset point; role 8
     starts from the constant chain states with R = 0 (`:268, :425-426`).

8. **The MSM.** Roles 0, 2, 3 run windows 50..40 in Jacobian, and roles 4..7 run windows 39..0 in affine
   (`makePlan`, `:32`; `mRole`, `:263-276`).
   - The windows cover each index exactly once, in decreasing order.
   - Each role uses the same scalars (step 5) and the same tables (step 6). Its start point is its predecessor's end
     point (step 7).
   - Role 4 converts with its ZI push, checked by Z·zi = 1 (`:269`). Role 7 adds the constant correction (`:273`). The
     MA roles consume their slope streams exactly (`:274`).
   - So the point handed to role 8 is the single-input program's P* (A4).

9. **SI.**
   - Both SI roles recompute h0, ρ and z from the same G0[0,32) = uRaw, ST's WS and input 8's WQ (`siPre`, `:391-401`;
     WQ is input 8's own push or a header-checked read, `:422`). So both use the challenges of §0.
   - The DS slices are SHA-256-checked against the baked chain slopes (`:421`). By ¬B3 they are the single-input pile.
   - The schedule bytes are constants (`:427, :459`).
   - Role 8's WS slice and role 9's WS slice partition WS's 33 states by BOUNDS. Each is consumed exactly (`:216,
     :429-430`).
   - The cut after event 34 hands over P*, both chain states, F± and R (step 7).
   - Role 9 runs the terminal, the quotient Horner over WQ (words < p, `:447`) and the final identity (`:454-456`).
   - So the SI computation is the single-input one, split at a chunk boundary. ∎

## 6. Theorem and bound

**Theorem.** Assume A1–A6. Let an adversary make at most Q queries to SHA-256 and output either a single-input spend
(`script.mjs`) or a today's-rules transaction (`multi.mjs`) that is accepted for statement x. Then

  Pr[accepted ∧ x ∉ L_vk] ≤ ε_PLONK(Q) + Q·2^-128 + Q·1.134·165/p + 15Q²·2^-256 + 8Q·2^-256
                          ≈ ε_PLONK(Q) + Q·2^-128 + Q·2^-246.05 + Q²·2^-252.09 (+ 8Q·2^-256).

  Track 7 (folded build): the SI term becomes Q·1.134·(33 + 780)/p ≈ Q·2^-243.75. Lemma 4 is inserted after A6. B3
  has 9 targets: the 2 P2SH32 hashes, C0, C1, C2 and the 4 DS slices; TF is gone. The bound is otherwise unchanged:
  ≈ ε_PLONK(Q) + Q·2^-128 + Q·2^-243.75 + Q²·2^-252.09 (+ 9Q·2^-256), still ≈ 2^-64 beyond ε_PLONK for Q ≤ 2^64.

*Proof.*
- Discard Bad (Lemma 0 and B3).
- For the chain, Lemma 3 gives the single-input checks on one value set.
- By A6, except with probability Q·2^-246.05 over the q_ρ, q_z answers, e(P*, [1]_2)·e(P_R, [τ]_2) = 1. That is (E).
  The q_h0 input fixes P* and P_R (Lemma 0).
- By the Corollary of §4, except with probability Q·2^-128, Λ' = Λ and A0 = A1 = 0. Then (x, π̃) is gnark-valid.
- A reduction that forwards all oracle queries outputs it. So the rest is at most ε_PLONK(Q). ∎

**Numbers.** For Q ≤ 2^64 the terms other than ε_PLONK sum to at most 2^-64 + 2^-124.09 + 2^-182.05 + 2^-189 ≈ 2^-64.
In other words, each hash query buys the adversary at most a 2^-128 chance against the KZG step. That is below
BN254's own discrete-log security (about 100–110 bits), so this step is not the weakest link. The single-input build
has no B3 targets except R, and the same bound applies.

## 7. What the code does not do as the sketches say (no soundness gap found)

- **Track 7: a gap found and closed while writing Lemma 4.** The first folded build did not range-check the nibble
  bytes; see the remark after Lemma 4. `gtNibCheck` (NB & 0x0f…0f == NB) is now run on the whole NB:
  - in the single-input program, right after NB is split off WS;
  - in the chain, in the binder (ST for mul2, the last SI role for merkle16), whose read of ST's WS covers every byte
    any SI role uses.
  
  Tests: nibble byte 0x10 and 0x81 manipulations are rejected (single input and chain). They are rejected anyway,
  since h0 changes; the check is what the argument relies on.
- **Track 7: assembler.** `Asm.arrange` kept an already-placed prefix even when other items sat above it. It then left
  those items between the prefix and the rolled names.
  - Fixed in this fork's `asm.mjs`.
  - Every Track 6 build is byte-identical with the fix: single spec and 100 KB, chain C0/C1, both circuits.
  - The reviewed `chunked/bn254/sound-si-gls/asm.mjs` and `bn-native-sound/asm.mjs` contain the same pattern. They
    were not changed here; whether their builds are affected was not checked.
- **Track 7: WQb is not size-checked by its host.** ST checks the size rule on the bytes it reads, which are exactly
  the host's stack item (Lemma 3 step 2).

- **ST's read of the Wζω table is not header-checked.** It reads TV at `off + 960·vi` with no header check
  (`multi.mjs:372-373`). The redeem's C0/C1 loads do not check headers either (`:301`). The sketch says every remote
  read checks its push header. The argument above does not need header checks: offsets follow from the owner's size
  and DEPTH checks plus the consensus minimal-push rule (Lemma 3, step 2). The code blobs are hash-checked.
- **The layout argument depends on consensus rules that were checked only in libauth.** Minimal pushes and push-only
  unlockings are consensus rules in libauth 3.1.0-next.8 and, per the BCH 2018-11 / 2019-11 upgrades, in BCHN. No BCHN
  node was run.
- **WQ length rule.** The chain's WQ is fixed at 60 words with leading zeros allowed; the single-input build requires a
  nonzero leading word. A6's degree bound uses only the 60-word cap, so the difference is malleability, not soundness.
- **Formula correctness (A4) remains an assumption.** It is tested by the valid, tampered and adaptive vectors. It is
  not proved.
