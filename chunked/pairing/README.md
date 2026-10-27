# chunked/pairing/ — BCH-native multi-transaction Groth16 pairing

The BN254 pairing split across transactions so **every step fits one BCH input**
(op-cost ≤ 8,032,800, locking and unlocking scripts each ≤ 10,000 B). This is the BCH-compatible
counterpart of the `singleton/bn254/` oracle (which is correct but needs ~151
inputs' worth of op-cost in one go).

Three benchmark entries (in the verifier repo) are produced from here:

- **`bch-pairing-chunked`** — the **Miller boundary** `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)`
  (checkpoint #2) as one prepared, batched optimal-ate loop. It shares each `fp12Sqr`
  across the three runtime-dependent pairs, omits the fixed `e(α,β)` pair, then multiplies
  its precomputed raw Miller value into `f` once. The exact four-pair boundary takes 20 inputs.
- **`bch-groth16-chunked`** — the **complete verifier** (checkpoint #3): vk_x
  (computed on-chain from canonical public inputs) → canonical G1/G2 input validation → the
  prepared Miller chunks → final exponentiation → a final step asserting the product
  == Fp12 ONE. 43 inputs.

The current source-owned covenant frontier is reproduced separately:

```sh
VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
```

It writes exactly
`$VERIFIER_DIR/src/bch/groth16-chunked-covenant-residue-vectors.json`.
The 12-transaction graph uses three standalone GLV `vk_x` chunks, one transaction that
fuses the GLV terminal with the Miller prefix, and eight remaining quotient-torus Miller
chunks. Its GLV minting-baton genesis commits the raw proof tuple. The fused transaction
finishes `vk_x`, derives a B-identity flag exactly from the all-zero raw B encoding, and maps only that case to
`G2.BASE` for the affine walk, and immediately checks the canonical points and curve
equations before emitting the first Miller state. There is no intermediate
`(-A,effective-B,C,vk_x,B-identity)` covenant seam: the fused input commitment binds the
partial GLV state and raw proof tuple, and its output commitment binds the resulting Miller
state. A finite raw `B=G2.BASE` remains finite. The fused step derives its normalized line
state and uses the identity flag to make only the
original all-zero B pairing neutral; the runtime-B endpoint proves exact G2 subgroup
membership. The six-limb finite residue root is introduced inside that fused transition,
then every later state is committed by a canonical NFT commitment. Every nonterminal
covenant pins its successor P2SH32 locking, and the mutable thread terminates as an
immutable NFT.

The reproduction command also runs the affine, unit-line, integer-bound, endpoint,
and quotient-torus proof scripts. The writer refuses to emit vectors unless the
committed, second, dense, and 11 identity/boundary proofs all pass the same locking graph
on both BCH 2026 consensus and standard-policy VMs with exact per-transaction fee funding,
and it rejects its point, residue-range, state, successor-locking, token-lifecycle,
quotient, and stage-seam fixtures.
The exact satoshi values and fees belong to those funded vectors; the covenant programs enforce
the token and successor transitions but intentionally do not pin satoshi values. This accepting
suite is relay evidence for the measured fixtures, not a proof-independent relay ceiling for every
valid proof.

The verifier evaluates the complete four-pair equation, but verifier.cash's prescribed BN254
checkpoint key is synthetic and publishes its setup and IC scalars. The vectors therefore establish
equation execution, runtime witness handling, and covenant validity for that key, not circuit
knowledge, secure binding of the public-input vector, or interoperability with an independently
generated setup.

The legacy 20-transaction non-quotient residue graph remains reproducible by running
`generate_covenant_residue.mjs` without `MILLER_TORUS=1`.

Every chunk is validated on the real BCH 2026 VM.

## Covenant-residue composition: what the scripts enforce and what the deployment supplies

This section is the composition argument for `bch-groth16-chunked-covenant-residue` (BN254, 12
transactions) and, with the BLS line numbers in `../bls12-381/README.md`, for
`bch-groth16-bls12381-chunked-covenant-residue` (27 transactions). It covers only how the steps
compose into one verdict. The per-step arithmetic (GLV `vk_x`, canonical points, curve and G2
subgroup checks, quotient-torus Miller, residue terminal) is argued in the review notes and the
`prove_*` scripts listed below. Notation: `C` is the 32-byte token category baked into every
redeem, `L_0 .. L_{N-1}` are the graph's P2SH32 lockings (`N = 12`), and `S_k` is the state that
step `k` emits.

### What every redeem enforces (code, not convention)

The builder appends one fixed lifecycle block to each generated contract
(`build_vectors_covenant_residue.mjs:115-136`), inserted before the close of the contract's
single `spend` function (`:147-154`), and pins each nonterminal's successor (`:150-153`). The
per-step state checks come from `covIn` / `covOut` (`_millermath.mjs:461-477`). `CATEGORY` is a
constant (`_millermath.mjs:456`, the fixture value `0xcd`×32). An opcode census of the shipped
redeems (`node chunked/pairing/covenant_lifecycle_census.mjs <vector file>`) agrees with the table
below. Each redeem P2SH32-hashes to its step's locking. The
literal `C‖02`, `C‖01` and `C` pushes appear where the table needs them. The token introspection
counts are:
- genesis: 1 input-category, 1 input-commitment (the empty check), 2 output-category,
  2 output-commitment and 2 output-locking reads, and 1 spent-locking read;
- forward: 2 input-category, 1 input-commitment, 2 output-category, 1 output-commitment and
  1 output-locking read;
- terminal: 1 of each, plus 1 spent-locking read.

| step | inputs / outputs | spent token (active input) | created tokens | state |
|---|---|---|---|---|
| genesis `L_0` (GLV chunk 0) | exactly 1 / exactly 2 | category+capability `== C‖02` (minting), commitment empty | out0 `== C‖01` (mutable) at a locking with `hash256 == hash256(L_1)`; out1 `== C‖02` (minting), commitment empty, locking `==` the active input's locking (`L_0`) | no `covIn`: the genesis input check is removed (`:141-146`); out0 commitment `== hash256(S_0)`, computed from the genesis unlocking (public inputs, GLV witnesses, raw proof tuple) |
| forward `L_k`, `0<k<N-1` | exactly 1 / exactly 1 | `== C‖01` (mutable) | out0 `== C‖01` at a locking with `hash256 == hash256(L_{k+1})` | `covIn`: input commitment `== hash256(S_{k-1})` over the pushed limbs; `covOut`: out0 commitment `== hash256(S_k)` |
| terminal `L_{N-1}` | exactly 1 / exactly 1 | `== C‖01` (mutable) | out0 `== C` (immutable), commitment empty, locking `==` the active input's locking (`L_{N-1}`) | `covIn` on `S_{N-2}`, then the quotient-torus verdict; no state is emitted |

Each commitment is `hash256` of fixed-width little-endian limbs (32 B for BN254, 48 B for BLS12-381,
`toPaddedBytes`, i.e. `OP_NUM2BIN`). A fixed-width `OP_NUM2BIN` is injective on the integers that
fit, and a value that does not fit fails the script. So a commitment fixes every limb value, up to
a `hash256` collision. The builder also asserts that `out0` of step `k` is the `in` of step `k+1`,
both as a commitment and as a locking (`:365-372`). It refuses to write vectors unless every
lifecycle mutation is rejected (`:257-311`, `:1195`): wrong category, wrong capability, wrong
successor, terminal self-lock, baton commitment and baton locking. The shipped file's
`verification` block records the counts.

Facts used below (CashTokens consensus rules): a mutable or immutable NFT of `C` can come into
existence only (a) in the category-genesis transaction of `C`, (b) from a transaction that spends
a minting NFT of `C`, or (c) as the single replacement of a spent mutable NFT of `C`. Immutable
NFTs can only be moved unchanged. Fungible tokens of `C` cannot create NFTs. The category reads
return `C‖01` for mutable, `C‖02` for minting and bare `C` for an immutable NFT. Bare `C` with an
empty commitment is also what an output carrying only fungible tokens of `C` reports. So if
fungible tokens of `C` exist and ride on the thread's input, the terminal's out0 check is also met
by a fungible-only output; that spend burns the thread and leaves no verdict NFT. This affects
liveness only, not soundness: the theorem below concerns outputs that carry an immutable NFT, and
P1 need not exclude fungible tokens of `C`.

### Deployment premises (supplied by the deployer, not by the scripts)

- **P1 (category genesis).** The deployer first chooses the outpoint that input 0 of the
  category-genesis transaction will spend; it must be an outpoint with output index 0. `C` is the
  transaction id of that outpoint, and the deployer regenerates the graph with that `C`. The
  bench bytes use the placeholder `0xcd`×32 (BN) or `0xbe`×32 (BLS); they are not a deployment,
  and their lockings and
  hashes change with `C`. The category-genesis transaction must create no NFT of `C` except
  minting NFTs locked by `L_0` with an empty commitment (normally exactly one: the baton). No
  other minting or mutable NFT of `C` may ever exist outside the graph. Nothing on-chain checks
  this, because a script cannot see the category-genesis transaction. It is checkable once, by
  inspecting that one transaction.
- **P2 (how a consumer reads a verdict).** The verdict is the immutable, empty-commitment `C` NFT
  at `L_{N-1}`. The terminal contract requires its active input to carry `C‖01`, and the verdict
  reports `C`. So the verdict output can never be spent: it is a permanent ledger fact, and its
  satoshis are locked with it. No on-chain contract can consume it. Its commitment is empty, so
  it does not name the statement. A consumer is therefore off-chain (a full node, an indexer, or
  SPV with the ancestor transactions). To accept "the Groth16 statement `(n0, n1)` verified for
  this VK", the consumer must:
  1. find an output locked by `L_{N-1}` that carries an immutable `C` NFT with an empty commitment;
  2. follow input 0 of each transaction back `N-1` transactions (every graph transaction has exactly
     one input, so this ancestry is a unique linear chain) to the transaction whose input spends a
     `C‖02` baton locked by `L_0`;
  3. read the statement from that genesis unlocking. The genesis `spend(Ax, .., Cy, in0, in1, k10,
     k20, k11, k21, zeroPadding)` pushes its arguments last-first, so (counting from push 0,
     `zeroPadding`) push 6 is `in0` (`n0`) and
     push 5 is `in1` (`n1`) (`gen_vkx_glv.mjs:174-176,285`). Pushes 4 and 2 are the GLV witnesses
     `k10` and `k11`. They equal `n0` and `n1` only for small scalars (as in the committed
     fixture), so a consumer must not read the statement from them. The bench descriptor's
     `publicInputs` is a mutation-test list, not a statement locator.

  In step 2, a consumer that also checks each spent output's locking `== L_k` gets a
  self-contained proof that does not depend on P1. Each of those transactions was consensus-valid
  under the contract of `L_k`. A consumer that relies on P1 may skip those locking checks. It
  still needs steps 2 and 3 to learn which statement was verified.
- **Not provided.** The covenant does not constrain satoshi values (see above). The baton is the
  single input of every genesis spend and has no signature check, so any party may start a thread.
  Each thread is funded from the baton's value, and that value bounds how many genesis spends are
  possible. This is a liveness and funding matter for the deployment, not a soundness one. The
  synthetic-VK caveat above applies unchanged.

### Composition argument (assuming P1)

**Lemma (token provenance).** Under P1, every NFT of `C` that ever exists is one of:
- (i) a minting NFT locked by `L_0` with an empty commitment;
- (ii) a mutable NFT locked by `L_k` (`1 ≤ k ≤ N-1`), created by a valid execution of the contract
  of `L_{k-1}`, whose commitment is `hash256(S_{k-1})` for the state that execution computed;
- (iii) an immutable, empty-commitment NFT locked by `L_{N-1}`, created by a valid execution of the
  terminal contract.

*Proof*, by induction over ledger order. The category-genesis transaction creates only (i) (P1).
A later NFT of `C` is created only by spending a minting NFT of `C` or by replacing a mutable one.
By induction, those are of kind (i) or (ii), so their spend runs the contract of `L_0` or `L_k`.
- A spend of `L_0` has exactly one input (the baton) and exactly two outputs: a mutable NFT at
  `L_1` committing the genesis state, and a minting NFT with an empty commitment back at `L_0`.
  These are kinds (ii) and (i).
- A spend of `L_k` (`0<k<N-1`) has exactly one input and one output: a mutable NFT at `L_{k+1}`
  committing the state it computed. That is kind (ii).
- A spend of `L_{N-1}` emits only the immutable kind (iii).

Kind (iii) can never be spent (P2), and no other transaction can introduce a token of `C`.
Because every graph transaction has exactly one input, no second token of `C` (from another
thread or another kind) can ever enter a graph transaction. ∎

**Theorem.** Under P1, if an output of kind (iii) exists, then its unique ancestry `T_0 .. T_{N-1}`
consists of valid executions of the contracts `L_0 .. L_{N-1}` in order:
- `T_0` spends a baton;
- `T_k` spends the single output of `T_{k-1}`;
- the state that `T_k` checks with `covIn` is exactly the state `S_{k-1}` that `T_{k-1}` computed
  (an injective commitment, up to a `hash256` collision).

So the chain is one deterministic run of the reviewed per-step computation on the inputs of
`T_0`'s unlocking (the public inputs `n0, n1` and the GLV witnesses), plus the proof tuple:
- for BN, `T_0` commits the raw proof tuple;
- for BLS (full-stage GLV), `A, B, C` enter at the last GLV step, and from there they are bound by
  that step's output commitment.

The terminal accepted, so by the per-step arguments the Groth16 equation holds for
`vk_x = IC0 + n0·IC1 + n1·IC2`, with `n0, n1` taken from `T_0`. *Proof:* by the lemma, the
mutable input of the terminal is kind (ii), created by `L_{N-2}`. Repeat back to `L_0`, whose
input is kind (i). The state hand-off at each seam follows from `covIn`/`covOut` and the
successor pin. ∎

**Without P1** (for example, if the deployer kept a minting NFT of `C` or minted extra mutable
NFTs at category genesis), a mutable NFT with any commitment could be placed at any `L_k`, so
kind (iii) alone proves nothing. The consumer procedure of P2, *with* the per-transaction locking
checks, still yields the theorem's conclusion for the chain it walks. That walk replaces P1 and
does not depend on it.

Per-step references:
- GLV: `prove_vkx_glv_split.mjs`, `prove_projective_vkx.mjs` (the non-grouped legacy prologue is
  used here);
- affine and unit-line Miller: `prove_miller_affine*.mjs`, `prove_miller_unit_lines.mjs`;
- G2 endpoint subgroup: `prove_miller_endpoint_subgroup.mjs`;
- quotient torus: `prove_miller_torus.mjs`;
- the B-identity flag, derived only from the all-zero raw B: `gen_miller_residue.mjs`
  (`B_INFINITY_FLAG` branch).

## Optimizations

- **Lazy reduction** — `addFp`/`subFp` defer the `% p` with per-call-site bias (option-B;
  see the build memos). `mulFp` and the committed state stay reduced.
- **Prepared batched Miller** — one loop squares `f` once per NAF step and folds the
  runtime-dependent pairs' lines into the shared `f`. The fixed `e(α,β)` pair contributes
  a VK-only raw Miller value, so its 87 op objects (88 line folds) are removed and replaced
  by one terminal `fp12Mul`. Fixed-G2 line coefficients are baked, leaving on-chain G2
  arithmetic only for `e(-A,B)`. The folded `f` is the exact four-pair boundary — no
  combine step. The flat trace falls from 413 to 327 ops and the pairing from 24 to 20
  inputs, saving 38,678 bytes and 30,872,282 op-cost in the covenant deployment.

## How it works

Each chunk carries its state — `f` (Fp12, 12 limbs) + the runtime pair's G2 point `R0`
(6 limbs) for the prepared Miller; the live Fp12 values for final-exp — committed
as `hash256` of 32-byte little-endian canonical limbs, re-supplied in the witness and
verified on entry and exit (the same stateful-covenant pattern as the chunked
vk_x in `../shamir`). Within a chunk the ops are **unrolled straight-line with fresh
SSA variables** (no runtime loop / masks), so the body compiles once and **op-cost
binds, not size** — chunks are ~5 KB. The per-step math is noble's (which the CashScript fp2/fp6/fp12 ops
match bit-for-bit), so the carried limbs equal what the contract computes and the
baked hash commitments line up. Window sizes are chosen by measuring real-VM
op-cost.

The full flow is one continuous mutable-NFT chain. The vk_x genesis derives its
Jacobian infinity state from the public inputs, G2 validation derives its accumulator
from `B`, and the Miller genesis derives `f=1` and `R0=B`. Each stage emits only the
tuple consumed by the next stage, and every nonterminal contract pins the actual
P2SH32 locking bytecode of its successor.

## Regenerating (everything in `generated/` is git-ignored)

The 43 full-verifier chunk contracts + manifests are reproducible artifacts, so they are
**not committed** — only the generators are. Regenerate them (and the benchmark
vectors) with one command:

```
VERIFIER_DIR=/path/to/zk-verifier-bench node generate.mjs
```

This runs (several minutes):

1. `gen_miller.mjs` → `generated/miller_NN.cash` + `manifest_miller.json`
   — the prepared batched Miller loop as a flat op list, chunked at any op boundary.
2. `gen_finalexp.mjs` → `generated/finalexp_NN.cash` + `manifest_finalexp.json`
   — the final exponentiation `f^((p¹²−1)/r)` traced as an SSA op-DAG (the 3
   cyclotomic-exp ladders chunked like the Miller loop; liveness carries only the
   live Fp12 values as committed state); the last chunk asserts result == ONE.
3. `gen_vkx.mjs` → standalone `vkx_NN` and full-stage `vkxfull_NN` chunks
   — vk_x = IC0 + in0·IC1 + in1·IC2 (Shamir/Straus, public inputs at runtime);
   the full-stage terminal binds `(-A,B,C,vk_x)` for G2 validation.
4. `gen_g2check.mjs` → full-stage `g2checkfull_NN` plus lean linked
   `g2check_NN` chunks — on-curve checks plus the fast-endomorphism G2 subgroup check.
5. `build_vectors.mjs` → three files in `../../verifier/src/bch/`:
   `pairing-chunked-vectors.json` (boundary, for `bch-pairing-chunked`) and
   `groth16-chunked-vectors.json` (vk_x → validation → pairing → final-exp → verdict, for
   `bch-groth16-chunked`), plus `vkx-chunked-covenant-vectors.json`.

### Why it takes a few minutes

The runtime is **not** the cryptography — it's the chunk *planner*. There is no
formula for "how many steps fit one BCH input", so each chunk is sized empirically:
the generator grows a window one step at a time and, for every candidate, **shells
out to the custom `cashc` to compile the contract and then evaluates it on the real
BCH 2026 VM to measure its exact op-cost**, stopping when the next step would exceed
the per-input budget. That's a few compile+measure iterations per chunk × 43
chunks ≈ several hundred `cashc` subprocess invocations and VM runs. `build_vectors`
then compiles, pads, and evaluates every one of the 43 chunks **twice** (the valid
witness and a tampered one) on the real VM. So the cost is dominated by hundreds of
compiler launches + VM evaluations, not the field/pairing math (which is fast). The
result is fully deterministic, so it only needs to run when the instance or the
chunking changes.

Run a single piece directly if needed: `node gen_miller.mjs`, `node gen_finalexp.mjs`,
`node gen_vkx.mjs`, etc. Fast probes (no planner): `node gen_miller.mjs probe`,
`node gen_finalexp.mjs probe`.

## Files

| file | role | committed |
|------|------|:--------:|
| `_millermath.mjs` | shared reference math (noble), serialization, instance pairs, real-VM measurer | ✅ |
| `gen_miller.mjs` | plan + emit the prepared batched Miller chunks (flat-op) | ✅ |
| `gen_finalexp.mjs` | trace + chunk the final exponentiation (op-DAG + liveness) | ✅ |
| `gen_vkx.mjs` | chunk vk_x for the pairing instance (Shamir/Straus) | ✅ |
| `gen_g2check.mjs` | chunk G2 on-curve and subgroup validation | ✅ |
| `build_vectors.mjs` | assemble all chunks → the pairing, full-verifier, and vk_x vectors | ✅ |
| `generate.mjs` | one-command orchestrator (runs all of the above) | ✅ |
| `generated/` | the 43 full-verifier `.cash` chunks + manifests (derived) | ❌ git-ignored |
| `build_vectors_covenant_residue.mjs` | assemble and gate legacy or quotient-torus covenant lifecycles | ✅ |
| `generate_covenant_residue.mjs` | one-command proof, vector, and VM reproduction for either covenant mode | ✅ |
| `generated/` | the 43 full-verifier `.cash` chunks + manifests (derived) | ❌ git-ignored |

The committed instance lives in the verifier repo
(`src/checkpoints/pairing-vectors.json`); the singleton oracle is `../../singleton/bn254/`.
