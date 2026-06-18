# ZKPs on Bitcoin Cash vs. Prior Attempts on Other Bitcoin Chains

This document situates the Groth16-in-CashScript effort in this repo against the
earlier zero-knowledge-proof (ZKP) verification work done on other Bitcoin
forks. The short version: every prior "ZKP on Bitcoin" milestone was achieved
either on a chain that removed Bitcoin's script/transaction limits (BSV), on a
testnet with an opcode that mainnet lacks (BTC + `OP_CAT`), or by moving the
verification off-chain entirely. Bitcoin Cash sits in a genuinely different
spot, and that difference dictates a different architecture — see
[BCH Shortcomings](README.md#bch-shortcomings) and
[Breaking Up Computation Across Multiple Steps](multi-step-computation.md).

Background reading: Wei Zhang (nChain),
[*Four First-Ever ZKP Verifications on Bitcoin*](https://medium.com/@w.zhang/four-first-ever-zkp-verifications-on-bitcoin-9475df11d57e).

## The prior attempts

In July 2024 four teams each claimed a "first-ever" ZKP-on-Bitcoin milestone.
They fall into three architectural buckets, and none of them is the situation
BCH is in.

### 1. BSV — native big-integer arithmetic, no script limits

This is the most-cited line of work and the closest technical cousin to what we
are attempting, because BSV kept (and extended) Bitcoin's native arithmetic
opcodes and **removed the script-size and operation limits** that constrain
other chains.

- **sCrypt (Aug 2022)** were first to implement a Groth16 verifier in Bitcoin
  Script, over the **BN256 / alt_bn128 / BN254** curve — the same curve this
  repo targets. The verifier was deployable on BSV. The catch is size: the
  first iteration was an **~11 MB transaction**, later optimised down to
  **~1.5 MB**. The whole verifier runs in **one transaction**.
- **nChain (Jul 2024)** verified a Groth16 proof on **BSV mainnet** using
  **BLS12-381**, exploiting BSV's restored large-integer opcodes
  (`OP_MUL`, `OP_MOD` on big numbers). They emphasised being the first to be
  *practically compliant* with network policy — specifically the ~500 KB limit
  on the **locking script** — spending around ~40 KB, and demonstrated circuits
  from ~40,875 constraints (SHA256 of a 5-byte input) up to ~700,000 constraints
  (ML inference). This was reportedly **functionally equivalent** to the earlier
  ~1.5 MB version (a few more script optimisations, no reduction in scope), so
  the milestone is about policy-compliance rather than added capability. Proof
  size is constant regardless of constraint count — the verifier cost, not the
  proof, is the wall.

The defining feature of the BSV approach is **brute force in a single
transaction**: because BSV lifted the per-script and per-transaction limits, a
multi-megabyte verifier is simply allowed to run. There is no need to split the
computation.

### 2. BTC — needs an opcode mainnet doesn't have

- **StarkWare (Jul 2024)** verified a hash-based **STARK** on **Signet**, the
  only Bitcoin testnet with `OP_CAT` enabled. The toy example (the 32nd term of
  the Fibonacci-squared sequence, ~100 constraints) took **11 Taproot
  transactions totalling ~4 MB**, and the author notes proof size becomes
  "economically or even computationally unviable" at scale. Critically this
  cannot run on BTC mainnet, where `OP_CAT` is disabled.

STARKs are chosen here precisely because BTC lacks native field arithmetic:
without big-number `OP_MUL`/`OP_MOD`, a pairing-based SNARK verifier is
impractical, so the hash-centric STARK route (which leans on `OP_CAT` for
commitment/concatenation) is the only viable path — and even that needs a
soft fork.

### 3. Off-chain / attestation — sidestep Script entirely

- **BitcoinOS (Jul 2024)** — a "Merkle Mesh" of off-chain decentralised
  verifications, with no reliance on opcode changes or in-Script verification.
  Pragmatic, works on BTC today, but the proof is not verified by Bitcoin
  consensus.
- **BitVMX (Jul 2024)** — hybrid STARK+Groth16 with verification done off-chain
  and only an *attestation* (plus a challenge/fraud-proof mechanism and a
  one-time-signature scheme) committed on-chain. Again, consensus does not
  itself check the proof.

## What makes the BCH situation unique

BCH is neither BSV nor BTC, and that is the whole point.

**Unlike BTC**, BCH has the primitives a pairing verifier needs *natively on
mainnet*:

- **BigInt high-precision arithmetic** (CHIP-2024-07, activated May 2025):
  VM numbers can grow to the 10,000-byte stack-element size, so the field
  arithmetic over the BN256 prime is native — no `OP_CAT` byte-shuffling, no
  soft fork required.
- **Loops and shift operators** (CHIP-2021-05, CashScript v0.13.0): the
  repeated structure of Miller's loop, tower multiplications, and final
  exponentiation can be expressed directly (see [roadmap.md](roadmap.md)).
- A **10,000-byte stack-element limit** (up from 520 bytes), enough to hold
  packed F_p², F_p⁶ and F_p¹² tower elements.

So, like BSV and unlike BTC, BCH can do the *math*. The verifier does not need
to be reframed as a STARK or pushed off-chain.

**Unlike BSV**, BCH deliberately *kept* conservative anti-DoS limits rather than
removing them. After the May 2025 upgrade these — not missing language features
— are the binding constraints (see
[BCH Shortcomings](README.md#bch-shortcomings)):

- **Max unlocking bytecode ~10,000 bytes** (P2SH consensus). For P2SH the
  contract ships in the unlocking bytecode, so this single limit caps how large
  the verifier can be.
- **Operation-cost budget**, scaled by unlocking-script length
  (`(41 + unlockingBytecodeLength) * 800`) and enforced per input. You can
  "buy" budget by padding, but only up to the same ~10 KB wall.
- **Stack-element, SigChecks, and hashing caps** per transaction.

The consequence is decisive: the BSV trick — drop a multi-megabyte verifier
(sCrypt's was ~1.5–11 MB) into a single transaction — is **structurally impossible on BCH**. A full pairing
verifier (F_p¹² tower arithmetic, Miller loop, final exponentiation) will not
fit in ~10 KB, and no amount of padding buys enough op-cost budget within one
input.

## The BCH-unique approach: split across sequential stateful transactions

Because the limits are *per input per transaction*, the only way to exceed them
is to spread the computation across a **chain of transactions**, carrying state
forward in a stateful covenant. This repo's design (see
[multi-step-computation.md](multi-step-computation.md)) does exactly that:

1. Each transaction performs one chunk sized to fit that step's op-cost and
   bytecode budget.
2. Intermediate state is carried in a **CashToken NFT commitment**. Since a
   commitment holds at most 128 bytes and the Groth16 working state (an F_p¹²
   accumulator alone is ~384 bytes, plus the running G2 point and counters) is
   far larger, only a `hash256` of the full state lives in the commitment; the
   full state is supplied in the spending transaction and checked against the
   hash.
3. A step/phase counter tracks progress; the final step asserts the pairing
   product equals the F_p¹² identity.

This is the inverse of the BSV philosophy. BSV says "remove the limits, run it
all at once." BCH says "keep the limits, and decompose the computation to fit
them." The trade-offs are latency (one mempool/block hop per step), per-step
fees and dust, and the overhead of re-providing and re-hashing the full state
each step — but it lets total computation exceed any single transaction's
budget *without changing consensus*.

## Footprint and elegance

A natural question is whether BCH's verifier is smaller and more elegant than
the BSV one. The honest answer splits into two claims — one clearly true, one
that needs to be stated carefully.

### Contract bytecode: genuinely more compact

BSV Script has no loops or reusable functions, so sCrypt **unrolls everything**
at compile time — the Miller loop body, the tower multiplications, the
final-exponentiation ladder are all copied out N times into the locking script.
That is the direct reason their verifier was ~1.5–11 MB.

BCH's native loops (CHIP-2021-05) put the loop body in bytecode **once** and
re-execute it, so for the heavily-repeated sections (Miller loop ~64 iterations,
square-and-multiply ladders, repeated F_p¹² muls) the BCH bytecode is roughly
`1/N` the size of the unrolled BSV equivalent. The per-step contract is
therefore dramatically more compact and more readable. (Reusable functions —
roadmap [#369](https://github.com/CashScript/cashscript/issues/369), tied to the
2026 upgrade — would add to this, but are not yet available, so this is a
loops-only claim today.)

Note this is a claim about **space, not compute**. The curve (BN256), the
algorithm, and the number of field operations executed are identical to BSV's;
a loop running 64 iterations still costs 64 iterations of op-cost budget. Loops
shrink the bytecode, not the math.

### Aggregate footprint: likely smaller than BSV, not larger

Because every BCH step is hard-capped at the ~10,000-byte P2SH unlocking-bytecode
limit (which already includes the re-supplied redeem script, the provided state,
and signatures), the total on-chain footprint is cleanly bounded:

```
aggregate unlocking bytecode  ≈  N_steps × (≤ 10 KB)
```

That puts the crossover points against the BSV implementations at:

| BSV reference | Size | Approx. BCH steps to match |
|---|---|---|
| nChain 2024, policy-compliant | ~500 KB *locking script* | ~50 steps |
| sCrypt 2022, optimised | ~1.5 MB *transaction* | ~150 steps |
| sCrypt 2022, first iteration | ~11 MB *transaction* | ~1,100 steps |

> The BSV figures mix two different measurements — nChain's ~500 KB is a
> *locking-script* size, while sCrypt's ~1.5/11 MB are whole-*transaction*
> sizes — so these crossovers are order-of-magnitude, not exact.

So unless the verifier needs **more than ~150 steps**, BCH's aggregate footprint
is *smaller* than the optimised BSV transaction — and a well-tuned chunking (each step
packing as much of the post-2025 op-cost budget as the 100× VM-limits increase
allows) plausibly lands in the **tens of steps**, i.e. low-hundreds of KB total.

The per-step carrying overhead is small in byte terms and dwarfed by the redeem
script (and bounded by the 10 KB cap regardless):

- Working state re-provided each step: F_p¹² accumulator (~384 B) + running G2
  point (~128 B) + counters ≈ **~600 B**.
- Transaction skeleton (inputs/outputs/version/locktime): a few hundred bytes.

**The real costs of the multi-step approach are therefore not aggregate bytes**
but: **latency** (sequential, one mempool/block hop per step), **per-step fees
and dust**, and the **hashing/op-cost budget** burned re-hashing the full state
every step (a compute cost, not a size cost).

> **Caveat — the one number we can't yet pin down is `N_steps`.** It depends on
> how much work each step can pack under the op-cost budget, which requires
> actually compiling representative chunks (an F_p¹² mul, a Miller-loop
> iteration, a final-exponentiation segment) and measuring their op-cost and
> bytecode. The crossover bounds above are firm; the realised step count is
> pending that measurement.

## Comparison at a glance

| Chain / team | Proof system & curve | Where math runs | Single-tx? | Why this repo differs |
|---|---|---|---|---|
| **BSV** — sCrypt 2022 (testnet → mainnet) | Groth16, BN256 | In-Script, native big-int, **no limits** | Yes (~11 MB → ~1.5 MB tx) | BCH keeps DoS limits → can't drop a multi-MB verifier in one tx |
| **BSV** — nChain 2024 (mainnet) | Groth16, BLS12-381 | In-Script, native big-int, policy-compliant | Yes (<500 KB lock) | Same: no equivalent of BSV's unbounded single-tx budget on BCH |
| **BTC** — StarkWare 2024 (Signet) | STARK (hash-based) | In-Script, requires `OP_CAT` | No (~11 txs, ~4 MB) | BCH has native arithmetic on mainnet; no soft fork / `OP_CAT` needed |
| **BTC** — BitcoinOS 2024 | (Merkle Mesh) | **Off-chain** | n/a | BCH verifies in consensus, not off-chain |
| **BTC** — BitVMX 2024 | STARK + Groth16 | **Off-chain + on-chain attestation** | n/a | BCH verifies the proof itself, no fraud-proof/challenge game |
| **BCH** — this repo | Groth16, BN256 | In-Script, native big-int, **limited per tx** | **No — multi-step covenant** | Decompose across sequential NFT-covenant transactions |

## Takeaway

The earlier milestones answer a different question than BCH faces. BSV asked
"what if Bitcoin had no limits?" and answered with a single giant transaction.
BTC asked "what can we do without native arithmetic?" and answered with STARKs
on a testnet opcode, or with off-chain attestation. BCH is the only chain that
both **has native big-integer arithmetic on mainnet** *and* **keeps tight
anti-DoS limits** — so its unique contribution is showing that an in-consensus,
no-soft-fork Groth16 verifier is achievable by **decomposing the verifier
across a chain of stateful covenant transactions**, rather than by removing
limits or leaving consensus.

---

*Reference: Wei Zhang, [*Four First-Ever ZKP Verifications on Bitcoin*](https://medium.com/@w.zhang/four-first-ever-zkp-verifications-on-bitcoin-9475df11d57e), Medium.*
