# ZKPs on Bitcoin Cash vs. Prior Attempts on Other Bitcoin Chains

This document situates the Groth16-in-CashScript effort in this repo against the
earlier zero-knowledge-proof (ZKP) verification work done on other Bitcoin
forks. The short version: every prior "ZKP on Bitcoin" milestone was achieved
either on a chain that removed Bitcoin's script/transaction limits (BSV), on a
testnet with an opcode that mainnet lacks (BTC + `OP_CAT`), or by moving the
verification off-chain entirely. Bitcoin Cash sits in a genuinely different
spot, and that difference dictates a different architecture; see
[BCH Shortcomings](README.md#bch-shortcomings) and
[Breaking Up Computation Across Multiple Steps](multi-step-computation.md).

Background reading: Wei Zhang (nChain),
[*Four First-Ever ZKP Verifications on Bitcoin*](https://medium.com/@w.zhang/four-first-ever-zkp-verifications-on-bitcoin-9475df11d57e).

## The prior attempts

In July 2024 four teams each claimed a "first-ever" ZKP-on-Bitcoin milestone.
They fall into three architectural buckets, and none of them is the situation
BCH is in.

### 1. BSV: native big-integer arithmetic, no script limits

This is the most-cited line of work and the closest technical cousin to what we
are attempting, because BSV kept (and extended) Bitcoin's native arithmetic
opcodes and **removed the script-size and operation limits** that constrain
other chains.

- **sCrypt (Aug 2022)** were first to implement a Groth16 verifier in Bitcoin
  Script, over the **BN256 / alt_bn128 / BN254** curve, the same curve this
  repo targets. The verifier was deployable on BSV. The catch is size: the
  first iteration was an **~11 MB transaction**, later optimised down to
  **~1.5 MB**. The whole verifier runs in **one transaction**.
- **nChain (Jul 2024)** verified a Groth16 proof on **BSV mainnet** using
  **BLS12-381**, exploiting BSV's restored large-integer opcodes
  (`OP_MUL`, `OP_MOD` on big numbers). They emphasised being the first to be
  *practically compliant* with network policy (specifically the ~500 KB limit
  on the **locking script**), spending around ~40 KB, and demonstrated circuits
  from ~40,875 constraints (SHA256 of a 5-byte input) up to ~700,000 constraints
  (ML inference). This was reportedly **functionally equivalent** to the earlier
  ~1.5 MB version (a few more script optimisations, no reduction in scope), so
  the milestone is about policy-compliance rather than added capability. Proof
  size is constant regardless of constraint count; the verifier cost, not the
  proof, is the wall.

The defining feature of the BSV approach is **brute force in a single
transaction**: because BSV lifted the per-script and per-transaction limits, a
multi-megabyte verifier is simply allowed to run. There is no need to split the
computation.

### 2. BTC: needs an opcode mainnet doesn't have

- **StarkWare (Jul 2024)** verified a hash-based **STARK** on **Signet**, the
  only Bitcoin testnet with `OP_CAT` enabled. The toy example (the 32nd term of
  the Fibonacci-squared sequence, ~100 constraints) took **11 Taproot
  transactions totalling ~4 MB**, and the author notes proof size becomes
  "economically or even computationally unviable" at scale. Critically this
  cannot run on BTC mainnet, where `OP_CAT` is disabled.

STARKs are chosen here precisely because BTC lacks native field arithmetic:
without big-number `OP_MUL`/`OP_MOD`, a pairing-based SNARK verifier is
impractical, so the hash-centric STARK route (which leans on `OP_CAT` for
commitment/concatenation) is the only viable path, and even that needs a
soft fork.

### 3. Off-chain / attestation: sidestep Script entirely

- **BitcoinOS (Jul 2024)**: a "Merkle Mesh" of off-chain decentralised
  verifications, with no reliance on opcode changes or in-Script verification.
  Pragmatic, works on BTC today, but the proof is not verified by Bitcoin
  consensus.
- **BitVMX (Jul 2024)**: hybrid STARK+Groth16 with verification done off-chain
  and only an *attestation* (plus a challenge/fraud-proof mechanism and a
  one-time-signature scheme) committed on-chain. Again, consensus does not
  itself check the proof.

## What makes the BCH situation unique

BCH is neither BSV nor BTC, and that is the whole point.

**Unlike BTC**, BCH has the primitives a pairing verifier needs *natively on
mainnet*:

- **BigInt high-precision arithmetic** (CHIP-2024-07, activated May 2025):
  VM numbers can grow to the 10,000-byte stack-element size, so the field
  arithmetic over the BN256 prime is native, with no `OP_CAT` byte-shuffling and
  no soft fork required.
- **Loops** and **bit-shift opcodes** (shifts via CHIP-2025-05 Bitwise, active
  May 2026): the repeated structure of Miller's loop, tower multiplications, and
  final exponentiation can be expressed directly (see [roadmap.md](roadmap.md)).
- A **10,000-byte stack-element limit** (up from 520 bytes), enough to hold
  packed F_p², F_p⁶ and F_p¹² tower elements.

So, like BSV and unlike BTC, BCH can do the *math*. The verifier does not need
to be reframed as a STARK or pushed off-chain.

**Unlike BSV**, BCH deliberately *kept* conservative anti-DoS limits rather than
removing them. After the May 2025 upgrade these, not missing language features,
are the binding constraints (see
[BCH Shortcomings](README.md#bch-shortcomings)):

- **Max unlocking bytecode ~10,000 bytes** (P2SH consensus). For P2SH the
  contract ships in the unlocking bytecode, so this single limit caps how large
  the verifier can be.
- **Operation-cost budget**, scaled by unlocking-script length
  (`(41 + unlockingBytecodeLength) * 800`) and enforced per input. You can
  "buy" budget by padding, but only up to the same ~10 KB wall.
- **Stack-element, SigChecks, and hashing caps** per transaction.

The consequence is decisive: the BSV trick (drop a multi-megabyte verifier,
sCrypt's was ~1.5 to 11 MB, into a single transaction) is **structurally
impossible on BCH**. A full pairing verifier (F_p¹² tower arithmetic, Miller
loop, final exponentiation) will not fit in ~10 KB, and no amount of padding
buys enough op-cost budget within one input.

## Would the BSV or BTC solutions run on the BCH VM?

Set the resource limits aside for a moment and ask: do the prior solutions
depend on opcodes BCH lacks, or only on the limits BCH keeps? The answer differs
between the two in-Script approaches.

**BSV Groth16: opcode-compatible.** The BSV verifier is built from the "restored
arithmetic" opcodes (`OP_MUL`, `OP_DIV`, `OP_MOD`, the bitwise ops,
`OP_NUM2BIN`/`OP_BIN2NUM`) on unbounded numbers. BCH now has the same set:
`OP_CAT`, `OP_SPLIT`, `OP_DIV`, `OP_MOD`, `OP_AND`/`OP_OR`/`OP_XOR`,
`OP_NUM2BIN`, `OP_BIN2NUM` (re-enabled 2018); `OP_MUL` (2022);
arbitrary-precision integers (BigInt, 2025); and arithmetic/binary shift opcodes
plus `OP_INVERT` (CHIP-2025-05 Bitwise, active May 2026, which this repo's
[`math.cash`](math.cash) `<<`/`>>` compile to). It uses no BSV-exclusive opcode
and no Taproot construction (BSV and BCH share the pre-2018 Script lineage), so
with the limits disabled it would essentially run as-is. The limits, not any
missing instruction, are the whole problem this repo works around.

**BTC STARK: primitives port, Taproot packaging does not.** StarkWare's verifier
needs hashing and `OP_CAT`, and BCH has had both since 2018, so the
computational core needs no new opcode. (BTC must soft-fork to get `OP_CAT`, the
very change StarkWare's $1M research fund is lobbying for.) But the demo is
written in Tapscript and relies on Taproot machinery (taptree commitment,
`OP_CHECKSIGADD`, Schnorr key-path spends, an 11-transaction layout) that BCH
has no equivalent for, so it would need re-expressing in BCH's P2SH/script model
rather than porting verbatim.

So neither approach is blocked on BCH by a missing instruction, only by the
resource limits BCH retains. BCH's challenge is not "can the VM express it" but
"can it be made to fit," which is what forces the multi-step covenant design
below.

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
each step, but it lets total computation exceed any single transaction's budget
*without changing consensus*.

## Footprint and elegance

Is BCH's verifier smaller and more elegant than BSV's? Two separate claims, one
clearly true and one needing care.

**Contract bytecode is genuinely more compact.** BSV Script has no loops, so
sCrypt unrolls everything (the Miller loop, tower muls, and final-exponentiation
ladder copied out N times), which is the direct reason its verifier was ~1.5 to
11 MB. BCH's native loops put the loop body in bytecode once and re-execute it,
so the per-step contract is far more compact and readable. This is a claim about
space, not compute: the curve, algorithm, and field-operation count are
identical to BSV's, and a 64-iteration loop still costs 64 iterations of op-cost
budget.

**Aggregate footprint is likely smaller too, not larger.** Each BCH step is
hard-capped at the ~10,000-byte P2SH unlocking limit (which already includes the
redeem script, provided state, and signatures), so total footprint is bounded by
`N_steps × ≤10 KB`. The crossover against BSV is therefore roughly ~150 steps to
match the ~1.5 MB optimised transaction (and ~50 to match nChain's ~500 KB
locking script, though that mixes locking-script and whole-transaction
measurements, so treat it as order-of-magnitude). A well-tuned chunking
plausibly lands in the tens of steps, i.e. low-hundreds of KB total. The
per-step state-carrying overhead is small in bytes (~600 B of working state plus
a few hundred bytes of tx skeleton).

The real costs of the multi-step approach are therefore not aggregate bytes but
latency (one mempool/block hop per step), per-step fees and dust, and the
op-cost spent re-hashing the full state each step. The one number still unknown
is `N_steps`, which needs real compilation and op-cost measurement of
representative chunks to pin down.

## Comparison at a glance

| Chain / team | Proof system & curve | Where math runs | Single-tx? | Why this repo differs |
|---|---|---|---|---|
| **BSV** sCrypt 2022 (testnet to mainnet) | Groth16, BN256 | In-Script, native big-int, **no limits** | Yes (~11 MB to ~1.5 MB tx) | BCH keeps DoS limits, can't drop a multi-MB verifier in one tx |
| **BSV** nChain 2024 (mainnet) | Groth16, BLS12-381 | In-Script, native big-int, policy-compliant | Yes (<500 KB lock) | Same: no equivalent of BSV's unbounded single-tx budget on BCH |
| **BTC** StarkWare 2024 (Signet) | STARK (hash-based) | In-Script, requires `OP_CAT` | No (~11 txs, ~4 MB) | BCH has native arithmetic on mainnet; no soft fork / `OP_CAT` needed |
| **BTC** BitcoinOS 2024 | (Merkle Mesh) | **Off-chain** | n/a | BCH verifies in consensus, not off-chain |
| **BTC** BitVMX 2024 | STARK + Groth16 | **Off-chain + on-chain attestation** | n/a | BCH verifies the proof itself, no fraud-proof/challenge game |
| **BCH** this repo | Groth16, BN256 | In-Script, native big-int, **limited per tx** | **No, multi-step covenant** | Decompose across sequential NFT-covenant transactions |

## Takeaway

The earlier milestones answer a different question than BCH faces. BSV asked
"what if Bitcoin had no limits?" and answered with a single giant transaction.
BTC asked "what can we do without native arithmetic?" and answered with STARKs
on a testnet opcode, or with off-chain attestation. BCH is the only chain that
both **has native big-integer arithmetic on mainnet** *and* **keeps tight
anti-DoS limits**, so its unique contribution is showing that an in-consensus,
no-soft-fork Groth16 verifier is achievable by **decomposing the verifier
across a chain of stateful covenant transactions**, rather than by removing
limits or leaving consensus.

---

*Reference: Wei Zhang, [*Four First-Ever ZKP Verifications on Bitcoin*](https://medium.com/@w.zhang/four-first-ever-zkp-verifications-on-bitcoin-9475df11d57e), Medium.*
