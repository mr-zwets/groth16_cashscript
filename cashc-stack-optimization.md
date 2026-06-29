# Improving cashc's stack management

How CashScript's code generator could do more optimal stack placement / stack
management — diagnosis grounded in the actual compiler source
(`packages/cashc/src/generation/GenerateTargetTraversal.ts`) and validated by a custom
bytecode recompiler that cut the BN254 Groth16 singleton verifier from **14,641 → 9,730
bytes (−33.5%)** with no algorithmic change, purely by rescheduling stack operations.

Relevant upstream issues: **#393** ("add variable to stack right before first usage,
rather than at its definition") and **#217** (related stack-cleanup optimisation). The
analysis below shows #393 is one symptom of a deeper structural choice, and that fixing
the structure captures the bulk of the win.

## Evidence

Measured on the singleton verifier (`singleton/bn254/groth16.cash`), disassembling the
cashc output and recursively expanding the `OP_DEFINE` subroutine bodies:

- Of 14,641 bytes, ~3,172 B are genuine constant data (field moduli, VK points, NAF
  masks) — an irreducible floor — and ~11,469 B are opcodes.
- cashc's local peephole is already clean: **zero** removable adjacent no-op pairs.
- The opcode bytes are dominated by stack shuffling, and it is **concentrated in
  control-flow bodies**:

  | body type            | shuffle % of bytes |
  |----------------------|--------------------|
  | straight-line        | ~40%               |
  | loop / branch bodies | **82–87%**         |

  `millerSingle` (a `for` loop compiled with `OP_BEGIN`/`OP_UNTIL`): 4,039 B, **87%**
  shuffle — `1,075 OP_TOALTSTACK + 1,075 OP_FROMALTSTACK + 1,132 OP_SWAP`.

A custom decompile → reschedule → recompile pass (semantics-preserving, diff-tested per
subroutine against the originals and end-to-end against the real proof) reduced the worst
bodies dramatically with **no change to the math**:

| subroutine            | cashc | rescheduled |   Δ        |
|-----------------------|-------|-------------|------------|
| `millerSingle` (loop) | 4,039 | 1,098       | **−73%**   |
| id 44 (branch)        | 1,503 |   589       | **−61%**   |
| id 47 (loop)          | 1,174 |   549       | **−53%**   |

Whole contract: **14,641 → 9,730 B**, full verify green (accepts valid proof, rejects
tampered), op-cost 862M → 750M. The 9,730 B also drops under BCH's 10,000-byte standard
script-size cap (op-cost still over budget, so not yet one-input-standard).

## Root cause: variables are pinned to fixed stack homes

cashc models a symbolic stack of variable names (`this.stack: string[]`,
`getStackIndex = this.stack.indexOf`). Reads are already liveness-aware —
`visitIdentifier` emits `OP_ROLL` on a variable's final use and `OP_PICK` otherwise. That
part is good. The cost is in two places.

### 1. Reassignment bubbles the new value back to the variable's home slot

`emitReplace` (≈ line 643):

```ts
this.emit(encodeInt(BigInt(index)), locationData);
this.emit(Op.OP_ROLL, locationData);     // roll the old value to the top
this.emit(Op.OP_DROP, locationData);     // drop it
for (let i = 0; i < index - 1; i += 1) {
  this.emit(Op.OP_SWAP, locationData);   // bubble the new value down toward `index`
  if (i < index - 2) this.emit(Op.OP_TOALTSTACK, locationData); // park items above
}
for (let i = 0; i < index - 2; i += 1) {
  this.emit(Op.OP_FROMALTSTACK, locationData);                  // restore them
}
```

That is **~3·index ops per reassignment**, and the `TOALTSTACK … FROMALTSTACK` is
*literally* the 1,075 + 1,075 alt-ops measured in `millerSingle`. A Miller loop reassigns
`F` (12 limbs) + `R` (6) on every iteration, each to a deep home slot → this one method
produces most of the 85% shuffle in loop bodies. The source even flags it:

> `// This algorithm can be optimised for hardcoded depths`
> `// See thesis for explanation`

### 2. Why the bubble exists at all

At `scopeDepth === 0`, `visitAssign` does the *free* thing:

```ts
this.popFromStack();
this.pushToStack(node.identifier.name);  // just rename the top — zero bytecode
```

Inside an `if`/loop (`scopeDepth > 0`) it is forced into `emitReplace`, and
`visitIdentifier` is forced to `OP_PICK` even on a final use:

```ts
// If the final use is inside an if-statement, we still OP_PICK it
// We do this so that there's no difference in stack depths between execution paths
```

So the entire expense is a mechanism to keep **every variable at a position that is
identical across branches and across loop iterations**. The fixed home is how cashc
guarantees that determinism — and `getStackIndex` (and the debug/source-map machinery)
relies on it.

The custom recompiler beats this by *not* enforcing determinism per statement — it only
reconciles the physical layout at control-flow boundaries (IF/ELSE/ENDIF/UNTIL), and lets
values float in between. That deferral is the whole 33%.

## Tier 1 — local peephole, no architecture change (lands today)

Pure instruction-selection wins; each rippled through every body in the experiment.

- **1-byte ops for shallow access.** `visitIdentifier` / `emitReplace` always emit
  `encodeInt(i) + ROLL/PICK` (2 bytes). For small `i`, use the dedicated single-byte ops:
  `ROLL(1) → SWAP`, `ROLL(2) → ROT`, `PICK(0) → DUP`, `PICK(1) → OVER`; plus `NIP` / `TUCK`
  for the cleanup patterns. ~1 byte saved per shallow access, and shallow access is the
  common case.
- **Skip degenerate shuffles.** `ROLL(0)` and the empty tails of `emitReplace` emit bytes
  that do nothing.
- **Ship it as a bytecode post-pass.** The entire 33% reduction was achieved as a post-pass
  over cashc's *emitted output*. cashc could ship the same as an optional `--optimize`
  stage without touching the AST traversal — and it has *more* information than an external
  pass (it knows the variable structure directly, rather than recovering it by symbolic
  execution).

## Tier 2 — the structural fix (where the 33% really comes from)

Replace "fixed home + bubble-on-assign" with **deferred layout reconciliation**.

- **Let values float within straight-line regions.** Don't relocate on assignment — just
  update the name → position map (positions are *already* dynamic via `indexOf`; the only
  reason to bubble is cross-branch consistency). `x = f(x)` becomes: evaluate, drop the
  dead old `x`, rename the result. No bubble-down.
- **Reconcile only at join points.** At `else` / `endif` and the loop back-edge, emit a
  single permutation that makes the branch's exit layout match the canonical layout —
  instead of forcing every intermediate assignment to its home. The permutation is often a
  no-op when the schedule already aligns. (This is exactly "preserve the layout at block
  boundaries," which is what makes the whole thing sound.)
- **Altstack passthrough.** When loop-carried state sits on the altstack untouched through
  a block, leave it there — don't `FROMALTSTACK`/`TOALTSTACK` it every iteration. This one
  change took `millerSingle` from 1,711 → 1,098.
- **Schedule expressions Sethi–Ullman-style.** CashScript expressions are mostly trees;
  evaluating the heavier subtree first minimizes stack depth and shuffling. For the
  cross-statement DAG (reused variables) a list-scheduler with a locality heuristic — pick
  the ready value whose operands are nearest the top — does the rest.

This is precisely what **#393** asks for, as a special case: "materialize at first use, not
definition" falls out automatically once a value is only pushed when its consumer is
scheduled — and it generalizes to "place, move, and reconcile by liveness + schedule, not
by source position." **#217** (eager cleanup) likewise becomes free: dead values are
consumed by their final-use `ROLL` rather than accumulating and being swept later.

## Tier 3 — the function ABI

The fork's `OP_DEFINE` / `OP_INVOKE` model adds its own marshaling tax.

- **Inline tiny functions.** `fp2Add` is two real ops; the argument marshaling +
  `DEFINE`/`INVOKE` glue exceeds the body. An inlining heuristic (inline when body ≤
  call + marshal cost) helps directly, and inlined bodies then benefit from the Tier-2
  scheduler.
- **Scheduler-aware calling convention.** Pass arguments in the order they already sit on
  the stack where possible, instead of always reversing/staging to a canonical order.

## Caveats — constraints a real fix must respect

The fixed-home model isn't naive; it buys two things:

1. **Deterministic stack depth across branches**, which the symbolic stack and
   `getStackIndex` depend on. A scheduler must preserve branch-merge determinism — the
   boundary-reconciliation approach above does exactly this.
2. **Clean source-map / debug positions** (`finalStackUsage`, `sourceTags`). Once values no
   longer live at fixed slots, debug info has to track lifetime *ranges* rather than fixed
   points — more work on the debug side.

The control-stack-depth limit and the `OP_DEFINE`-body-as-data model also bound how
aggressively functions can be inlined or restructured.

## Suggested landing order

1. **Tier 1 peephole** — low risk, immediate bytes, ships as `--optimize`.
2. **Tier 2 join-point reconciliation** for `emitReplace` and loop bodies — the big lever,
   and the direct answer to #393 / #217.
3. **Tier 3** — inlining + calling convention.

A working reference implementation of Tier 2 — decompile → value-DAG → schedule → re-emit,
diff-tested per subroutine and end-to-end — exists as the `golf/` pipeline used to produce
the numbers above; it operates on cashc's own emitted bytecode and could be ported into the
compiler as either a post-pass or an IR scheduling stage.

## The floor: what's left after rescheduling, and which inefficiency is universal

Pushing the recompiler as far as it goes — both topological and greedy-locality schedules,
min-per-body, over all 52 subroutines — bottoms out at **9,724 B** (from 14,641; −33.5%),
verified end-to-end. Node-ordering is exhausted: greedy locality beats topological on only
one body (−6 B total), so smarter scheduling is *not* the remaining lever.

Bucketing every byte of the final 9,724-B contract (recursively through the `OP_DEFINE`
bodies):

| category                                   | bytes | %   |
|--------------------------------------------|-------|-----|
| depth-argument pushes (operand of ROLL/PICK) | 3,116 | 32% |
| constant data (moduli, VK points, NAF masks) | 2,406 | 25% |
| ROLL / PICK opcodes                        | 2,162 | 22% |
| 1-byte stack ops (SWAP/ROT/OVER/DUP/…)     |   547 |  6% |
| OP_INVOKE                                  |   442 |  5% |
| invoke-id pushes                           |   338 |  3% |
| altstack (TOALTSTACK/FROMALTSTACK)         |   198 |  2% |
| other / drop / define / headers / consts   |   515 |  5% |

The universal inefficiency is now unmistakable: **stack-access addressing —
`[depth-push][ROLL|PICK]` — is 3,116 + 2,162 = 5,278 B, 54% of the whole contract**, and
the depth-argument pushes alone (3,116 B) are the single largest category, larger than the
irreducible constant data. The altstack park/restore that dominated cashc's loop bodies is
essentially gone (198 B).

This is the floor of a *stack VM* for a register-heavy program, not a cashc-specific bug. A
pairing performs thousands of operand accesses over a deep working set (the Miller loop
alone carries ~25 live values: F[12] + R[6] + Q[4] + P[2] + counter). With no addressable
registers, every access pays to bring its operand to the top, and once the working set
exceeds 16 the depth argument needs 2 bytes instead of 1. In `millerSingle`, **276 of the
ROLL/PICK accesses are at depth > 16** (2-byte args) versus 75 shallow ones.

Two consequences for where to push next:

1. **Compiler-side (keeps the VM as-is):** the only lever left is *register allocation* —
   keep the hot working set shallow and spill cold, rarely-accessed values (loop
   invariants like `P`, `Q`, the NAF masks) out of the way, so the frequent accesses land
   at depth ≤ 16 (1-byte args). Quantified headroom: shrinking the > 16-depth accesses to
   ≤ 16 across the optimized bodies is on the order of ~500 B (contract → ~9.2 KB). Beyond
   that you are fighting the inherent O(depth) addressing of a stack machine.

2. **VM/language-side (removes the floor):** the deepest fix is to give the VM *addressable
   locals*. The single biggest line item in an optimal Groth16 verifier is not the field
   math or the constants — it is the `[depth-push][ROLL/PICK]` addressing tax, 54% here. An
   opcode set with indexed local variables (as JVM/WASM have, versus the stack-only
   DUP/SWAP/PICK/ROLL model) would collapse most of that 5,278 B. The fork's
   `OP_DEFINE`/`OP_INVOKE` functions are a step in this direction; per-function *indexed
   locals* would be the natural completion and would matter far more for ZK-scale contracts
   than any scheduling heuristic.

**Summary of the inefficiency taxonomy this exercise surfaced:**

- **Eliminated (cashc's biggest waste): `emitReplace` altstack park/restore in control
  flow** — was 2,150 alt ops in `millerSingle` alone, now ~0. Pure overhead, fully
  recoverable by deferred reconciliation (Tier 2). This is the 33% win.
- **Reducible (~500 B): access depth** — deep working sets force 2-byte depth args;
  recoverable by register-allocation-style shallow-layout + cold-value spilling.
- **Inherent (the real floor, ~5 KB here): stack addressing itself** — `ROLL`/`PICK` +
  depth argument for every operand fetch; only removable by VM-level addressable locals.
- **Irreducible (~2.4 KB): constant data** — field moduli, VK points, NAF masks.
