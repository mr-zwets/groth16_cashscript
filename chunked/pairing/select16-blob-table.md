# `select16`: off-stack blob table vs. an `if/else` cascade

This note explains a non-obvious optimization in [`gen_vkx_glv.mjs`](./gen_vkx_glv.mjs): the
GLV `select16` lookup is emitted as a **byte-blob table read by a runtime `split`** instead of a
15-deep `if/else` cascade. The two produce identical results, but the blob is ~74% cheaper in
op-cost. It is easy to misread the blob form as "an array, which `arrays.md` says is slow," so the
reasoning is documented here.

## What `select16` does

The GLV vk_x MSM is a 4-scalar ~128-bit Straus loop over the fixed base points
`{IC1, phi(IC1), IC2, phi(IC2)}`. Each of the 128 iterations forms a 4-bit window index
`idx ∈ 0..15` (one bit from each sub-scalar) and must add the precomputed subset-sum point

```
table[idx] = sum of BP[i] for each bit i set in idx        (idx = 1..15; idx 0 = skip)
```

These 15 points are **baked constants** (proof-independent — they depend only on the verification
key). `select16(idx)` returns `(aX, aY, doAdd)`: the selected point, plus `doAdd = 0` for `idx = 0`
(the identity, no addition). It runs once per Straus iteration → **128 times per vk_x**, across the
~5 chunks the stage is split into.

## The original form: a linear `if/else` cascade

```solidity
internal function select16(int idx) returns (int, int, int) {
    int aX = 0; int aY = 0; int doAdd = 0;
    if (idx == 1) { aX = <x1>; aY = <y1>; doAdd = 1; } else {
      if (idx == 2) { aX = <x2>; aY = <y2>; doAdd = 1; } else {
        ...                                    // 15 levels deep
}}}}}}}}}}}}}}
    return aX, aY, doAdd;
}
```

This is correct but expensive. On the BCH 2026 op-cost model, the dominant cost is **not** the
two 32-byte data pushes for the selected point — it is the **branch dispatch**. A lookup for `idx`
walks `idx` comparisons (`idx == k` → `OP_NUMEQUAL` + `OP_IF`), descending through the nested
`else` blocks. Averaged over the uniformly distributed `idx ∈ 0..15`, that is ~8.4 comparisons per
lookup, ~1,075 comparisons over the 128-iteration loop.

## The new form: a blob table + runtime `split`

```solidity
internal function select16(int idx) returns (int, int, int) {
    int aX = 0; int aY = 0; int doAdd = 0;
    if (idx != 0) {
        bytes table = 0x<960 bytes>;                       // 15 entries x 64 bytes
        bytes ent = table.split((idx - 1) * 64)[1].split(64)[0];   // O(1) indexed slice
        aX = int(ent.split(32)[0]);
        aY = int(ent.split(32)[1]);
        doAdd = 1;
    }
    return aX, aY, doAdd;
}
```

The 15 entries are concatenated into one 960-byte literal (`entry (idx-1) = x(LE32) || y(LE32)`,
built by `le32`/`TABLE_HEX` in the generator). The lookup is a single indexed slice — no branching,
no comparisons. `idx = 0` is still a cheap one-comparison guard (returns the identity / `doAdd = 0`).

## Measurements (micro-benchmark, 128 lookups, real BCH 2026 cost model)

| variant | bytes | op-cost | vs. cascade |
|---|---:|---:|---:|
| linear cascade (old) | 1,338 | 4,765,836 | — |
| balanced binary tree (≤4 compares) | 1,347 | 4,879,597 | **+2.4%** |
| **blob table + runtime `split` (new)** | 1,106 | 1,228,236 | **−74.2%** |
| O(1) floor (push one entry, no branch) | 161 | 1,202,812 | −74.8% |

Two things to notice:

- **The blob lands on the O(1) floor** (1.23M ≈ 1.20M). The runtime `split` captures essentially
  the entire dispatch saving (~3.56M op, 74.8% of the select loop) — the same result a true
  function-factory `OP_DEFINE`-table / `idx OP_INVOKE` would give, but using only current CashScript
  (`bytes.split` at a runtime index). No CHIP / compiler-fork change is required.
- **The balanced binary tree is *worse* (+2.4%)**, which is counterintuitive. Even though it does
  ~4 comparisons instead of ~8, each level is a nested `if/else` whose `OP_IF`/`OP_ELSE`/`OP_ENDIF`
  control structure costs more per executed level than the linear chain's cheap early-outs. The only
  way to beat the cascade is to remove the branching entirely.

The core insight: **on this VM, conditional dispatch is expensive and pushing/slicing constant data
is cheap.** A 16-way branch is the wrong tool; an indexed read of a packed blob is the right one.

## Why this does not contradict `arrays.md`

[`arrays.md`](../../arrays.md) argues byte-string arrays are a poor trade in the hot path. That
analysis is correct **for its case**: compile-time-indexed tower arithmetic (`Fp12` multiply /
square / Frobenius), where the index is known statically and the alternative — keeping coordinates
in named locals at fixed stack positions — avoids all split/concat overhead. `select16` is the
opposite case: the index is a genuine **runtime** value and the alternative is a **16-way branch**,
not fixed locals. When the comparison is "blob slice vs. deep conditional tree" (not "blob slice vs.
named locals"), the blob wins decisively. Same primitive, opposite conclusion — because the access
pattern is different.

## Correctness

- **Encoding.** Each coordinate is a field element in `[0, P)`. It is stored as a fixed 32-byte
  little-endian value. This is sign-safe: `P < 2^254 < 2^255`, so the sign bit (bit 7 of the
  most-significant LE byte) is always clear, and `int()` (`OP_BIN2NUM`) recovers the value as a
  positive number. 32 bytes is therefore sufficient (no 33-byte padding needed).
- **`idx = 0`.** Handled by the `if (idx != 0)` guard; the defaults `(0, 0, 0)` mean `doAdd = 0`,
  i.e. the caller skips the addition — identical to the cascade.
- **Validated against the JS reference.** The generator's `measureCovenant` checks each chunk's
  output against `vkxGlvStateAt` (the JS Jacobian MSM that reads the same `TBL`). The non-final
  chunks regenerate `accepted = true`, which means the blob recovers the exact same points as the
  old cascade. (The final chunk reports `accepted = false` standalone for an unrelated reason — its
  vk_x cross-bind is only satisfiable in the full multi-input/grouped context — and that is
  pre-existing, not caused by this change.) The downstream residue builds (`grouped-residue`,
  `intratx-residue`) accept and reject invalid runs as before.

## Impact (and honest limits)

- **GLV stage:** 29.13M → 26.77M op (**−8%**); chunk lockings a few bytes smaller.
- **`intratx-residue`:** 262,604 → 260,097 B; 201.99M → 198.77M op (still 33 inputs).
- **`grouped-residue`:** still 3 transactions, but the tightest group's worst-case dropped
  99,051 → 95,406 B — the margin under the 100,000 B standardness cap improved from ~950 B to
  ~4,600 B (more robust packing).

It does **not** reduce the GLV chunk count (still 5), for two reasons worth recording so nobody
expects it to:

1. The select dispatch is only ~8% of the **per-iteration** cost — `jacDouble`/`jacAdd` field
   arithmetic dominates each Straus step, so removing the lookup is a real but small slice.
2. The 5th chunk is **structural**, not op-bound: the final chunk does the `IC0` add + `zInv`
   finalization and is always forced into its own window by the planner (its standalone
   `accepted = false` cross-bind makes the planner's `fits` check fail for any final window). Even
   with the freed op-budget headroom, the planner cannot merge the last iterations into it. Dropping
   5→4 is a separate *planner* change (plan final windows by op/bytes, ignoring the benign
   standalone-accept artifact), and even then it would only shave ~1 input — not a transaction —
   since `grouped-residue` is byte-bound at 3 tx.

## Where else this technique applies

Any **runtime-indexed lookup into a fixed, baked table** is a candidate: prefer a packed-blob slice
over a conditional cascade whenever the index is a runtime value and the entries are constants. It is
*not* a win for compile-time-indexed access (tower coordinates), where named locals remain cheaper
(see `arrays.md`). In this codebase `select16` is the only such runtime-indexed table; the Miller
loop's baked line coefficients are consumed sequentially (one per unrolled step), not by a runtime
index, so they are not candidates.
