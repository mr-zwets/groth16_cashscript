# PR6 grouped-affine component reference

This directory preserves the two existing repaired CashScript programs proved for
source PR6 (`0b5b2240cbb2f723a87dce2f43b92fc6f38e4b4d`). The windows `[0,21)`
and `[21,43)` are internal GLV loop positions in two component inputs. The exact
historical patch is included for provenance; apply it only to that historical
source, not to the current generator.

The current `../gen_vkx_glv.mjs` already implements equal-point doubling inside
`jacAddAffine`, introduced by `76f85727b1b91688b981239d5f7bbcc8cdf66330`. Its
current two-by-64 schedule differs from this frozen three-by-43 schedule. No old
fallback is added to the current generator and no current default program changes.
The legacy compiled proof does not automatically transfer to different programs.

## Mathematical boundary

Under the exact ordered graph, table, scalar/group and byte-channel premises in
`mathematical-scope.json`, the component computes the canonical affine coordinates
of `T = IC0 + n0*IC1 + n1*IC2` whenever T is finite. The range-bounded four GLV
components and the three shifted subset tables implement the stated scalar sum.
The repaired final addition covers `MSM = IC0` by doubling the original accumulator,
and `MSM = O` returns IC0. `MSM = -IC0` produces neutral T, outside this affine output
domain; the inverse check rejects it. This is a component theorem with explicit
interfaces, not a complete Groth16, producer, ledger-ancestry or admission theorem.

The first program owns its 132-byte input and binds its 228-byte output to the
second input. The final program requires the shared 2880-byte table and emits a
64-byte affine output into the stated 704-byte successor channel. Whole-graph
placement and successor ownership remain explicit premises. An imported component
alone does not establish those premises for a complete verifier.

## Reproduction without proof generation

The paired benchmark PR51 contains `artifacts/pr6-grouped-affine-reference/` with
the existing compiled programs, manifest and bounded archive-search result. Pass
its actual path; the two checkouts need not have particular directory names.

```sh
node chunked/pairing/pr6-grouped-affine-reference/verify.mjs /path/to/benchmark/artifacts/pr6-grouped-affine-reference
node chunked/pairing/pr6-grouped-affine-reference/rebuild.mjs --compiler-root=/path/to/cashscript --benchmark-dir=/path/to/benchmark/artifacts/pr6-grouped-affine-reference
```

The first command verifies identities and metadata only. The second compiles only
the two saved CashScript sources, in memory, with the pinned historical compiler
`1c707c1dbf87396b30ba5e0704b1db44475ce893`, `rescheduleStacks: true`, and the
recorded `75` padding-drop prefix. Each saved program therefore expects one extra
stack item on top of the CashScript arguments, consumed by that prefix; it is not
an additional declared CashScript parameter. It requires exact equality with the pinned
2244-byte and 2179-byte programs. It does not run a planner, prover, VM, witness
encoder, fixture writer or compiler-variant selection.

No matching archived full-verifier affine fixture was found in the searched set.
The related PR13/14 archive matches a different projective final program and
successor ABI. No replacement witnesses are generated or credited as validation.
Historical PR6 remains withdrawn, and this reference is not registered or ranked.
