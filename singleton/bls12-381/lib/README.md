# BLS12-381 singleton libraries

Shared CashScript libraries for the BLS12-381 Groth16 verifier, consumed by the contracts in the
parent directory (`../*.cash`). They rely on the custom cashc fork's `library` / `import` support
(branch `feat/library-support`). Mirrors the bn254 singleton (`../../bn254/lib/`).

## Why a `contract` per layer

The full verifier is `../groth16.cash`. The other parent-directory contracts (`fp2`, `fp6`, `fp12`,
`mul014`, `g2lines`, `miller`, `miller4`, `finalexp`, `verify`, `vkx`) are **per-layer test harnesses**:
each is a small `contract` whose `spend()` exercises only that one layer's operations and is graded
against the reference implementation (`@noble/curves`) by its `.mjs`.

Keeping one gradable contract per layer buys:

- **Pinpointed failures** — verifying bottom-up (Fp2 → Fp6 → Fp12 → Miller → FinalExp → full verifier),
  a break surfaces in the smallest failing layer instead of only at the ~20 KB / ~M-opcode end product.
- **Fast, isolated tests** — check an Fp2 multiply without running the whole pairing.
- **Per-layer size / op-cost** — each compiles on its own, so a layer's cost is measurable in isolation.

The libraries are what make this cheap: every harness *and* the full verifier share one implementation
from `lib/`, so a layer is written (or fixed) once and all of them pick it up. Files in `lib/` use the
`library` keyword (no `spend()`, never deployed); the parent-directory files use `contract`.

## Differences from bn254

- **One arithmetic scheme.** Every BLS contract uses reduced arithmetic (`addFp`/`subFp` reduce mod p),
  so there is a single tower — no separate "lazy" library (bn254 needed one for `miller`/`finalexp`).
- **Six libraries, no `G1`.** The vk_x G1 Jacobian scalar-multiply is *inlined* in the `groth16` and
  `vkx` spend functions (CashScript can't yet return the 3-coord points as tuples), so there is no `G1`
  library — those contracts just `import Fp`.
- **No `psi`.** The BLS Miller loop has no untwist-Frobenius post-precompute step.
- **Different field constants.** BLS prime, Fp6 non-residue `xi = u+1` (not `9+u`), M-twist sparse
  multiply `mul014` (not `mul034`), BLS seed, and Frobenius/twist constants — all baked into the
  function bodies in the libraries.

## Dependency graph

```
Fp.cash        base field Fp (6 fns: add/sub/mul/sqr/neg/inverse)
 └─ Fp2.cash   Fp2 = Fp[u]/(u^2+1)         imports Fp   (11 fns)
     └─ Fp6.cash   Fp6 = Fp2[v]/(v^3-xi)   imports Fp2  (12 fns: + sparse mul01/mul1, frobenius, inverse)
         └─ Fp12.cash   Fp12 = Fp6[w]/(w^2-v)  imports Fp6  (8 fns: mul/sqr/conj/inv/frob1-3 + mul014)
             ├─ Miller.cash    pointDouble/pointAdd, line, millerSingle   (4 fns)
             └─ FinalExp.cash  fp4Square, cycSqr, cycExpX, powMinusX, finalExp  (5 fns)
```

`import` is transitive and de-duplicated; **tree-shaking** drops every library function a contract
never calls, so importing a tower costs only the bytecode actually used.

## What each consumer imports

| Contract (`../*.cash`) | Imports | vs original |
|---|---|---|
| `fp2` | `Fp2` | byte-identical |
| `fp6` | `Fp6` | byte-identical |
| `mul014` | `Fp12` | byte-identical |
| `fp12`, `fp12_inv`, `fp12_frob` | `Fp12` | value-equivalent (graded) |
| `g2lines` | `Miller` | value-equivalent |
| `miller`, `miller4` | `Miller` | value-equivalent |
| `finalexp` | `FinalExp` | value-equivalent |
| `verify` | `Miller`, `FinalExp` | value-equivalent |
| `groth16` (full verifier) | `Miller`, `FinalExp` | value-equivalent (smaller: 19699 B vs 19852 B) |
| `vkx` | `Fp` (G1 inlined) | value-equivalent |

"Value-equivalent" means the bytecode differs from the old inline version (the libraries consolidate
value-equal micro-variants such as `negFp` vs `subFp(0,x)` to one canonical implementation), but every
contract is graded accept-valid / reject-invalid against its `.mjs` harness.

## Grade / compile

```sh
node ../X.mjs    # e.g. node ../groth16.mjs   -> PASS/FAIL  (vkx: build_vectors_vkx.mjs)
node <cashscript>/packages/cashc/dist/cashc-cli.js ../groth16.cash -s   # bytesize
```

## Obsolete: `assemble.mjs`

`../assemble.mjs` used to *generate* `verify.cash` / `vkx.cash` / `groth16.cash` by extracting and
concatenating `internal function` bodies from `finalexp.cash` + `miller4.cash` — a manual stand-in for
the library system. Those source files are now thin consumers (their functions live in `lib/`), so
`assemble.mjs` no longer works and is superseded by this folder. It can be deleted.
