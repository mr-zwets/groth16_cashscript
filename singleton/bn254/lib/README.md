# BN254 singleton libraries

Shared CashScript libraries for the BN254 Groth16 verifier, consumed by the contracts in the parent
directory (`../*.cash`). These rely on the custom cashc fork's `library` / `import` / global-`constant`
support (branch `feat/reusable-functions`).

## `library` vs `contract` — the important distinction

There are two kinds of `.cash` file, told apart by the **keyword inside**:

| Keyword | Where | Has `spend()`? | Deployed / graded? | Purpose |
|---|---|---|---|---|
| `library Name { … }` | here, in `lib/` | no | no | reusable functions + constants, only ever `import`ed |
| `contract Name { … }` | parent dir, e.g. `../groth16.cash` | yes | yes | the actual top-level contract; imports libraries |

So `../groth16.cash` is a **`contract`** (the full verifier, with `spend()`) that `import`s three
libraries. Each parent-directory `*.cash` is now the library-based contract (the older inline versions
that re-declared the whole field tower have been replaced). Libraries live in this folder and use the
`library` keyword; they have no `spend()` and are never deployed alone.

## The two arithmetic schemes

The hand-written sources use two different field-arithmetic conventions, so there are two towers:

- **Reduced** (`lib/*.cash`): `addFp`/`subFp` reduce mod p; standard signatures. Used by almost
  everything.
- **Lazy** (`lib/lazy/Bn254Lazy.cash`): `addFp(x,y)=x+y` and `subFp(x,y,k)=x-y+k*p` do **not** reduce
  (only `mulFp` does); a per-call-site `k` bias is threaded through the subtractive ops. Different
  arities, so it cannot share the reduced tower. Used only by the two performance-critical loops
  (`miller`, `finalexp`).

The two towers deliberately reuse the same function *names* (`addFp`, `fp2Mul`, …). That's safe because
a contract imports exactly one tower, so the names never collide.

## Reduced tower — dependency graph

```
Fp.cash            base field Fp; defines `int constant P` (the field prime)
 └─ Fp2.cash       Fp2 = Fp[u]/(u^2+1)        imports Fp
     └─ Fp6.cash   Fp6 = Fp2[v]/(v^3-xi)      imports Fp2   (+ fp6Mul01 for mul034)
         └─ Fp12.cash   Fp12 = Fp6[w]/(w^2-v) imports Fp6   (+ mul034, frobenius, inverse)
             ├─ Miller.cash    G2 point/line ops, line, psi, millerSingle, g2 subgroup check
             └─ FinalExp.cash  cyclotomic squaring/exp, final exponentiation
G1.cash            G1 (Fp) Jacobian group law + scalar mult (vk_x)   imports Fp
```

`import` is transitive and the diamond (e.g. `Fp` reached via several paths) is de-duplicated by the
compiler. **Tree-shaking** then drops every library function a given contract never calls, so importing
a big tower costs only the bytecode actually used.

## What each consumer imports

| Contract (`../*.cash`) | Imports | What it exercises |
|---|---|---|
| `fp2` | `Fp2` | Fp2 mul/sqr/inv/mulXi/conj |
| `fp6` | `Fp6` | Fp6 mul/sqr/mulByV |
| `fp12`, `fp12_inv`, `fp12_frob` | `Fp12` | Fp12 mul/sqr/conj, inverse, Frobenius |
| `mul034` | `Fp12` | sparse line multiply |
| `g2lines` | `Miller` | pointDouble / pointAdd |
| `miller4` | `Miller` | 4-pair Miller product |
| `verify` | `Miller`, `FinalExp` | 4-pair pairing == 1 |
| `groth16` | `Miller`, `FinalExp`, `G1` | **full Groth16 verifier** |
| `vkx`, `vkx_jacadd` | `Fp` | G1 arithmetic (inlined in spend) |
| `miller`, `finalexp` | `lazy/Bn254Lazy` | lazy-scheme Miller loop / final exponentiation |

## Adding / verifying a consumer

A consumer is just: `pragma`, the `import`s it needs, and a `contract` with only its `spend()`:

```cash
pragma cashscript ^0.13.0;
import "./lib/Fp12.cash";
contract Foo() { function spend(...) { ... fp12Mul(...) ... } }
```

Grade any contract against its reference vectors with its harness:

```sh
node ../X.mjs          # e.g. node ../groth16.mjs   -> prints PASS/FAIL
```

(`vkx` is graded by `build_vectors_vkx.mjs` with constructor binding; set `OUT=/tmp/…` so it doesn't
overwrite the verifier repo's vectors.)

Compile to bytecode/size with the fork's CLI:

```sh
node <cashscript>/packages/cashc/dist/cashc-cli.js ../groth16.cash -h   # hex
node <cashscript>/packages/cashc/dist/cashc-cli.js ../groth16.cash -s   # bytesize
```

## Why this is a win

Every original `*.cash` harness re-declared the entire field tower inline. These libraries hold one
canonical copy; the contracts shrink to their `spend()`. Where the originals were byte-for-byte
consistent, the library build is **byte-identical** (`fp2`, `fp6`, `fp12`, `mul034`, `vkx`); where they
had value-equal micro-variants, it consolidates them to one implementation (verified by the graders).
