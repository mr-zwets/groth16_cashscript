# Reconstructed BN254 genpow assembly

This directory owns a readable low-level reconstruction of the published BN254
singleton genpow leader. `verifier.asm` contains all 62 function bodies and the
main program as explicit instructions, symbolic calls and named field constants.
`build.mjs` assembles that source; it does not read or patch an existing program.
The fixture files contain public proofs and inputs from the official benchmark.
They contain no locking bytecode or setup secrets.

With the repository's pinned @bitauth/libauth 3.1.0-next.8 installed, run:

```
node singleton/bn254/genpow-reconstructed/build.mjs /tmp/genpow-reconstructed
```

This is a direct assembly emitter, not a recovered CashScript compiler pipeline.
The original claimed `genpow-src`/stackcert replay sources were unavailable in the
pinned public repositories. Baseline assembly reproduces the official 4,292-byte
program with SHA256
`61c451d0bf8835e6ab850a02c325775d3769dbff92b87ba2d564c8f1f8494c83`
and the complete original vector objects. Its fixture origin is benchmark commit
`464722989363227e5cfc47bbe0d2f2e5a4053d95`.

Arithmetic names denote independently checked local interfaces, with stack order
bottom to top and all omitted prefix items preserved:

- `reduce_mod_p`: `[a] -> [a % P]`, using Script's signed remainder.
- `fp_mul`: `[a,b] -> [(a*b) % P]`.
- `fp_add`: `[a,b] -> [(a+b) % P]`.
- `fp_sub_top_minus_next`: `[a,b] -> [(b-a+P) % P]`.
- `fp2_mul`: `[a_imag,a_real,b_imag,b_real] -> [real,imag]`.
- `prime`: `[] -> [P]`; former prime-pair callers append `OP_DUP`.

The canonical Fp2 interpretation requires canonical inputs; the source preserves
all original call sites and guards. The remaining `outline_N` names deliberately
identify exact compiler outlines without claiming unproved high-level semantics.
Each body remains readable opcode source, including its exact stack scheduling.
The main program retains proof/public-input checks, embedded public-VK constants,
Miller arithmetic, exact `(P^12-1)/R` derivation, and generic final exponentiation.

Byte equality and a local rewrite proof establish preservation relative to the
published artifact. They are not a new universal proof of that artifact's subgroup
or malformed-point semantics. The official adapter provides no isolated point
validation cases, and the relaxed singleton VM is not a native BCH resource gate.

The P-sharing candidate changes only two literal-P sites into calls to `prime`,
changes the former `prime_pair` definition from ID47 to the unused ID0, and adds
DUP at its two static callers. This yields 4,228 locking bytes, SHA256
`a7686356eba90eb594d2a05189e645111506e67fc3c52007144081761d357cd0`.
The committed relaxed-VM cost rises from 5,206,615,819 to 5,505,565,336.
The benchmark score is 4,587 bytes including its unchanged 272-byte witness and
87-byte transaction overhead. Full official gates and independent review must
accompany any promotion; byte equality alone is insufficient.

Run the standalone reverse-expansion certificate:

```
node singleton/bn254/genpow-reconstructed/prove-prime-sharing.mjs
```

It compiles the current source, checks the constant's entire body, restores exactly
two literal-P sites and two prime-pair callers, and requires the complete restored
program to match the pinned official hash. Thus all other code, including the
original verification predicates, is fixed. The additional invocation changes
resource accounting and call depth; the equivalence claim is about stack values
and predicates, conditional on execution resources. It does not prove that every
possible witness fits a limit waived by the official singleton environment.
