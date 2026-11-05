# Source4 connected-covenants reference

This directory is the single source owner for the corrected BN254 48-stage and
BLS12-381 86-stage covenant graphs. `source/`
contains the shared source/import closure; `generated-bn-v1/` contains the
generated BN254 stage sources. The compiled program catalog is owned separately
by `artifacts/pr4-connected-reference/compiled-catalog.json` in the paired benchmark repository and must contain each program
bytecode once, together with its source, ABI, and successor-lock hashes.

The correction preserves the existing proof and public-input fixtures and is
intended to bind the complete declared state ABI at each handoff. In
particular, BN254 stage 34 emits and stage 35 consumes 28 limbs; BLS stage 63
commits its 12 boundary limbs on input while carrying 12 inverse witnesses as
spend arguments; later BLS final-exp stages commit every declared live register
pair. Publication requires the paired theorem-transfer certificate and a
catalog whose bytecode, ABI, and successor bindings pass the fixed-policy
rebuild; this source directory alone is not that certificate.

The source is finite-coordinate and fixed-key qualified. It does not claim
unrestricted infinity, arbitrary-verification-key, or universal mainnet
resource admission. See the artifact qualification and replay records for the
existing-positive VM evidence and byte-size holds.

This source-only closure contains the 48 corrected BN254 programs, 86 corrected
BLS12-381 programs, and only the CashScript libraries required by their relative
imports. Package manifests, lockfiles, node modules, generators, and runtime
copies are intentionally excluded.

Rebuild using explicit source, artifact, and compiler owners:

```sh
node rebuild-fixed-policy.mjs --source-root SOURCE_DIRECTORY --catalog BENCHMARK_ARTIFACT_DIRECTORY/compiled-catalog.json --compiler-root CASHSCRIPT_CHECKOUT --receipt OUTPUT_RECEIPT
```

The fixed original policy uses raw compilation at BLS stages79/81/83/84 and stack rescheduling for the other130 programs. The pinned compiler package, entry and loaded compiler module are checked before import. No compiler-variant search is performed. The paired receipt reproduces all134 exact source/program/ABI/successor bindings.
