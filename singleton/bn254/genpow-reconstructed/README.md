# Reconstructed BN254 genpow assembly

This directory owns a readable low-level reconstruction of the published BN254
singleton genpow leader. `verifier.asm` contains all 69 function bodies and the
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

Public-input range check (Oct 16, 2026): main now starts with a 32-byte check that both
claimed public inputs are canonical scalars, 0 <= n0, n1 < r. Without it n + r gives the same
vk_x, so one proof verified for two different claimed integers (the bench's public-input gate
accepted n0 + r and n1 + r). It builds r as P - 6x^2 from the shared `prime` function and the
G2 subgroup scalar already in the program. Locking: 4,260 bytes, SHA256
`6d884ee69b1ec0f6b20e749d64422a4f0c779f756a1b01bb1b8edb9b40836e80`.
`prove-prime-sharing.mjs` checks that prefix exactly, strips it and runs the reverse
expansion proof on the remaining 4,228-byte program. The witness (272 bytes) and the
87-byte transaction overhead are unchanged. Full official gates and independent review must
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

Duplicate-body sharing (Oct 17, 2026): `outline_17` and `outline_9` had identical
instruction bodies and identical static `fp_mul` targets. The current assembly
removes definition 17 and retargets five calls to definition 9; all other IDs and
instructions stay exact. This reduces locking bytecode from 4,260 to **4,242 bytes**
and the committed singleton score from 4,619 to **4,601 bytes**. The witness and
public values remain unchanged. This improves singleton size and cost; it does
not establish BCH input-budget compliance or stronger point-validation semantics.

The standalone certificate first restores the duplicate definition and its five
calls, requiring the exact 4,260-byte range-checked hash above. It then performs
the existing range-prefix and prime-sharing reverse expansion to the official
4,292-byte artifact. The current program is assembled directly from its readable
source; the reverse expansion is a separate verification step.

Compact namespace-ID packing (Oct 18, 2026): `outline_18` uses the proven-unused raw
ID `-1`, encoded as the one-byte `OP_1NEGATE`, while all other IDs retain the original
non-negative byte-domain and uniqueness checks. Its five static call sites are rewritten
back to ID 18 in the certificate before any duplicate-body expansion. This isolates the
exact 4,242-byte control with SHA256
`8537de8922c6e4711357e4390fd0e1a2006015a16e7b93a7f1d5a88c7d0d58a2`; the next stage
restores `outline_17` and its five calls to obtain the exact 4,260-byte range-checked
hash `6d884ee69b1ec0f6b20e749d64422a4f0c779f756a1b01bb1b8edb9b40836e80`. The existing
range-prefix removal and P-sharing expansion then produce the 4,228-byte post-sharing
candidate and the pinned 4,292-byte historical artifact. This remains a relaxed-VM
singleton and does not claim BCH-native input-resource admission.

Matched current public measurements retain the 32-byte range check in both
programs: baseline 4,619 bytes / 5,505,567,176 relaxed VM cost; duplicate sharing
4,601 bytes / 5,505,566,861. The duplicate-sharing improvement is **18 bytes and
315 cost units**. The current compact-ID candidate is 4,236 locking bytes plus the
unchanged 272-byte witness and 87-byte overhead: **4,595 total bytes** and
5,505,566,856 relaxed VM cost, improving the 4,601-byte control by **6 bytes and
5 cost units**. The historical 4,587-byte figure precedes that range check and is
not this comparison's baseline. Four supplied proofs, the original invalid proof
and all nine current public-input mutations pass the unchanged official gates.

TW static frontier (Oct 18, 2026): `outline_65=13` shares eleven exact
`OP_6 OP_ROLL OP_7 OP_ROLL` sequences and moves `outline_13` to raw key `47`.
The candidate has 64 functions, 4,217 locking bytes, and SHA256
`6229f2e5784b8f78c7b89fc6075c8de37a4ab9938bb04eb244459a4fa5a07bf6`. An actual
decoded inverse expands `outline_65`, restores the published 4,225-byte program
byte-for-byte, and preserves the 32-byte range prefix. Runtime cost and proof
gates remain separate release evidence.

G1 parity compression (Oct 18, 2026): the normal build CLI exports A/C y pushes
2 and 8 as parity bits, preserving each original x and every other witness push.
The archived fixture files keep their original coordinates. The encoder requires
canonical y and checks the original on-curve equation before discarding y; one
encoder owns both primary and multiproof exports. No proof or public-input
integer is regenerated.

`g1_decompress` maps `[parity,x]` to `[canonicalY,originalX]`. It shares the
original 254-step `fp_pow` loop with inversion in the UY profile, computes a square-root candidate
using `(P+1)/4`, verifies its square against the original reduced curve equation,
and selects the requested parity. The final parity check rejects signs outside
0/1 and parity 1 for a zero root. The decoder adds no x canonicality restriction.
This codec is reversible for canonical G1 coordinates; it does not preserve the
old unrestricted integer or byte-string language. Its root check owns the two
removed standalone A/C on-curve predicates. The public scalar guard, G2 checks,
and later arithmetic remain unchanged.

The UY parity profile uses 4,232 locking bytes plus a 208-byte witness and 85-byte overhead:
4,525 total, 32 bytes below the 4,557-byte UE control. Static recovery of the
unchanged arithmetic and direct decoder VM cases are separate from whole-proof
qualification. This remains relaxed BCH VM research; neither the byte saving nor
decoder checks establish native consensus or relay compatibility. Historical
reverse-expansion certificates above describe their respective earlier stages.

Exponent-driven power (VG, Oct 18, 2026): the shared `fp_pow` routine now shifts
the remaining exponent until zero. Its loop state `[p,r,b,e]` preserves
`r * b^e = a^E (mod p)`, starting with `r=1` and `b=a mod p`. Each iteration
conditionally multiplies `r` by `b`, squares `b`, and shifts `e` right by one.
Both call sites construct fixed positive exponents below `2^254`: `P-2` for
inversion and `(P+1)/4` for square roots. Multiplication order matches the old
loop; unused trailing squares and the explicit iteration counter are removed.
The zero-exponent case returns one. All other 68 function bodies, identifiers,
the main program, scalar guard, decoder and archived witnesses remain exact.

The current program has 4,223 locking bytes, a 208-byte witness and 85-byte
transaction overhead: **4,516 total**, nine bytes below UY. Its locking SHA256 is
`11562df7a32468c8417741d5a512709fbe5184edb49b538e388671e8a7cdf3e5`.
Independent mathematical review and direct VM cases cover the loop boundary;
whole-verifier proof and cost measurements are recorded separately by the
release jobs. This remains relaxed-VM research with the same canonical G1
witness representation and existing subgroup posture.
