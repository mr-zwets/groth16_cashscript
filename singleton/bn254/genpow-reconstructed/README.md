# Reconstructed BN254 genpow assembly

This directory owns a readable low-level reconstruction of the published BN254
singleton genpow leader. `verifier.asm` contains all 72 function bodies and the
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

## Current default export

The default `bytes` profile emits **4,152 locking bytes**, a **208-byte primary
witness**, and **85 bytes of transaction overhead**: **4,445 bytes total**.
Locking SHA256:
`0e2ec0dc2ba7c23307385b6b742f89903c278c5ab095561a4350914953c65b2f`.
The same normal builder command above exports both the single-proof and
multiproof vectors; both use this exact program. The manifest records the
source hash, each function body and the selected profile. There are 72 function
bodies in the default profile. Primary relaxed-VM operation cost is 5,516,859,822.

The final Fp12 exponent loop now shifts its remaining exponent instead of
shifting the original exponent by an incrementing bit index. The exponent is
still derived exactly as `(P^12 - 1) / R`; its 2,790 bits and 1,376 set bits
produce the same multiply/square schedule. The unused counter stack slot remains
to preserve every field-helper stack index. All 72 function bodies and identity checks stay exact. The earlier loop update
saved nine program bytes and 2,732,478 primary op-cost against the 4,183-byte
program. The current verdict tail also removes eleven depth-10 rolls: rotating
the top eleven items eleven times is identity. The following depth-11 roll
remains and preserves the short-stack rejection boundary. This saves another
22 program bytes and 2,321 primary cost units.

A and C use x plus a one-bit y parity, replacing their full y coordinates
(primary witness: 272 -> 208 bytes). The verifier recomputes y from
`sqrt(x^3 + 3)`, checks the curve equation and requested parity, and retains the
public-input range check. This changes the accepted witness representation;
canonical G1 coordinates round-trip, but unrestricted byte-string equivalence
is not claimed. Archived fixture coordinates remain unchanged. The detailed
codec and exponent-loop contracts below still apply.

The old standalone reverse-expansion script targeted a historical 61-function,
4,236-byte stage. It does not certify the present 72-function program and has
been removed; its historical implementation remains in Git history. Current
reproduction is the source-owned builder and manifest above, with exact
single-proof/multiproof artifact comparison and separate public VM gates. These
checks do not constitute a universal equivalence or soundness certificate.

## Factored alternate export

```
node singleton/bn254/genpow-reconstructed/build.mjs /tmp/genpow-factored factored
```

The `factored` profile emits **4,408 locking bytes**, the same **208-byte witness**,
and **85 bytes overhead**: **4,701 bytes total**. Primary relaxed-VM operation
cost is **2,049,440,569**, compared with 5,516,859,822 for the 4,445-byte default.
It spends 256 more bytes for about 63% less cost. Locking SHA256:
`955865f3ea49d9f93e0fb378b7d4f79944dac398c5eada1d8f8cd1cc5a76813d`.
Both tradeoffs remain available; the default does not use the new field predicate.

Let `r=P-6u^2`, `H=(P^4-P^2+1)/r`, `g=f^H`, and `h=Frob2(g)*g`. For canonical
`f` in Fp12, `f^((P^12-1)/r)=1` iff `h` is a nonzero element of Fp6. The profile
checks the upper six limbs of `h` are zero and at least one lower limb is nonzero.
The explicit nonzero condition rejects `f=0`; no field inverse is needed.

The existing P/r derivation computes H directly instead of the full exponent.
The unchanged generic multiply/square loop owns exponentiation, with a second
exponent-one call computing the final product. Frobenius uses one shared root
`t=18u^3+18u^2+9u+1` and the diagonal
`1,1,-(t+1),-(t+1),t,t,-t,-t,-1,-1,t+1,t+1`. Three helpers are added to the
original 72 bodies, giving 75 functions. `build.mjs` owns these source-level
statements and the guarded main transformation; it does not patch old bytecode.

All twelve incoming final-field limbs must satisfy `0 <= limb < P`. This can
reject noncanonical encodings accepted by the previous relaxed program. The
canonical guard, existing proof/input/G2/Miller code, and original proof,
witness and public values are fixed in the qualification cohort.

Independent checks cover the exact Fp12 multiply/square polynomial on canonical
limbs, nonnegative modular-reduction intervals, and Frobenius coefficients from
an independent quotient-ring basis. Actual native helper kernels cover the
field basis, Frobenius, both exponent constants, canonical boundaries and the
nonzero predicate. Whole-verifier validation uses the published relaxed VM:
four fixed valid proofs pass, four fixed invalid witnesses and nine generic
public-input mutations reject. These establish the stated finite corpus and
conditional final-field identities, not universal Groth16 soundness or input
validation. Both profiles exceed current native resource limits; no bch-spec
admission is claimed. Existing security/input-validation grades stay unchanged.

## Historical derivation

The measurements and inverse descriptions below belong to the named historical
stages. They are retained as provenance, not as current build instructions or
current-profile measurements.

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
At that historical stage, a reverse-expansion check stripped the exact prefix
and checked the remaining 4,228-byte program. The witness (272 bytes) and the
87-byte transaction overhead are unchanged. Full official gates and independent review must
accompany any promotion; byte equality alone is insufficient.

That historical check verified the constant's entire body, restored two
literal-P sites and two prime-pair callers, and compared the complete restored
program with the pinned official hash. It covered that rewrite's stack values
and predicates conditional on execution resources, not later changes or every
possible witness under limits waived by the singleton environment.

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

The VG/A program has 4,223 locking bytes, a 208-byte witness and 85-byte
transaction overhead: **4,516 total**, nine bytes below UY. Its locking SHA256 is
`11562df7a32468c8417741d5a512709fbe5184edb49b538e388671e8a7cdf3e5`.
Independent mathematical review and direct VM cases cover the loop boundary;
whole-verifier proof and cost measurements are recorded separately by the
release jobs. This remains relaxed-VM research with the same canonical G1
witness representation and existing subgroup posture.

Additional exact outlines (VJ/B, Oct 18, 2026): three repeated instruction sequences
are now named helpers. `outline_69` uses short ID 15 at ten static call sites;
the original `outline_15` moves to ID 68. `outline_70` uses ID 69 at five sites,
and `outline_71` uses ID 70 at five sites. Expanding these three helpers and
restoring the original ID 15 reconstructs the exact 4,223-byte VG/A program
above, including its 41-byte exponent-driven `fp_pow`. The scalar guard,
G1 decoder, proof coordinates and witness representation remain unchanged.

The current program has 72 functions, maximum call depth 11, and 4,207 locking
bytes plus the same 208-byte witness and 85-byte overhead: **4,500 total**, 16
bytes below VG/A. The additional invocation frames require separate whole-proof
and resource-cost qualification; static recovery does not establish those results.

The builder derives `outlinedAdditionalFunctions` from the parsed declarations
and symbolic calls in all function bodies and main. The manifest records each
`outline_66` through `outline_71` with its actual ID and static occurrence count;
`outline_65` remains covered by its earlier provenance field. Export tooling
consumes this manifest metadata without maintaining a second helper list.

Posttest exponent loop (VX, Oct 18, 2026): `fp_pow` keeps identifier 66 but
shrinks from the VJ 41-byte pretest body to a 36-byte body. Each iteration shifts
the remaining nonnegative exponent, then tests whether it is zero. For exponent
zero, the posttest loop returns one after a discarded square; the pretest body
returns one without that square. Both actual callers use the positive constants
`p - 2` and `(p + 1) / 4`. Negative exponents are outside this contract, and the
extra zero-exponent square prevents a universal resource-equivalence claim.

The program now has 4,202 locking bytes (SHA256
`25ed09e4a4645ce245032d6ecbd6b5eedf8e097da4bb8317f2387b9dd8903ee2`),
plus the unchanged 208-byte primary witness and 85-byte overhead: **4,495 total**.
Restoring only the old `fp_pow` body reconstructs the exact 4,207-byte VJ program.
All other 71 bodies, identifiers, complete main, G1 decoder and 32-byte range
guard remain unchanged. The builder, its six derived outline metadata entries,
and raw proof archives are unchanged. Actual operation cost and whole-proof
acceptance require separate qualification; this source change makes no native
or relay admission claim.

Optional outline profiles (WG, Oct 18, 2026): the normal builder accepts
`node build.mjs OUTPUT_DIRECTORY [bytes|balanced|cost]`, and the assembly API
accepts `assemble(source, {profile})`. The default `bytes` profile preserves the
VX program and its normal exports and manifest exactly. Unknown profiles fail.
The master assembly remains the sole owner of each helper body.

| Profile | Retained recent outlines | Locking bytes | Primary witness + overhead | Total |
| --- | --- | ---: | ---: | ---: |
| `bytes` (default) | 69, 70, 71 | 4,202 | 208 + 85 | 4,495 |
| `balanced` | 69 | 4,212 | 208 + 85 | 4,505 |
| `cost` | none | 4,218 | 208 + 85 | 4,511 |

Before compilation, the alternate profiles inline the selected straight-line
helper bodies at their symbolic call sites and remove their declarations. The
`cost` profile also restores the displaced `outline_15` from ID 68 to ID 15.
Function IDs and occurrence counts in `outlinedAdditionalFunctions` are derived
after this transformation. Alternate manifests identify their selected profile.
The 36-byte power routine, G1 decoder, 32-byte public-input guard and all proof
and witness values remain fixed; a decoded inverse restores the exact default program.

A bounded pilot verified the same committed primary proof once per profile.
Its operation costs were 5,534,299,258 (`bytes`), 5,528,763,523 (`balanced`) and
5,520,406,248 (`cost`) in the pinned relaxed BCH VM. These are single-proof
measurements, not complete alternate-profile qualification. Additional proofs,
rejection gates and native resource or relay admission require separate evidence.
