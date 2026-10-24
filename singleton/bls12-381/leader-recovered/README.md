# Recovered BLS singleton program

The default `export.mjs` profile is now `checked`, selecting `cofactorPoints()`
from `cofactor-points.mjs`. It emits 5,675 bytes with SHA256
`6b36b9febaa033b366672c7a6a9d01dd604402d77cf7aced0a001a173292ad3f`.
It checks canonical finite compressed coordinates and curve equations, completes
the G2 square-root chart, and projects both pairing operands into their r-order
components using complete group operations. This preserves the fixed-VK
cofactor-equivalent equation for G1 and G2; it does not enforce subgroup
membership of the original G2 input. The original ten-push proof/public-input
interface is unchanged. Native-resource status remains **HOLD**: four original
positive proofs passed the arithmetic oracle with resource ceilings lifted,
which does not establish current BCH or relay admission.

The explicit compact profiles and their measurements below describe historical
unchecked controls. `compact.mjs` remains their source owner; shared raw kernels
and independently reviewed FS/native entries are unchanged. Exporting the
default checked profile updates only the two genpow vector locking/provenance
records and preserves all supplied witness and public-input fields.

`program.mjs` is symbolic assembly recovered from the exact 3,425-byte genpow leader. It declares all 51 functions by name and gives the complete main program. Calls reference names rather than historical numeric identifiers. `field.mjs` records the deterministic negative-seed field and full-exponent derivation. `build.mjs` compiles this source directly and rejects a baseline that differs from SHA256 `44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1`.

Run `node singleton/bls12-381/leader-recovered/build.mjs /absolute/output.json` with the pinned Libauth dependency. This build reads no benchmark artifact, frozen hex, recovery inventory or historical compiler output. Data literals in the assembly retain their exact wire encodings; function declarations and calls are emitted from symbolic references.

This recovers a reviewable program source, not the unavailable original CashScript generator, compiler revision, committed search witness or stackcert compression pipeline. Descriptive function names are recovered labels; neutral stack/tower names identify bodies whose complete semantic contract has not been established here. Exact-byte reconstruction transfers the existing artifact's behavior and limitations. It does not prove subgroup/canonical-input soundness or make the singleton runnable under current BCH limits.

The compact stage preserves SZ-a1 inlining and the SM-a2 outline described below. One shared stack-outline owner applies the measured TW/UE transformations. It preserves the compact identifier map and the public-input range guard, then expands `stackSequence33`, `negFp`, `inverseFp`, and `fp2Sqr`; SV-a2 assigns `stackSequence52=7` and `decompressG2=17`. TB-a3 adds `mulFp=1` for 41 `OP_MUL CALL fieldPrime OP_MOD` sites and moves `fp6Add` from `1` to `18`; TJ-a2 adds `stackSequence53=-1` for ten `OP_7 OP_ROLL OP_7 OP_ROLL` sites and moves `fp6Mul` from `-1` to `19`. TW keeps the guard prefix and retains the prior bindings except for the named short-key demotions below; each added helper is a static straight-line outline with an independent byte inverse. The historical assertions retain the recovered baseline and prior published controls; the current VO-a1 source assertion emits the 3,295-byte candidate described below. Unknown symbols, raw DEFINE/INVOKE instructions, duplicate identifiers and malformed data literals fail explicitly. The complete source contains no dynamic invocation references.

After committing this source, run `node singleton/bls12-381/leader-recovered/export.mjs /absolute/candidate-benchmark` to export the reviewed compact candidate. The exporter accepts the pinned original and previously published genpow vectors, including the current published parity-encoded pair, retains all witness/public-input fields exactly, and updates only the two genpow vector files. It records the recovered-source revision and hashes, explicitly preserving the missing original compiler/search lineage. It fails on an unexpected or already-updated baseline; it never imports a prebuilt candidate locking.

SM-a2 adds one static outline after the SZ-a1 derivation: `stackSequence52` uses identifier `17` and the two-roll body `OP_PUSHBYTES_1 0x11 OP_ROLL OP_PUSHBYTES_1 0x11 OP_ROLL` at six recorded sites. SV-a2 swaps that ID with `decompressG2`, assigning `stackSequence52=7` and `decompressG2=17`. TB-a3 adds `mulFp=1` and moves `fp6Add=1` to `18`; an actual decoded inverse restores the exact 3,412-byte SV-a2 program. The measured TB-a3 candidate is 3,341 bytes with SHA256 `167e1ab1647f8b41b12bcde2cbf17068671192d56a11be68d105254a4a28515a`; VM cost and proof gates remain separate release evidence.

TJ-a2 replaces three sites each in `fp6Add` and `fp6Sub`, one each in `fp6Mul` and `towerSequence38`, and two in `millerLoop`. Ten four-byte sequences become two-byte calls, saving 20 bytes; the new declaration costs 7 bytes and the `fp6Mul` key change costs 5 bytes, for a net eight-byte reduction. The decoded inverse expands those ten calls and reverses the four existing `fp6Mul` calls plus its declaration, restoring the exact TB-a3 bytecode. The function graph remains acyclic with maximum call depth 10. This static inverse does not establish runtime cost, stack limits, or acceptance; those require separate actual gates.

TR-a2 adds `stackSequence54=14` for nine exact `OP_6 OP_ROLL OP_7 OP_ROLL` sequences and moves `fp2Scale` from 14 to 31. Two sites each belong to `fp6Mul`, `towerSequence37`, `millerLoop`, and `g1Add`, with one in `stackSequence8`. The main and its range guard remain exact TJ-a2. The resulting 51-function program is 3,328 bytes (`d0dc12d1b7ac3d50c0ba0b07462ec8b63cf9f813d0107b3c0102f5c81f695118`). Eighteen replaced bytes, seven declaration bytes, and six bytes from the existing key change give a net five-byte reduction. Static inverse and sampled runtime gates have separate evidence.

TW/UE/UR static frontier (Oct 18, 2026): the four TW outlines add 28 call sites; UE-a1 adds `stackSequence59=54` for four exact `0x37 OP_ROLL 0x37 OP_ROLL` sites, UE-a2 adds `stackSequence60=55` for two guarded `g1Add` stack sequences, and UE-a3 adds `stackSequence61=56` for three `fp2Mul/swap/fp2Add` sequences. The resulting UE candidate is 58 functions and 3,310 bytes with SHA256 `24f462b2345f79354be7ea5aa0ec70deb28282001eb6efe53fd7e955accdf360`; the 17-byte range prefix remains exact. An independent actual-decoded inverse expands all three UE helpers and restores the published 3,315-byte TW-a8 program byte-for-byte. The candidate graph remains acyclic at maximum depth 11. UR-a1 then adds `stackSequence62=57` for two exact `OP_3 OP_PICK OP_MOD CALL sqrtFp OP_DUP OP_5 OP_ROLL OP_1 OP_NUMEQUAL` sites in `decompressG2`, and `stackSequence63=58` for two exact `OP_ROLL OP_2SWAP OP_SWAP OP_2ROT CALL stackSequence8 CALL stackSequence10 CALL millerAccumulate` sites in main. The resulting 60-function candidate is 3,308 bytes with SHA256 `3ef0a31623a2322afed809f40ee4245365b8f5f10c86142853408b27edacd4d1`; the 17-byte guard remains exact, the decoded main inverse restores UE byte-for-byte, and the graph remains acyclic at maximum depth 12. Runtime cost and proof gates remain separate evidence.

VO-a1 replaces only the compact `powFp` body (raw key `1e`) with a 37-byte exponent-driven loop. It shifts the remaining exponent after each iteration, retaining the field modulus, accumulator and reduced base; exponent zero returns one. The supported equivalence domain is valid numeric `0 <= E < 2^381`, including the actual exponents `p - 2` and `(p + 1) / 4`; negative exponents are outside this contract. The recovered `program.mjs` and its baseline assertions remain unchanged. Restoring the old 50-byte body reconstructs the published 3,308-byte program exactly: all other 59 bodies, identifiers, complete main, decoder and 17-byte range guard are unchanged. The candidate remains 60 functions and is 3,295 bytes with SHA256 `c5b4cf41459b7ec2f4c84fef0eb8cba5dfffee09ad03da909c9d31378a9d5ece`. With the unchanged 205-byte witness and 85-byte transaction overhead, the score is 3,585 bytes. Actual operation cost and whole-proof acceptance require separate qualification; this source change makes no native or relay admission claim.

## Submitted genpow comparison

Against the merged benchmark baseline, the compact genpow program reduces
locking bytecode from **3,432 to 3,295 bytes**. Its unchanged 205-byte witness
and 85-byte transaction overhead give a **3,585-byte score**. This combines
function inlining, an outlined `MUL P MOD` helper, short function identifiers,
and the remaining-exponent `powFp` loop described above. The measured primary
relaxed-VM operation cost rises by approximately **1.4%**; this is a size/cost
tradeoff. The symbolic source reconstructs both submitted locking programs
(single-proof and multiproof) exactly. Witness and public-input values remain
fixed. This remains the unrestricted singleton lane.
