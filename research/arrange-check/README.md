# arrange() / roll() assembler check (constructive, 2026-10-30)

Track 7 (`wip/plonk-usable-verifier`, 05c7c6b) fixed `Asm.arrange()`: it kept an in-place prefix `names[0..k)` even
when items that are not in `names` sat above it in the top-n window. Those items then stayed between the prefix and the
rolled suffix, so the top n were not `names`. Track 6 had fixed `Asm.roll()`: the symbolic splice used
`st.length - 1 - d`, but `d` counts every physical piece of a sized pile above the item, so with a pile above the item
the symbolic stack could lose the wrong name (the emitted ROLL depth was always right).

This branch applies both fixes to every copy of the symbolic-stack assembler on main and checks whether any shipped
build was affected.

## Method

1. `node patch.mjs detect <asm.mjs>`: the old behaviour plus a log line whenever the arrange fix would lower `k`, or
   the old roll splice removes a different symbolic item than `idx(name)` (a negative splice index clamps to 0, which is
   still the right item when the rolled item is the bottom one: logged as benign). Every documented build was run.
   Positive control: the detector on the Track 7 code with the pre-fix asm (`chain.mjs mul2`) fires
   (`arrange k 1->0 names=acc6,fs_S2`).
2. `node patch.mjs fix <asm.mjs>` (committed here), rebuild with the documented commands, and compare redeem/program
   and the exported bench vectors byte-for-byte (`cmp.mjs`) with the committed files and the bench `src/bch/*` files.

## Results

| assembler copy | used by (bench entry) | arrange pattern | detector (old asm) | rebuild with fix |
|---|---|---|---|---|
| chunked/bn254/sound-si-gls | bch-groth16-sound-si-gls-single (+ txv5pad) | yes, unfixed; roll unfixed | 0 arrange; roll: 2 benign (WS, WQc at the stack bottom under the 11-piece Dp pile, negative index clamps to 0) | redeem 242c3ce7…8b5d identical; export == bench vectors; txv5-pad derive == bench txv5pad vectors |
| chunked/bls12-381/sound-si-gls | bch-groth16-bls12381-sound-si-gls-single (+ txv5pad) | yes, unfixed; roll unfixed | 0 arrange; roll: 2 benign (same WS, WQc case) | redeem c93557ac…8f74 identical; export == bench; txv5pad == bench |
| chunked/bn254/bn-native-sound | bch-groth16-bn254-sound-native | already fixed on main (02ff13a, "fix vs the SI-GLS copy"); roll already uses idx | 0 arrange (even without its own fix) | unchanged file; rebuild code 75c780ae…78d7, export == committed vectors.json == bench |
| chunked/bls12-381/bls-native-sound | bch-groth16-bls12381-sound-native | yes, unfixed; roll unfixed | 0 arrange, 0 wrong roll | R 37fb7c1c…374a, program e6fcc3d9…ebb8 identical; export == vectors.json == bench |
| research/frontier-middle/bn254/sigls-dproj | bch-groth16-sound-si-gls-dproj; also imported by rolled-residue (bch-groth16-singleton-rolled-residue, -mulc) | yes, unfixed; roll unfixed | 0 / 0 (T1, T2 default, T2 mulc) | T1 980482d4…1125 identical (and DPROJ_SHARED=0 == build-inline.json); T2 95297900…758f identical; T2 mulc build.json == build-mulc.json; all three exports == bench |
| research/frontier-middle/bls12381/sigls-dproj | bch-groth16-bls12381-sound-si-gls-dproj | yes, unfixed; roll unfixed | 0 / 0 | redeem bd3fe6eb…d30c identical; export == bench |
| research/bls-native-sound-design2 | none (design prototype) | yes | 0 / 0 (proto_worker 2 18 1, measure) | fix applied |
| research/sound-si-gls-bls12381-d2 | none (design prototype) | yes | 0 / 0 (kernels.mjs 400) | fix applied |
| research/sound-sz-bls12381-native/prototypes | none (design prototype) | yes | 0 / 0 (worker 4 12 aff, head, glue) | fix applied |
| research/sound-bn254-native/prototypes, research/bn-native-msi-d2 | none; import the bn254 sound-si-gls asm | (shared) | 0 / 0 (loop affineN 0 65, setup2, glue, proto-tx) | covered by the sound-si-gls fix |
| research/plonk-kzg/verifier | PLONK research (Track 6/7) | fixed on the Track 7 branch | positive control fires | not touched here |
| research/pq-hash, pq-stark (lib/asm.mjs `arrange(layout)`), singleton/bn254/recompiler, si-gls-spec / single-identity prototypes, pairfold5-msm vkx-msm-asm | various | no: whole-stack arrange (arrangeAll algorithm) or roll-everything; no greedy prefix | n/a | n/a |

Conclusion: no shipped build ever reached the arrange bug, and the only old-roll cases are two benign clamps at the stack
bottom. Every leaderboard entry's emitted bytecode and bench vectors are byte-identical with the fixed assembler, so the
shipped builds compute exactly what the fixed assembler compiles; no test or red-team re-run is needed for them.
The fix is committed so future builds from these copies cannot hit either bug.
