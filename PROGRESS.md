# PROGRESS: Track 7, task "Ceremony SRS" (wip/plonk-usable-srs; this file stays on the wip branch)

- [x] Ceremony choice: Aztec Ignition MAIN IGNITION (176 participants + Aztec seal), range-loaded
- [x] research/plonk-kzg/prover/ceremony/main.go: download ranges, verify (t2 pin, header, chain of first power over
      176 + seal, RLC power check over 65,538 powers, monomial + flat cross-checks), write gnark kzg.SRS
- [x] main.go -srs FILE (srs.go); -unsafe-test-srs keeps the old path
- [x] vectors regenerated (prover + verifier copies); verify.mjs: 164 cases OK
- [x] verifier/srs-check.mjs: baked [x]_2 constants vs ceremony, with control
- [x] verifier tests re-run on the new vectors: all verdicts unchanged, redeem sizes identical (README)
- [x] docs updated (prover README + FORMAT SRS, verifier README re-run table, SOUNDNESS A3)
