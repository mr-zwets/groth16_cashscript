# native-bn-design1 (design only, angle A: state & binding)
Worktree: work/native-bn-design1/groth16_cashscript on wip/native-bn-design1 (from wip/native-bn 2bd3f90).
Doc: work/native-bn/DESIGN-1.md (copy committed under research/native-bn-design1/).
- [x] per-instruction op trace of glue sections -> research/native-bn-design1/trace.mjs
- [x] prototype chunked/bn254/bn-native-v2a-proto (A1 single code host, A2 prefix-first reads, A3 5-word HAND + receiver-hosted cut state, A4 CUTS env)
- [x] measured: 27,538 @6% / 27,316 @<=4% (cuts 0/26/48/65); cap rule ok (input 0 7.71%); rejection checks ok; B1 (d01) measured and rejected
- [x] DESIGN-1.md written, committed, pushed
Done.
