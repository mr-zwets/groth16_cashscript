# PROGRESS (wip/pq-hash-prover only; never merge to main)

Task: pq-hash Prover phase. Spec: zk-verifier-bench wip/pq-hash-design c3497a1 (work/pq-hash/design/SPEC.md).

- [x] pqfield / pqparams / pqproto / verifier.py / prover.py (numpy)
- [x] vectors for P100 (4), P128 (4), U100 (2), C100 (2), C128 (2); 20 tamper cases per set
- [x] test_soundness.py (stdlib, matches design calculator) + test_roundtrip.py (numpy)
- [x] SERIALIZATION.md, README.md (results)
- [x] verify.mjs: independent JS verifier, agrees on all vectors
Next (Build): layout (a)/(b) scripts from vectors; consider p99 proof size for P128 single-input fit.
