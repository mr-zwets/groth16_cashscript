# PROGRESS (wip/pq-hash-prover only; never merge to main)

Task: pq-hash Prover phase. Off-chain prover + reference verifier + vectors for P100, P128, U100, C100, C128.
Spec: work/pq-hash/design/SPEC.md (zk-verifier-bench wip/pq-hash-design c3497a1).

- [x] pqfield / pqparams / pqproto / verifier / prover (numpy) written; small-n round trip e=2,3 OK
- [ ] full-size proofs per set, timings
- [ ] gen_vectors.py + tampered vectors
- [ ] test_soundness.py
- [ ] SERIALIZATION.md, README.md
