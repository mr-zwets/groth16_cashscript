# pq-hash prover and reference verifier

This folder holds the off-chain side of the pq-hash track:
- a prover for a post-quantum, hash-based (SHA-256) STARK verifier on CashVM;
- two independent reference verifiers;
- test vectors for every parameter set.

It implements SPEC.md (zk-verifier-bench, branch `wip/pq-hash-design`, commit c3497a1). Branch: `wip/pq-hash-prover` (groth16_cashscript). **Research only: not a leaderboard entry.**

The protocol is a DEEP-ALI STARK with batched DEEP-FRI:
- Field: Goldilocks, with the extension F_p[u]/(u^e − 7).
- Hashing: SHA-256 Merkle trees with nodes truncated to h bytes, and a SHA-256 Fiat-Shamir transcript with 28-bit grinding.
- Statement: a MiMC-7 chain, 2 columns × 2^16 rows, y_out = F^(n−1)(x_in).

**Zero-knowledge is out of scope.** There are no masking polynomials, and the opened trace values reveal parts of the (public) computation. Soundness for the chosen parameters is in scope; see `test_soundness.py`.

## Files

| file | what |
|---|---|
| [SERIALIZATION.md](SERIALIZATION.md) | **byte-level contract**: encodings, TAG and constants, transcript, proof layout, multiproof order, check order, vector format |
| `pqfield.py` | Goldilocks and F_{p^2}/F_{p^3} scalar arithmetic (pure Python) |
| `pqparams.py` | parameter sets, FRI shape, soundness calculator (the design formulas), round constants, TAG |
| `pqproto.py` | encodings, E(d), grinding check, Merkle hashing and multiproof, transcript, layout offsets |
| `verifier.py` | reference verifier (pure Python, stdlib only); `python3 verifier.py vectors/*.json` |
| `verify.mjs` | **independent** JavaScript BigInt verifier written from SERIALIZATION.md, sharing no code with the Python; `node verify.mjs vectors/*.json` |
| `prover.py` | prover (numpy vector arithmetic; transcript and serialization via the shared pure-Python modules) |
| `gen_vectors.py` | writes `vectors/<SET>-<k>.json` and `vectors/summary.json` |
| `test_soundness.py` | unit tests (stdlib): FRI soundness numbers, query minimality and byte expectations match the design calculator (and cross-check the calculator file itself when present); constants, digest map, grinding and multiproof |
| `test_roundtrip.py` | small-size prove/verify/tamper round trips for e = 2, 3, arities 4/8/16 and 2- or 3-fold schedules (numpy) |

## Running

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt      # numpy, prover only
.venv/bin/python gen_vectors.py              # all sets (~15 min on 24 cores; grinding uses all cores)
python3 verifier.py vectors/*.json           # stdlib only
node verify.mjs vectors/*.json
python3 -m unittest test_soundness -v
.venv/bin/python -m unittest test_roundtrip -v
```

The prover is deterministic: the same set and x_in give the same proof, because the nonce is the smallest valid one. Statement k uses x_in = LE(SHA256("verifier.cash/pq-hash/x_in" ‖ u8 k)) mod p.

## Results

Measured on 2026-10-28 (24-core x86-64, Python 3.14, numpy 2.5). The canonical proof is the layout (b) stream of SERIALIZATION.md §4, without script pushes or code. The Monte Carlo row samples 20,000 uniform index sets per parameter set and runs the exact multiproof count. "Prover s" is wall time, including grinding.

| set | regime | queries | proofs | measured proof bytes | design expectation | Monte Carlo mean ± sd (min / p99 / max) | PT | leaves | siblings (measured mean) | plain paths | prover s |
|---|---|--:|--:|---|--:|---|--:|--:|--:|--:|--:|
| P100 | JB | 22 | 4 | 49,718, 49,618, 49,093, 50,618 | 50,022 | 50,022 ± 407 (47,643 / 50,793 / 51,293) | 6,388 | 14,080 | 29,294 | 61,718 | 66 |
| P128 | JB | 43 | 4 | 88,752, 90,736, 91,952, 92,240 | 91,468 | 91,469 ± 729 (86,992 / 92,976 / 93,808) | 6,416 | 27,520 | 56,984 | 126,128 | 19 |
| U100 | UDR | 79 | 2 | 106,967, 105,892 | 107,423 | 107,430 ± 773 (103,517 / 109,067 / 109,842) | 4,300 | 35,392 | 66,738 | 164,117 | 6 |
| C100 | CONJ | 11 | 2 | 24,326, 23,851 | 23,940 | 23,937 ± 270 (22,376 / 24,426 / 24,676) | 1,228 | 8,448 | 14,412 | 28,651 | 41 |
| C128 | CONJ | 15 | 2 | 41,936, 42,032 | 41,748 | 41,750 ± 410 (39,248 / 42,544 / 42,832) | 3,344 | 12,480 | 26,160 | 50,864 | 63 |

What this shows:
- **The design's byte model is confirmed.** The Monte Carlo means equal the calculator's dedup expectations within 0.03%. Every measured proof lies inside the Monte Carlo range. The headline numbers hold: **P100 ≈ 50.0 KB and P128 ≈ 91.5 KB**, provable in the Johnson regime.
- **Proof size varies with the indices: σ ≈ 0.4 KB (P100) and 0.7 KB (P128).** Layouts must be sized for a high percentile, not the mean.
  - P128's p99 is 92,976 B and its maximum over 20k samples is 93,808 B. That is +1.5 KB and +2.3 KB over the expectation the SPEC used for the single-TXv5-input fit (95.6 KB unlocking, ≈ 4.3 KB spare under the 100,000 B transaction).
  - So the code budget for P128 layout (b) is about 6 KB at p99, not 8 KB. Build should confirm it with measured code size and treat the rare large-proof tail explicitly: re-grind with the next nonce if needed. That keeps the proof valid and only changes the indices.
- Every valid proof is ACCEPTED by `verifier.py` and by the independent `verify.mjs`. Both derive the same G and the same query indices.
- Every tamper case is REJECTED by both, with the expected reason: 20 cases per set (100 in total), listed in `tampered` of `<SET>-0.json`. The categories:
  - flipped Merkle siblings (first trace, last fri2);
  - flipped opened values (trace, comp and fri1 leaves);
  - FRI final-layer coefficients: two plain flips, which grinding rejects, and an honestly re-ground and re-opened proof whose only defect is final coefficient 0 + 1, which the FRI final check rejects;
  - public inputs (x_in or y_out flipped, which the AIR check at z rejects; non-canonical x_in; verifying against a different expected y_out);
  - the trace root, the fri1 root, OOD values and the nonce;
  - truncation and trailing bytes.
- `test_soundness.py` (stdlib) checks:
  - the per-round soundness bits, λ, the limiting round, the FRI shape and the byte expectation for P100, P128, U100, C100 and C128 against the design calculator's output;
  - that s is the minimal query count (s − 1 misses the target);
  - an independent closed-form recomputation of the BCIKS20 Thm 8.3 commit and query errors for P100/P128 (P128 commit-phase 128.31 bits);
  - SPEC 4.2's claim that m = 3 would need s = 44 at P128;
  - and, when the design worktree is present, it imports `params.py` and compares results field by field.

Notes and caveats:
- **No zero-knowledge** (SPEC 1.2). Soundness numbers are the design's. The open item stays open: the per-round Fiat-Shamir commit errors against ePrint 2023/1071 are for the Analysis phase.
- C100's commit round comes out at 99.99999 bits, shown as 100.0 after the calculator's 2-decimal rounding. It is a conjectured comparison set in any case.
- U128g (per-round commit grinding) and B128 (sensitivity only) are not built.
- Duplicate query indices occur (sampling with replacement). The verifiers require the duplicated leaves to agree.
- The prover runs at full size in 20–80 s per proof. Grinding (2^28 SHA-256 calls expected) is parallel over all cores.

