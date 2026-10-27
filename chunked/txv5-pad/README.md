# TXv5-grading pad-slot variants of the SI-GLS entries

The bench grades `bch-spec` entries a second time on TXv5 as written (density base 41, per-input budget
`(41 + unlocking length) * 800`; bench issue #35, `zk-verifier-bench/src/harness/txv5.ts`). Its grade pads an
input's unlocking with an ignored zero push. The two reviewed SI-GLS entries (`bch-groth16-sound-si-gls-single`,
BN254, and `bch-groth16-bls12381-sound-si-gls-single`, BLS12-381) pin their push layout with `DEPTH == 2` at entry,
so they reject any pad, and until now their TXv5 figure was an estimate.

This directory holds a **TXv5-grading variant** of each. It is used only for the bench's `txv5` field; the
reviewed `bch-spec` artifacts (`../bn254/sound-si-gls/redeem.hex`, `../bls12-381/sound-si-gls/redeem.hex`) and
their vectors are unchanged.

## The variant

One instruction-level edit, at the first instruction after the function prologue:

| | bytes | |
|---|---|---|
| reviewed | `74 52 9d` | `DEPTH <2> NUMEQUALVERIFY` |
| variant | `74 53 9d 75` | `DEPTH <3> NUMEQUALVERIFY DROP` |

The unlocking becomes `<WQ> <WS> <pad> <redeem'>`. Everything else in the redeem is byte-identical.

| | reviewed redeem | variant redeem | variant sha256 |
|---|---|---|---|
| BN254 | 11,182 B | 11,183 B | `881ee04a…` (`bn254.json`) |
| BLS12-381 | 12,793 B | 12,794 B | `a570e257…` (`bls12-381.json`) |

## Why the pad cannot affect acceptance

- The prologue (function definitions) runs before the edit and is byte-identical, so the function table is the
  same.
- When the edited check starts, the main stack is `[WQ, WS, pad]` (pad on top) and the altstack is empty. The
  check requires exactly three items and `DROP` removes the pad, so after `DROP` the main stack is `[WQ, WS]`: the
  state the reviewed program has right after its own `DEPTH <2> NUMEQUALVERIFY`. Control state is the same (no
  open `IF`/loop at that point).
- From there the variant runs the reviewed program's remaining bytecode, byte for byte. That code reads only the
  stack, the altstack and its functions. It contains no transaction introspection and no `OP_ACTIVEBYTECODE`
  (checked over the code and over every function body), so it cannot see the pad, the redeem's new byte or the
  unlocking length.
- The pad's only effects are its push and `DROP` op-cost and the input's density budget. A resource limit can
  only turn an accept into a reject. So the variant accepts `(WQ, WS, pad)` only if the reviewed program's logic
  accepts `(WQ, WS)`, and the reviewed soundness argument (`../*/sound-si-gls/README.md`) carries over unchanged.
  The statement (VK, public inputs at the same offsets of WS) is the same.
- The locking commits to the variant redeem (P2SH32), so the variant is a different deployment with its own
  locking; it is never mixed with the reviewed one.

## Derivation and checks: `derive.mjs`

```
node derive.mjs ../bn254/sound-si-gls ../../../zk-verifier-bench/src/bch/groth16-sound-si-gls-single-vectors.json bn254
node derive.mjs ../bls12-381/sound-si-gls ../../../zk-verifier-bench/src/bch/groth16-bls12381-sound-si-gls-single-vectors.json bls12-381
```

The script derives the variant from the reviewed `redeem.hex` (not from a rebuild) and the honest witnesses from
the reviewed bench vectors (the same WQ / WS pushes; only the pad and the redeem change). It asserts:

- the reviewed vectors' locking is P2SH32 of the reviewed `redeem.hex`, which matches its `build.json`;
- `74 52 9d` occurs once, at `build.json`'s prologue offset;
- the decoded instruction lists of reviewed and variant are equal except the entry check (the edit is not inside
  push data);
- no introspection opcode (`0xc0..0xd3`) in the code or in any function body;
- every honest run (valid, extra proofs, worst case) with a 1-byte zero pad is accepted on the bch-spec VM
  (consensus and standard);
- pad independence on fixture 0: pads of 0, 1, 2, 75, 76, 520, 4,000 and 20,000 B, as zeros and as random bytes, plus
  the single bytes 0x01, 0x81 and 0xff, are all accepted in both modes. For each length, zero and random pads give
  identical op-cost and hash-iteration counts;
- rejection tests: no pad, two pads, and a pad below WQ are rejected; every reviewed invalid vector, carried over
  with the pad and the variant redeem, is rejected (both modes).

Outputs: `<curve>.redeem.hex`, `<curve>.json` (hashes, offsets, op-costs, pad table) and `<curve>-vectors.json`.
The vectors file is copied to the bench as `src/bch/groth16-*-sound-si-gls-single-txv5pad-vectors.json`. The honest
runs ship a 1-byte zero pad; the bench's TXv5 grade grows that pad to the minimal length.
