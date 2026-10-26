# BN254 frontier verification

> **Historical (2026-09-05).** The 36,836-byte entry certified here is `bch-groth16-intratx-pairfold5-pevalfuse`, which now **fails** the benchmark: the maintainer red-team accepts a forged public input because its vk_x is not bound to the claimed inputs. It is also withdrawn by its author ([#32](https://github.com/mr-zwets/groth16_cashscript/issues/32) F9). The densless-msm-slim entry (35,143 B) that later replaced it as the frontier is withdrawn too (F6). The current non-withdrawn BN254 frontier is `bch-groth16-intratx-crown8-rawchain` (77,193 B); see [verifiers.md](../verifiers.md).

Current-BCH: 36,836 bytes, five inputs, 27,895,539 committed operation cost. Singleton: 4,587 bytes, 5,505,565,336 operation cost under the relaxed VM; the byte saving increases computation. Native and singleton preserve their separate declared semantics. Historical compiler lineage is not claimed recovered.

Both entries were rechecked through unchanged official benchmark gates in clean publication checkouts based on benchmark `464722989363227e5cfc47bbe0d2f2e5a4053d95`; TypeScript typecheck passes. Dependencies are Libauth 3.1.0-next.8 and Noble curves 2.2.0. Experimental smaller candidates without completed verification are excluded.
