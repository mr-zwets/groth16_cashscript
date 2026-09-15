# BLS12-381 frontier verification

Current-BCH: 79,948 bytes, 22 inputs, 53,133,274 committed consensus operation cost. Ten full transactions, 500 modified-field rejections and both resource certificates pass; minimum certified margins 23,838/122,142. Compiler revision: `1c707c1dbf87396b30ba5e0704b1db44475ce893`, compiler build SHA256 `2ebf0b95e78a2b7dc12c4778a1ee2fcac258aa3244d9f3a6871d8000b2b3e6fc`. See BLS_QSPLIT_TAIL22_STATUS.md for source commands and declared Fiat-Shamir/cofactor semantics.

Singleton: 3,705 bytes, 20,711,247,449 committed operation cost under the relaxed VM. The 51 bodies and 311 calls retain their behavior under identifier reassignment. Original compiler/search lineage remains unrecovered; no stronger input-validation or native compatibility claim.

Both entries were rechecked through unchanged official benchmark gates in clean publication checkouts based on benchmark `464722989363227e5cfc47bbe0d2f2e5a4053d95`; TypeScript typecheck passes. Dependencies are Libauth 3.1.0-next.8 and Noble curves 2.2.0. Experimental smaller candidates without completed verification are excluded.
