# Arrays and the Field Tower

This note covers whether the Groth16 verifier needs arrays, which array operations would actually help, and why the performance win may be small for a computation built on 256-bit field elements.

## Can the verifier be built without arrays?

Yes. The current pseudo-code already does it by carrying every composite value as individual `int`s:

- F_p2 = 2 ints, F_p6 = 6, F_p12 = 12 ints
- G1 = 2 ints, G2 = 4 ints

Nothing in the computation has a runtime-variable length. The tower sizes are constants, the ate-loop length is a compile-time constant, and a Groth16 verifier for a given circuit has a fixed number of public inputs (the verification key is hardcoded for that circuit). So arrays are an ergonomics problem, not a feasibility blocker.

The cost of going without them:

- Signature explosion. An `mulFp12` takes 24 int args and returns 12; `multiPairing` already takes ~24. Tuple returns of 12 elements are unwieldy and error-prone.
- Manual unrolling. The input aggregation `X = IC[0] + sum_i input_i * IC[i]` and the tower index arithmetic are written out coordinate by coordinate.
- Stack pressure. Each F_p12 value is 12 separate stack items, against the VM's 1000-item stack limit.

### Workaround that exists today (no arrays)

CashScript v0.13 has `bytes` with `.slice(start, end)`, `.split()`, and `toPaddedBytes(int, len)` plus int casts. A tower element can be packed into a single `bytes` blob (12 x 32-byte chunks) and sliced apart, instead of using 12-arg signatures. This is essentially the same representation arrays would compile to (see below).

## What array support would need

Tracked in [#266 Add support for Array types](https://github.com/CashScript/cashscript/issues/266).

Essential (the actual win):

- Fixed-size declaration, e.g. `int[12] f`.
- Indexed read/write, `f[i]` and `f[i] = x`.
- `.length` and iteration with the existing `for` loop.

Nice to have:

- Literals / construction for initialization.
- `slice` for extracting sub-elements (an F_p6 half out of an F_p12).
- `map` / `reduce`. The input aggregation is literally a reduce; Frobenius is a map over coordinates. Convenient, but expressible with index + `for`.

## Fixed vs dynamic length

Fixed-size arrays are sufficient. The tower elements are always 2/6/12, and the public-input count is fixed per circuit. Dynamic-length arrays would only matter for a single generic verifier that handles circuits with a runtime-variable input count, which is not how Groth16 verifiers are deployed (one verifier per circuit) and would hit the contract-size and op-cost limits anyway. Dynamic arrays are also much harder to implement on the BCH VM, so they are neither needed nor worth the complexity here.

## How arrays would compile, and why the win may be small

Bitcoin Cash has no native array type, so a CashScript array has to compile to one of two things:

1. A fixed set of distinct stack items. This only works when the index is known at compile time (the access is effectively unrolled). In that case an array is pure syntax sugar over what the current code already does, with no runtime cost but also little benefit beyond readability.
2. A single concatenated byte string, manipulated with `OP_SPLIT`, `OP_CAT`, `OP_NUM2BIN` and `OP_BIN2NUM`. This is the realistic target whenever the index is a runtime value (a real `for` loop over an array), because the compiler tracks stack positions statically and a runtime-variable stack depth does not fit that model.

For this workload the elements are large: a field element is ~32 bytes, an F_p12 value is ~384 bytes, and an array of points or inputs is longer still. Under the op-cost model, operations are charged roughly in proportion to the number of bytes they process, so on the byte-string representation:

- An indexed read is one or two splits plus a bin2num, touching up to the blob length.
- An indexed write has to split the slot out and concatenate the blob back together, copying the entire ~384-byte value on every write.

So an array write on an F_p12 blob costs on the order of ten times a single scalar field operation, and that cost is pure access overhead. It does not reduce the underlying field arithmetic at all. Hand-written code that keeps coordinates in named locals (fixed stack positions) avoids all of this splitting and concatenating.

The consequence: for the hot tower arithmetic (F_p12 multiply, square, Frobenius, accessed by fixed coordinate indices), explicit scalars are likely cheaper than a byte-string array. Arrays do not make the math cheaper; they add packing overhead on long blobs. Since op-cost and contract size are the binding constraints (see [BCH Shortcomings](README.md#bch-shortcomings)), paying op-cost for readability in the hot path is a poor trade.

### Where arrays still help

The one place the index is genuinely the natural loop variable is the public-input / IC aggregation, `X = IC[0] + sum_i input_i * IC[i]`. A `for` loop there reads cleanly. But the input count is small and fixed, so unrolling it (as the current code does) is also fine and cheaper.

> **Caveat — runtime-indexed *table* lookups are the opposite case.** The pessimism above is about
> *compile-time-indexed* tower arithmetic, where named locals at fixed stack positions beat a
> byte-string. When the index is a genuine runtime value and the alternative is a deep `if/else`
> cascade (e.g. the GLV `select16` 16-entry subset-sum table), a packed-blob slice is ~74% cheaper,
> because branch dispatch — not data movement — dominates. See
> [`chunked/pairing/select16-blob-table.md`](chunked/pairing/select16-blob-table.md).

## Takeaway

- Fixed-size arrays would be an ergonomic improvement (no 24-argument signatures, cleaner input loops), but because they compile to byte-string split/concat for big elements, the op-cost win is small to negative in the hot path.
- Dynamic arrays are neither needed nor worth the VM complexity.
- The main win would be readability and auditability: the contract code would be cleaner and easier to review, even though the effect on op-cost and size is small.
