Breaking the Groth16 verifier into manageable steps helps structure the work and stay within the BCH VM limits. Loops and shift operators now exist (CashScript v0.13.0 / CHIP-2021-05 Loops), so the binding constraints are the BCH [script & transaction limits](README.md#bch-shortcomings), chiefly the 10,000-byte unlocking bytecode limit and the op-cost budget it caps. The roadmap below minimizes op-cost and bytecode size while splitting the verifier into functional chunks.

### 0. **Foundations Already in Place**
   - **Objective**: The language features and tooling the verifier is built on.
   - **Done**:
     - Adopted CashScript v0.13.0 loops (`for`) and shift operators (`<<`, `>>`), replacing the old `unroll(N)` placeholders.
     - Forked `cashc` to add **reusable (user-defined) functions** plus multi-return functions, the language feature the whole field tower depends on. See [The CashScript Compiler Fork](cashscript-compiler-fork.md).
     - The complete verifier now **compiles and runs** on the loosened BCH 2026 VM and is validated against `py_ecc` / `@noble/curves`: a single-transaction reference (`singleton/`) and a BCH-limit-viable multi-transaction form (`chunked/`).
   - **Note**: The roadmap below is the historical build plan. Steps 1–6 are now implemented in `singleton/pairing/` and `chunked/`; the file/function references in each step have been updated to point at the real code. The remaining open item is broader deployment tooling (step 7).

### 1. **Setting Up Arithmetic on the BN256 Curve**
   - **Objective**: Implement BN256 (a.k.a. BN254 / alt_bn128) field and curve operations in CashScript.
   - **Tasks**:
     - Build the field tower \( \mathbb{F}_p \rightarrow \mathbb{F}_{p^2} \rightarrow \mathbb{F}_{p^6} \rightarrow \mathbb{F}_{p^{12}} \). **Done**: the full tower (mul, square, Frobenius, inverse) is implemented and graded against `@noble/curves` in `singleton/pairing/fp2.cash`, `fp6.cash`, `fp12.cash`, `fp12_frob.cash`, `fp12_inv.cash`.
     - Without an array/struct type, each tower element is carried as separate ints (2 for \( \mathbb{F}_{p^2} \), 12 for \( \mathbb{F}_{p^{12}} \)), passed through multi-return functions. See the "No Array Type" shortcoming in the README.
     - Implement basic field arithmetic (addition, subtraction, multiplication, modular inversion), using the native shift operators where useful. The base field prime is hard-coded into `mulFp` (so it constant-folds), and additions use lazy reduction.
   - **Milestone**: ✅ Complete tower arithmetic (`addFp`, `mulFp`, `mulFp2`, ... up through `mulFp12`) plus the G1 and G2 point types, validated against the reference libraries on the loosened BCH VM.
    - **Equivalent Ethereum Precompiled Contracts**:
      0x06 (ecAdd): Handles point addition on the BN256 curve.
      0x07 (ecMul): Performs scalar multiplication on the BN256 curve.


### 2. **Implement Elliptic Curve Operations for Pairing**
   - **Objective**: Create functions for point addition, doubling, and scalar multiplication.
   - **Tasks**:
     - Implement point addition and doubling for \( G1 \) (coordinates in \( \mathbb{F}_p \)) and \( G2 \) (coordinates in \( \mathbb{F}_{p^2} \)), plus the A-negation trick. **Done**: G1 uses Jacobian projective coordinates with a single Fermat inverse at the end (`jacAddG1`/`jacDoubleG1`/`jacToAffine` in `singleton/vkx.cash`, lifted into `singleton/pairing/groth16.cash`); the G2 line steps for the Miller loop live in `singleton/pairing/g2lines.cash`.
     - Implement scalar multiplication on \( G1 \) using the native shift operators for the bit tests (`(e >> i) % 2`), with a shared Shamir/Straus doubling chain in the chunked `vk_x`.
     - Ensure point operations fit within CashScript’s size and computational limitations.
   - **Milestone**: ✅ Functional point addition, doubling, and scalar multiplication, validated against `py_ecc`.
   - **Equivalent Ethereum Precompiled Contracts**:
          0x08 (ecPairing): Runs the pairing check on the BN256 curve in Ethereum.

### 3. **Miller’s Algorithm for Pairing Computation**
   - **Objective**: Implement Miller’s algorithm for the optimal ate pairing, which maps a \( G1 \) point and a \( G2 \) point to an \( \mathbb{F}_{p^{12}} \) element.
   - **Tasks**:
     - Set up the optimal ate pairing for BN256, iterating over the fixed ate loop bit pattern (6t + 2 in NAF form). **Done** in `singleton/pairing/miller.cash` (single pair) and `miller4.cash` (the four-pair boundary), with the sparse line multiply in `mul034.cash`.
     - Accumulate the tangent and chord line evaluations into the running \( \mathbb{F}_{p^{12}} \) value (square `f` once per step, multiply in the `mul034` line). Verified == golden `millerHex` byte-for-byte against `@noble/curves`.
     - Apply the final Frobenius-mapped addition steps (Q1, Q2) that complete the optimal ate loop.
   - **Milestone**: ✅ An operational Miller’s algorithm whose 4-pair boundary matches the reference exactly (~957M op-cost as a singleton).
   - **Equivalent Ethereum Precompiled Contracts**:
      0x08 (ecPairing): This precompile handles Miller’s algorithm and the final exponentiation in Ethereum’s Groth16 verifier.

### 4. **Final Exponentiation**
   - **Objective**: Compute the final exponentiation to \( (p^{12} - 1) / r \) that maps the Miller output into the r-th roots of unity in \( \mathbb{F}_{p^{12}} \).
   - **Tasks**:
     - Implement the Frobenius endomorphism over \( \mathbb{F}_{p^{12}} \).
     - Split into the "easy" part (using the \( p^6 - 1 \) and \( p^2 + 1 \) Frobenius powers) and the "hard" part, leveraging conjugates and cyclotomic squaring.
     - Split the computation into small chunks to stay within op-cost and stack limits.
   - **Milestone**: ✅ Final exponentiation (`singleton/pairing/finalexp.cash`) verified == `@noble/curves`: valid Miller output → 1, invalid → ≠ 1 (~255M op-cost, 9.3 KB as a singleton).

### 5. **Verification Equation for Groth16**
   - **Objective**: Assemble the Groth16 check `e(A, B) == e(alpha, beta) * e(X, gamma) * e(C, delta)`.
   - **Tasks**:
     - Pass the verification key into the verifier: alpha (\( G1 \)); beta, gamma, delta (\( G2 \)); and the IC points (\( G1 \), the constant term plus one per public input). The VK is hard-coded per circuit; the proof (A, B, C) and public inputs are supplied at runtime.
     - Aggregate the public inputs as X = IC[0] + sum_i (input_i * IC[i]) **on-chain** (the `vk_x` computation in `singleton/vkx.cash` / `chunked/`).
     - Fold the check into a single multi-pairing product by negating A and requiring `e(-A, B) * e(alpha, beta) * e(X, gamma) * e(C, delta) == 1` (the form used by the EVM ecPairing precompile). **Done** in `singleton/pairing/groth16.cash` (contract `Groth16Verify`): computes `vk_x` on-chain, negates A in-script, runs the four pairings + final exponentiation, and `require`s == 1.
   - **Milestone**: ✅ Complete, sound verifier: valid proofs accept, tampered inputs reject (singleton ~1.26B op-cost).

### 6. **Testing and Optimization**
   - **Objective**: Validate each component and the full verifier with known test cases.
   - **Tasks**:
     - Develop unit tests for all arithmetic and pairing functions. **Done**: each `.cash` layer has a matching `.mjs` grader that compiles it with the forked `cashc`, runs it on the loosened BCH 2026 VM, and checks the result against `@noble/curves` / `py_ecc`.
     - Test with actual Groth16 proofs to verify functionality and correct behavior. **Done**: valid proofs accept, tampered inputs reject, in both the singleton and chunked forms.
     - Optimize for op-cost and size. **Done**: Jacobian G1 (one Fermat inverse), hard-coded prime, lazy add-reduction, dedicated Fp12 squaring, and tuned per-chunk padding. The chunked full verifier currently lands at 116 steps / ~789M op-cost (see the build memos).
   - **Milestone**: ✅ All functions validated and optimized; the chunked verifier fits the BCH per-input limits (≤10 KB, ≤8,032,800 op-cost) at every step.

### 7. **Deploy and Document**
   - **Objective**: Finalize the CashScript implementation and provide documentation.
   - **Tasks**:
     - Document each function’s purpose, input, and output.
     - Provide deployment instructions for CashScript environments, including any required precompiled contracts.
   - **Milestone**: Fully documented and deployable Groth16 verifier in CashScript.

This modular approach should guide you in building the Groth16 verifier in manageable stages, each focusing on specific components required for zero-knowledge proof verification.

In summary, Steps 1-3 parallel Ethereum's precompiled contracts (0x06, 0x07, and 0x08) by implementing equivalent functionality from scratch in CashScript for Bitcoin Cash. While Ethereum can use these precompiles to execute complex curve operations rapidly, implementing these manually on BCH allows for flexibility but requires optimizations, particularly around operations like Miller’s algorithm.
