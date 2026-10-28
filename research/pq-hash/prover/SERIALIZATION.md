# pq-hash proof serialization (v1)

This is the byte-level contract between the off-chain prover (`prover.py`), the reference verifier (`verifier.py`) and the on-chain verifier that the Build phase writes. It implements SPEC.md §3 (zk-verifier-bench `wip/pq-hash-design`, commit c3497a1). Where the SPEC leaves a choice open, this document fixes it; those choices are listed in §8.

All hashing is SHA-256. Every "u8 / u16 / u64" is little-endian. `‖` is concatenation.

## 1. Encodings

| object | bytes | encoding |
|---|--:|---|
| base element (F_p, p = 2^64 − 2^32 + 1) | 8 | little-endian. Decoded unsigned and reduced mod p: `BIN2NUM(b ‖ 0x00) mod p`. **No range check**: a non-canonical value is simply another committed value (SPEC §3.1). |
| extension element (F_{p^e} = F_p[u]/(u^e − 7)) | 8e | coefficients c0, c1[, c2] (value c0 + c1·u + c2·u^2), each as a base element |
| statement x_in, y_out | 8 + 8 | base elements, but **must be canonical (< p)**; the verifier rejects otherwise |
| Merkle digest (roots, siblings) | h | SHA-256 output truncated to its first h bytes (h = 25 or 32) |
| grinding nonce | 8 | u64 |

e = 3 for P100, P128 and C128; e = 2 for U100 and C100 (comparison sets).

**Digest to field element, E(d).** v = LE(d) (unsigned, < 2^256); c_i = (v div p^i) mod p for i < e.

**Digest to index.** idx = LE(d) mod N_1 (N_1 is a power of two, so this is the low log2(N_1) bits).

**Grinding check.** The top g bits of G are zero, reading G as a big-endian bit string: for g = 28, G[0] = G[1] = G[2] = 0 and G[3] < 0x10.

## 2. Parameters, constants and TAG

| set | param-id | regime | e | n | N = n/ρ | arities | final coeffs | s | g | h | m |
|---|--:|---|--:|---|---|---|--:|--:|--:|--:|--:|
| P100 | 1 | provable (Johnson) | 3 | 2^16 | 2^23 | 4, 8, 8 | 256 | 22 | 28 | 25 | 3 |
| P128 | 2 | provable (Johnson) | 3 | 2^16 | 2^21 | 4, 8, 8 | 256 | 43 | 28 | 32 | 4 |
| U100 | 3 | provable (unique decoding), comparison | 2 | 2^16 | 2^20 | 4, 8, 8 | 256 | 79 | 28 | 25 | 3 |
| C100 | 4 | **conjectured**, comparison | 2 | 2^16 | 2^23 | 8, 16, 8 | 64 | 11 | 28 | 25 | 3 |
| C128 | 5 | **conjectured**, comparison | 3 | 2^16 | 2^23 | 4, 16, 8 | 128 | 15 | 28 | 32 | 3 |

(m is the Johnson multiplicity used in the soundness bound; it only enters the TAG for U100/C100/C128.)

Domains:
- ω_k = 7^((p−1)/k) for a power of two k. ω_n is the trace generator, ω_N the L_0 generator; ω_n = ω_N^(N/n).
- Layer sizes N_0 = N, N_{i+1} = N_i / a_i. Layer shifts: shift_0 = 7, shift_{i+1} = shift_i^{a_i}.
- Point u of L_i is shift_i · ω_{N_i}^u.

Round constants: C[j] = LE(SHA256("verifier.cash/pq-hash/rc" ‖ u8 j)) mod p, for j < 8. P_c is the polynomial of degree < 8 with P_c(ω_8^j) = C[j]. Its coefficients are P_c[k] = (1/8)·Σ_j C[j]·ω_8^(−jk).

**Baked constants**, the byte string K:

```
K = C[0..7] (8 × u64) ‖ P_c[0..7] (8 × u64) ‖ ω_n (u64) ‖ ω_N (u64)
    ‖ u8 e ‖ u8 7 ‖ u8 log2 n ‖ u8 log2 N ‖ u8 r ‖ u8 a_0 … u8 a_{r−1}
    ‖ u8 log2(final coeffs) ‖ u16 s ‖ u8 g ‖ u8 h ‖ u8 m
```

Here r is the number of folds (3 for every set).

**TAG** (57 bytes) = "verifier.cash/pq-hash/v1" (24 ASCII bytes) ‖ u8 param-id ‖ SHA256(K). Each vector file stores it as `params.tag_hex`.

## 3. Fiat-Shamir transcript

Each transcript state t_i is a full 32-byte digest, and every challenge is derived from a full 32-byte digest. "a", "z", "g" and "b" are single ASCII bytes.

```
t0 = SHA256(TAG ‖ x_in ‖ y_out)
t1 = SHA256(t0 ‖ root_trace)              α_j = E(SHA256(t1 ‖ "a" ‖ u8 j)), j = 1..4
t2 = SHA256(t1 ‖ root_comp)               z   = E(SHA256(t2 ‖ "z"))            reject if z ∈ F_p
t3 = SHA256(t2 ‖ OOD)                     γ_j = E(SHA256(t3 ‖ "g" ‖ u8 j)), j = 1..5;  β_1 = E(SHA256(t3 ‖ "b"))
t_{3+i} = SHA256(t_{2+i} ‖ root_fri_i)    β_{i+1} = E(SHA256(t_{3+i} ‖ "b")),  i = 1..r−1
t_{3+r} = SHA256(t_{2+r} ‖ final)
G  = SHA256(t_{3+r} ‖ nonce)              require grinding(G, g)
idx_q = LE(SHA256(G ‖ u16 q)) mod N_1,  q = 0..s−1   (with replacement)
```

For r = 3 this is exactly SPEC §3.4 (t4 absorbs root_fri1, t5 absorbs root_fri2, t6 absorbs final).
- OOD is the 5 extension elements X(z), Y(z), X(ω_n·z), H0(z), H1(z), in that order (5·8e bytes).
- final is the 2^log_df extension coefficients c_0 … c_{D−1}, lowest degree first.
- The honest prover's nonce is the smallest u64 that passes grinding.

The `derived.transcript` field of each vector lists every t_i and G, and `derived.alpha/z/gamma/beta/indices` list the challenges, so a script implementation can be checked step by step.

## 4. Canonical proof byte stream

The canonical proof is the single-input layout (b) of SPEC §7, without script pushes:

```
proof = PT ‖ LEAVES ‖ SIBLINGS
```

### 4.1 PT (public transcript), fields in transcript order

| field | bytes |
|---|--:|
| x_in | 8 |
| y_out | 8 |
| root_trace | h |
| root_comp | h |
| OOD | 5 · 8e |
| root_fri1 … root_fri{r−1} | (r−1) · h |
| final | 2^log_df · 8e |
| nonce | 8 |

PT size: P100 6,388 B; P128 6,416 B; U100 4,300 B; C100 1,228 B; C128 3,344 B (the SPEC §3.5 values).

### 4.2 LEAVES

For each query q = 0..s−1, in query order, one leaf per tree: trace, comp, fri1, …, fri{r−1}. **Duplicates are kept**: two queries with the same index carry the same leaf twice, and the verifier requires the two to agree (§4.3).

Positions:
- pos_0 = idx_q. For i = 0..r−1, pos_{i+1} = pos_i mod N_{i+1}.
- The leaf of layer i is leaf number pos_{i+1} of that layer's tree. The trace and comp trees are layer 0; fri_i is layer i.
- The value f_i(pos_i) sits in slot pos_i div N_{i+1} of that leaf.

A leaf holds a coset. Leaf v of layer i holds the values at points u = v + j·N_{i+1}, for j = 0..a_i−1 in j order. Those points are x_j = x0·ω_{a_i}^j, with x0 = shift_i·ω_{N_i}^v.

| tree | tag byte | leaf content per point j | leaf bytes (P100/P128) |
|---|---|---|--:|
| trace | 0x01 | X(x_j) ‖ Y(x_j) (2 base elements) | a_0·16 = 64 |
| comp | 0x02 | H0(x_j) ‖ H1(x_j) (2 extension elements) | a_0·16e = 192 |
| fri_i | 0x02 + i | f_i(x_j) (1 extension element) | a_i·8e = 192 |

### 4.3 Merkle trees and SIBLINGS

- leaf hash = SHA256(tag ‖ leaf bytes)[0:h]
- node = SHA256(left ‖ right)[0:h], untagged
- A tree of depth d has 2^d leaves. Leaf v sits at level 0, the root at level d, and the parent of node k at level ℓ is node k >> 1 at level ℓ+1.

SIBLINGS holds the deduplicated multiproofs, tree by tree in the order trace, comp, fri1, …, fri{r−1}. Each is h bytes per sibling, and nothing else (no counts). The canonical order and the verification are the same procedure:

```
cur := map position -> digest, built from the s (position, leaf hash) pairs in query order;
       if a position repeats with a different leaf hash: REJECT (duplicate leaf mismatch)
for level = 0 .. d-1:
    for k in sorted(keys(cur)) (ascending), skipping a k consumed as a right partner:
        if k even and k+1 in cur:  parent = node(cur[k], cur[k+1])
        elif k even:               sib = next h bytes; parent = node(cur[k], sib)
        else (k odd, k-1 absent):  sib = next h bytes; parent = node(sib, cur[k])
        next[k >> 1] = parent
    cur := next
require cur == {0: root}
```

The proof must be consumed exactly: after the last tree, no bytes may remain.

**Full per-query paths.** Layout (a) uses pruned caps (SPEC §6.2). Each vector file therefore also stores, for every query and tree, the leaf index, the leaf bytes and the full authentication path (`openings[q].trees[name].path`, LSB-first: path[ℓ] is the sibling at level ℓ). It also stores the multiproof siblings per tree (`multiproof[name]`). Every level-c node and every pruned-cap TOP blob can be derived from these.

## 5. Verifier algorithm and rejection reasons

`verifier.py` checks in this order. The first failing check gives the reason, and a vector's `expect_reason_prefix` matches its start.

1. `parse: proof shorter than PT + leaves`
2. `statement: non-canonical public input` (x_in or y_out ≥ p); `statement: proof is for a different statement` (when the caller supplies the expected statement)
3. Transcript up to z; `z-in-base-field` if z ∈ F_p, which means c1 = c2 = 0, or c1 = 0 for e = 2.
4. `air: composition identity at z fails`. This is the cross-multiplied identity of SPEC §2:

   ```
   (H0(z) + z^n·H1(z))·(z^n−1)(z−1)(z−ω^{n−1})
     == (α1·C1 + α2·C2)·(z−ω^{n−1})^2·(z−1) + α3·(X(z)−x_in)(z^n−1)(z−ω^{n−1}) + α4·(X(z)−y_out)(z^n−1)(z−1)
   ```

   Here C1 = Y(z) − s^3, C2 = X(ωz) − Y(z)^2·s, s = X(z) + P_c(z^{n/8}) and ω = ω_n.
5. `grinding: proof-of-work check fails`
6. Merkle, per tree in order: `merkle: duplicate leaf mismatch in <tree>`, `merkle: root mismatch in <tree>`, `parse: proof truncated inside multiproof`, then `parse: trailing bytes after multiproofs`.
7. For each query, in order:
   - DEEP at the a_0 coset points: f0(x) = [γ1(X(x)−X(z)) + γ2(Y(x)−Y(z)) + γ4(H0(x)−H0(z)) + γ5(H1(x)−H1(z))]/(x−z) + γ3(X(x)−X(ωz))/(x−ωz).
   - Fold with β_1, giving f_1(pos_1). For i = 1..r−1, compare with slot pos_i div N_{i+1} of the fri_i leaf (`fri: layer i value does not match fold of layer i−1`), then fold that leaf with β_{i+1}.
   - Finally compare with Σ_k c_k·y^k at y = shift_r·ω_{N_r}^{pos_r} (`fri: final polynomial does not match last fold`).

   Fold of a coset (v_0 … v_{a−1}) at x0 with challenge β:

   ```
   f' = (1/a) · Σ_{t<a} (β·x0^{−1})^t · V_t,    V_t = Σ_j v_j · ω_a^{−jt}
   ```

## 6. Vector files (`vectors/<SET>-<k>.json`, format `pq-hash/vector/v1`)

| key | content |
|---|---|
| `params` | the parameter set: shape, trees (tag, depth, leaf bytes), `tag_hex`, soundness rows, design byte expectation |
| `statement` | `x_in`, `y_out` (decimal strings), statement number k; x_in = LE(SHA256("verifier.cash/pq-hash/x_in" ‖ u8 k)) mod p |
| `proof`, `proof_bytes` | canonical proof (hex) and its length |
| `sections` | PT / leaves / siblings per tree, and the plain-path size for comparison |
| `nonce` | grinding nonce (integer) |
| `derived` | transcript states, G, α, z, γ, β (extension elements as 8e-byte hex), indices, AIR intermediate values (z^n, c(z), both sides), and per query: positions, f0 at the a_0 coset points, each fold result |
| `openings` | per query and tree: leaf index, leaf hex, full path |
| `multiproof` | per tree, the canonical sibling list |
| `tampered` (k = 0 only) | rejection cases: `patches` (offset + `xor` or replacement `bytes`), or `truncate`/`append`, or a full `proof_hex`; optional `want_statement`; `expect_reason_prefix` and `observed_reason` |

`python3 verifier.py vectors/*.json` re-verifies every valid proof and every tamper case.

## 7. Notes for the on-chain verifier

- Every extension element in the transcript is serialized exactly as it appears in the proof. The script never re-encodes a value before hashing, except in optimisation O1, which this format does not use.
- Leaves are hashed as opened, so non-canonical bytes in a leaf are hashed as given and then reduced mod p before arithmetic.
- The statement is the only range check.
- Duplicate query indices are legal and appear in practice (sampling with replacement).

## 8. Choices fixed here that SPEC.md leaves open

1. PT field order is transcript order: x_in, y_out, root_trace, root_comp, OOD, root_fri1, root_fri2, final, nonce.
2. Leaf tags: trace 0x01, comp 0x02, fri_i 0x02 + i.
3. Param-ids 3, 4 and 5 for the comparison sets U100, C100 and C128.
4. The byte string K of baked constants (§2).
5. Digests are read as little-endian integers everywhere (C[j], E(d), indices, statement x_in). Grinding reads the leading bytes.
6. The nonce is a u64, little-endian, and the prover takes the smallest valid one.
7. u16 query counters are little-endian.
8. For e = 2, E(d) takes 2 base-p digits and z ∈ F_p means c1 = 0. The extension is u^2 = 7.
9. The canonical proof's multiproof covers each tree separately. The trace and comp trees share positions, but their siblings are not shared.
