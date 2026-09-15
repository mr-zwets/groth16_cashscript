# Four-coordinate projective GT certificate

Run from the repository root:

```sh
node chunked/bls12-381/prove_gt_projective_chart.mjs
```

The executable emits a JSON mathematical certificate and exits nonzero on a failed assertion. It uses the repository's pinned `@noble/curves` dependency, no compiler, cache, external files, network, or fixture setup scalars. It does not change or replace the existing soundness, resource, corpus, or benchmark gates.

The universal arguments below establish the map for every target-group element and every canonical parameter tuple. Executable checks include exact symbolic identities, independent field arithmetic, public constant certificates and a fixed-schedule degree calculation. Finite samples supplement those arguments; they do not establish universal claims by themselves.

## Field and target

Let `k=Fp2=Fp[i]/(i²+1)`, `xi=1+i`, `L=k[Z]/(Z³−xi)` and `Fp12=L[W]/(W²−Z)`. Set `theta=WZ`, so theta²=xi. The executable checks p≡3 mod4, xi is not a cube in k, and xi is nonsquare in k. Thus the quadratic and cubic tower factors are irreducible. In particular Z is nonsquare in L: its norm to k is the nonsquare xi. Consequently `Fp12` is a field and nonzero factors cannot multiply to zero.

Let g be the exact desired GT contribution, of order dividing the odd scalar order r. The public-cache generator constructs its position-adjusted preimage bases in GT and all table entries by products and powers of those bases. This closure argument covers the entire table, including identity entries. The map does not use the fixture's setup scalars.

The executable checks `r | (p⁴−p²+1)` and `r | (p⁸+p⁴+1)`. Hence g has norm1 to Fp4 and conjugation over L sends g to g⁻¹. For the current pre-conjugated table, the encoder receives `conjugate(entry)`, not its normalized `[1,−u]` representative. Multiplication by an arbitrary Fp6 scale preserves the quotient class but need not preserve GT membership, so normalized representatives are not valid encoder inputs.

## Encoder, decoder and complete chart

For g≠1, define

```
a = theta*(g²+1)/(g²−1) = a0+a1*Z+a2*Z²
ell = xi*((a1−1)/3+a2−1/3)
s = a0/ell
t = (a1−1)/ell.
```

The first denominator is nonzero: g²=1 in a group of odd order implies g=1. Conjugation fixes a, so a belongs to L. Its quadric equation is

```
a0²−xi*a1*a2 = −xi/3.
```

To derive it, multiplication by a+theta on the Fp4 basis `(1,Z,Z²)` has matrix

```
[ a0+theta, xi*a2,    xi*a1    ]
[ a1,       a0+theta, xi*a2    ]
[ a2,       a1,       a0+theta ]
```

The executable expands this determinant as an exact integer polynomial and reduces theta²=xi. The odd coefficient is `3*(a0²−xi*a1*a2)+xi`. Since `(a+theta)/(a−theta)=g²` has norm1 to Fp4, the odd coefficient vanishes. None of these steps depends on sampled table entries.

Decode any s,t in k using

```
h = s²−t+(xi/3)*t²
A = s
B = h+t
C = (h−t)/3+1/xi
D = A+B*Z+C*Z²
N = h*Z.
```

The factor is `D+W*N`. Exact symbolic expansion, clearing denominators by 9xi, proves

```
A²−xi*B*C+(xi/3)*h² = 0
ell(D/h)*h = 1                     when h≠0.
```

This parametrizes the second intersection with the quadric of the line from `(0,1,1/3)` in direction `(s,t,1/xi−t/3)`. The inverse linear form and the quadric equation recover the original a. D is universally nonzero: D=0 forces h=0 from the first identity, B=t=0, then C=1/xi≠0, a contradiction. This also covers malformed but canonical parameter tuples, without an inverse witness.

If ell=0 on the affine quadric, let delta=a−(0,1,1/3). Substitution gives `delta0²+(xi/3)*delta1²=0`. The executable checks that −xi/3 is nonsquare in k; therefore delta=0. The sole finite exception is `(0,1,1/3)`. Its Cayley image is explicitly calculated, and independent flat-field exponentiation proves its r-th power is not 1. This excludes the exception from every g² in GT. The full nonidentity r-th power is included in the emitted certificate.

For g=1 emit s=t=0. The decoder returns h=N=0 and D=Z²/xi, a nonzero identity representative. Other canonical tuples can also represent identity, such as s=0,t=3/xi. Only the designated zero encoding should be emitted by preprocessing; exact authenticated bytes, not the decoded quotient class, bind the table entry. The decoder is not a GT membership recognizer.

For nonidentity targets, `D/h=a` gives

```
(D+W*N)/conjugate(D+W*N) = (a+theta)/(a−theta) = g²
g/conjugate(g) = g².
```

Their ratio is therefore fixed by conjugation and is a nonzero Fp6 scale. This proves exact equality with the current quotient class. Encoding the Cayley transform of g rather than g² would give the wrong class. Later squarings preserve equality of classes by squaring the nonzero scale; existing boundary charts and final conjugation remain valid.

## Scaled factor and flat coefficients

Multiplying the complete factor by the nonzero public constant 9xi removes the decoder's fractional constants. With `H=3s²−3t+xi*t²=3h`, the exact scaled components are

```
D' = 9xi*s + 3xi*(H+3t)*Z + (xi*(H−3t)+9)*Z²
N' = 3xi*H*Z.
```

This multiplication is in the field before flattening. It preserves the quotient class and universal nonzero property. Write s=(s0,s1), t=(t0,t1), H=(H0,H1) in the basis `(1,i)`. Substituting `i=Y³−1`, `Z=Y`, the coefficients of D', in ascending powers of Y, are

```
[-18s1, -6H1−18t1, -2H1+6t1+9,
 9(s0+s1), 3(H0+H1+3t0+3t1), H0+H1−3t0−3t1].
```

N' has coefficient −6H1 at Y and `3(H0+H1)` at Y⁴. The executable establishes these identities symbolically from the Fp2 components, and checks that the complement-based positive representatives differ only by known multiples of p. All coefficients are interpreted modulo p. For canonical complement arguments, `p−value` lies in `[1,p]`; the internal p endpoint represents zero and is intentional. It must not relax canonical checks on serialized parameters.

Thus deg(D')≤5 and deg(N')≤4; the full polynomial in W has degree≤10. Compute H in Fp2 and flatten the reduced field coefficients before evaluating at alpha. Scaling an already evaluated polynomial by a guessed value of 9xi, or computing extension arithmetic directly at alpha, is invalid because reduction modulo the extension polynomial does not commute with evaluation at an arbitrary challenge.

## Fixed-schedule q132 bound

The executable propagates polynomial supports by convolution under W²=Y. It overapproximates all coefficient cancellations and handles both canonical input charts `(1,u)` and `(0,1)`. The schedule assumptions are explicit in the emitted JSON: 63 binary rounds for `0xd201000000010000`, two active Miller pairs, root factors on nonzero bits, 21 three-round blocks, splits after six operations in blocks 0 and 15, two PIC factors on each of the 16 listed carriers, and the unchanged final normalized factor.

Under that schedule, every projective carrier's cross-relation degree is at most 136, while unchanged segments still attain 137. The terminal degree is 16. Division by the degree 6 field modulus needs at most 132 quotient coefficients. The executable proves those fixed-schedule bounds without a generated cache or fixture coefficients.

It does not inspect the live generator or prove that future operation schedules still match. The owning generator's degree certificate must be checked against these assumptions during integration. Nor does the mathematical degree bound establish operation-cost, stack-width, or density limits. Those require the existing strict resource certificates for the generated worker bytecode.

## Evidence and acceptance boundary

Independent Fp2 and flat `Fp[W]/(W^12−2W^6+2)` arithmetic check 26 public GT/conjugate round trips, including identity and inverses, with both the original and 9xi-scaled factors. An additional 625 canonical extremal tuples check the homogeneous relation and nonzero D. The executable also checks alternate identity encodings and rejects explicit out-of-range inputs in its own probe input contract. These are not runtime parsing tests.

Full acceptance still requires table-wide canonical and exact projective differential coverage, versioned leaf/domain/root generation, preserved window/digit/path and worker authentication, unchanged Fiat–Shamir ordering, regenerated quotient witnesses, both resource certificates, the complete mutation corpus and the official benchmark. This certificate establishes no stronger input-validation or subgroup-validation claim than the declared cofactor-equivalent construction.
