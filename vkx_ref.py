"""Reference vk_x computation using py_ecc.bn128 (== BN254 / alt_bn128).

vk_x = IC0 + input0*IC1 + input1*IC2  (all G1 points, affine)

Emits the chosen IC points, public inputs, the correct expected vk_x and a
deliberately-wrong point, as JSON for the CashScript/libauth harness to consume.
"""
import json
from py_ecc.bn128 import G1, multiply, add, curve_order, field_modulus

def normalize(P):
    # bn128 G1 points are affine (FQ, FQ) already.
    return (P[0], P[1])

p = field_modulus
r = curve_order
assert p == 21888242871839275222246405745257275088696311157297823662689037894645226208583
assert r == 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Choose IC points as fixed multiples of G1 (guaranteed on-curve, in the subgroup).
ic0 = multiply(G1, 5)      # constant term
ic1 = multiply(G1, 7)
ic2 = multiply(G1, 11)

# Public inputs (scalars mod r).
input0 = 123456789
input1 = 987654321

# vk_x = IC0 + input0*IC1 + input1*IC2
acc = ic0
acc = add(acc, multiply(ic1, input0))
acc = add(acc, multiply(ic2, input1))
vkx = normalize(acc)

def aff(P):
    x, y = normalize(P)
    return [int(x), int(y)]

out = {
    "p": str(p),
    "r": str(r),
    "ic0": aff(ic0),
    "ic1": aff(ic1),
    "ic2": aff(ic2),
    "input0": input0,
    "input1": input1,
    "expected": [int(vkx[0]), int(vkx[1])],
    # a wrong point: just bump y by 1 (off curve / wrong, used for reject test)
    "wrong": [int(vkx[0]), (int(vkx[1]) + 1) % p],
}

print(json.dumps(out, indent=2))
with open("vkx_vectors.json", "w") as f:
    json.dump(out, f, indent=2)
