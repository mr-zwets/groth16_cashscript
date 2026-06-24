// Reference vk_x computation using @noble/curves bn254 (== BN254 / alt_bn128).
//
// vk_x = IC0 + input0*IC1 + input1*IC2  (all G1 points, affine)
//
// Emits the chosen IC points, public inputs, the correct expected vk_x and a
// deliberately-wrong point, as JSON for the CashScript/libauth harness to consume.
//
// JS port of the former vkx_ref.py: the authoritative reference is @noble/curves
// bn254 (was py_ecc.bn128); both are alt_bn128 so the vectors are identical.
import { bn254 } from '@noble/curves/bn254.js';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const Point = bn254.G1.Point;
const p = Point.Fp.ORDER; // base field modulus
const r = Point.Fn.ORDER; // subgroup / curve order
if (p !== 21888242871839275222246405745257275088696311157297823662689037894645226208583n) throw new Error('p mismatch');
if (r !== 21888242871839275222246405745257275088548364400416034343698204186575808495617n) throw new Error('r mismatch');

// Choose IC points as fixed multiples of G1 (guaranteed on-curve, in the subgroup).
const G1 = Point.BASE;
const ic0 = G1.multiply(5n);  // constant term
const ic1 = G1.multiply(7n);
const ic2 = G1.multiply(11n);

// Public inputs (scalars mod r).
const input0 = 123456789n;
const input1 = 987654321n;

// vk_x = IC0 + input0*IC1 + input1*IC2
const vkx = ic0.add(ic1.multiply(input0)).add(ic2.multiply(input1)).toAffine();

const aff = (P) => { const { x, y } = P.toAffine(); return [x, y]; };

const ic0a = aff(ic0), ic1a = aff(ic1), ic2a = aff(ic2);
const expected = [vkx.x, vkx.y];
// a wrong point: just bump y by 1 (off curve / wrong, used for reject test)
const wrong = [vkx.x, (vkx.y + 1n) % p];

// Emit JSON matching the former python json.dump(indent=2): `p`/`r` as quoted
// strings, big coords as bare (unquoted) JSON integers expanded one per line.
const arr = ([a, b]) => `[\n    ${a},\n    ${b}\n  ]`;
const out = `{
  "p": "${p}",
  "r": "${r}",
  "ic0": ${arr(ic0a)},
  "ic1": ${arr(ic1a)},
  "ic2": ${arr(ic2a)},
  "input0": ${input0},
  "input1": ${input1},
  "expected": ${arr(expected)},
  "wrong": ${arr(wrong)}
}`;

console.log(out);
writeFileSync(join(here, 'vkx_vectors.json'), out);
