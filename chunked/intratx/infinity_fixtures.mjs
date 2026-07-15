import { bn254, vec, vk, vkxPoint } from '../pairing/_millermath.mjs';

const R = bn254.fields.Fr.ORDER;
const Fp12 = bn254.fields.Fp12;
const modR = (value) => ((value % R) + R) % R;
const invR = (value) => bn254.fields.Fr.inv(modR(value));
const g1 = (scalar) => modR(scalar) === 0n
  ? bn254.G1.Point.ZERO
  : bn254.G1.Point.BASE.multiply(modR(scalar));
const g2 = (scalar) => modR(scalar) === 0n
  ? bn254.G2.Point.ZERO
  : bn254.G2.Point.BASE.multiply(modR(scalar));

const scalars = vec.scalars;
const alpha = BigInt(scalars.alpha);
const beta = BigInt(scalars.beta);
const gamma = BigInt(scalars.gamma);
const delta = BigInt(scalars.delta);
const ic = scalars.ic.map(BigInt);
const vkExponent = ([in0, in1]) => modR(ic[0] + in0 * ic[1] + in1 * ic[2]);
const fixedExponent = (inputs) => modR(alpha * beta + vkExponent(inputs) * gamma);
const solveC = (inputs, a = 0n, b = 0n) => modR((a * b - fixedExponent(inputs)) * invR(delta));
const ordinaryInputs = [17n, 29n];
const zeroFixedInputs = [37n, modR(
  (modR(-alpha * beta * invR(gamma)) - ic[0] - 37n * ic[1]) * invR(ic[2]),
)];

if (fixedExponent(ordinaryInputs) === 0n || fixedExponent(zeroFixedInputs) !== 0n) {
  throw new Error('failed to construct deterministic infinity-proof input fixtures');
}

const definitions = [
  { name: 'a-infinity', inputs: ordinaryInputs, a: 0n, b: 5n, c: solveC(ordinaryInputs) },
  { name: 'b-infinity', inputs: ordinaryInputs, a: 7n, b: 0n, c: solveC(ordinaryInputs) },
  { name: 'c-infinity', inputs: ordinaryInputs, a: 1n, b: fixedExponent(ordinaryInputs), c: 0n },
  { name: 'a-b-infinity', inputs: ordinaryInputs, a: 0n, b: 0n, c: solveC(ordinaryInputs) },
  { name: 'a-c-infinity', inputs: zeroFixedInputs, a: 0n, b: 11n, c: 0n },
  { name: 'b-c-infinity', inputs: zeroFixedInputs, a: 13n, b: 0n, c: 0n },
  { name: 'all-infinity', inputs: zeroFixedInputs, a: 0n, b: 0n, c: 0n },
  { name: 'finite-b-base', inputs: ordinaryInputs, a: 7n, b: 1n, c: solveC(ordinaryInputs, 7n, 1n) },
  { name: 'vkx-msm-infinity', inputs: [0n, 0n], a: 19n, b: 23n, c: solveC([0n, 0n], 19n, 23n) },
];

const verifies = (proof, inputs) => Fp12.eql(bn254.pairingBatch([
  { g1: proof.a.negate(), g2: proof.b },
  { g1: vk.alpha, g2: vk.beta },
  { g1: vkxPoint(inputs), g2: vk.gamma },
  { g1: proof.c, g2: vk.delta },
].filter((pair) => !pair.g1.equals(bn254.G1.Point.ZERO) && !pair.g2.equals(bn254.G2.Point.ZERO)), true), Fp12.ONE);

export const infinityInstances = Object.fromEntries(definitions.map((definition) => {
  const proof = { a: g1(definition.a), b: g2(definition.b), c: g1(definition.c) };
  const alteredInputs = [definition.inputs[0], modR(definition.inputs[1] + 1n)];
  if (!verifies(proof, definition.inputs)) {
    throw new Error(`${definition.name} does not satisfy the fixed Groth16 pairing equation`);
  }
  if (verifies(proof, alteredInputs)) {
    throw new Error(`${definition.name} unexpectedly verifies after altering a public input`);
  }
  return [definition.name, { proof, inputs: definition.inputs, alteredInputs }];
}));
