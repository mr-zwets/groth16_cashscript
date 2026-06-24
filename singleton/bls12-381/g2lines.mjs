// Grade singleton/bls12-381/g2lines.cash (pointDouble / pointAdd) against the proven
// JS formulas (which match noble bls12-381). Run: node singleton/bls12-381/g2lines.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

import { bls12_381 } from '@noble/curves/bls12-381.js';
const { Fp, Fp2 } = bls12_381.fields;
const INV2 = Fp2.div(Fp2.ONE, Fp2.fromBigTuple([2n, 0n]));
// M-twist b' = 4*(1+u): (4 c0 - 4 c1) + (4 c0 + 4 c1) u
const mulByB = (x) => Fp2.fromBigTuple([
  Fp.sub(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n)),
  Fp.add(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n)),
]);

function pointDouble(Rx, Ry, Rz) {
  const t0 = Fp2.sqr(Ry), t1 = Fp2.sqr(Rz);
  const t2 = mulByB(Fp2.mul(t1, 3n)), t3 = Fp2.mul(t2, 3n);
  const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
  const c0 = Fp2.sub(t2, t0), c1 = Fp2.mul(Fp2.sqr(Rx), 3n), c2 = Fp2.neg(t4);
  const nx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), INV2);
  const ny = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), INV2)), Fp2.mul(Fp2.sqr(t2), 3n));
  const nz = Fp2.mul(t0, t4);
  return [c0, c1, c2, nx, ny, nz];
}
function pointAdd(Rx, Ry, Rz, Qx, Qy) {
  const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz)), t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz));
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), c1 = Fp2.neg(t0), c2 = t1;
  const t2 = Fp2.sqr(t1), t3 = Fp2.mul(t2, t1), t4 = Fp2.mul(t2, Rx);
  const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, 2n)), Fp2.mul(Fp2.sqr(t0), Rz));
  const nx = Fp2.mul(t1, t5);
  const ny = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry));
  const nz = Fp2.mul(Rz, t3);
  return [c0, c1, c2, nx, ny, nz];
}
const flat2 = (arr) => arr.flatMap((x) => [x.c0, x.c1]); // Fp2[] -> ints

const here = dirname(fileURLToPath(import.meta.url));
const rng = splitmix64(0x67326c6en); // "g2ln"
const randFp2 = () => Fp2.fromBigTuple([randFp(rng), randFp(rng)]);
const N = 5;
const vectors = [];
for (let i = 0; i < N; i++) {
  const Rx = randFp2(), Ry = randFp2(), Rz = randFp2();
  const Qx = randFp2(), Qy = randFp2();
  vectors.push([
    Rx.c0, Rx.c1, Ry.c0, Ry.c1, Rz.c0, Rz.c1,
    Qx.c0, Qx.c1, Qy.c0, Qy.c1,
    ...flat2(pointDouble(Rx, Ry, Rz)),
    ...flat2(pointAdd(Rx, Ry, Rz, Qx, Qy)),
  ]);
}

const template = compileTemplate(join(here, 'g2lines.cash'));
console.log(`g2lines: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('pointDouble+pointAdd', template, vectors, { tamperIndex: 10 });
process.exit(ok ? 0 : 1);
