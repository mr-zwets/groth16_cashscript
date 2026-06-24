// Port the EXACT vkx.cash algorithm to JS and compare against the reference vk_x.
//
// Dev cross-check (not part of any build): a JS port of the vkx.cash Jacobian
// double-and-add loop, run against the @noble/curves-derived expected point in
// vkx_vectors.json to prove the contract algorithm matches. Handy as an
// executable spec when debugging the singleton vk_x. JS port of vkx_sim.py.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const addFp = (x, y) => (x + y) % p;
const subFp = (x, y) => (x - y + p) % p;
const mulFp = (x, y) => (x * y) % p;
const sqrFp = (x) => (x * x) % p;
const modpow = (base, exp, mod) => {
  let r = 1n, b = base % mod, e = exp;
  while (e > 0n) { if (e & 1n) r = (r * b) % mod; b = (b * b) % mod; e >>= 1n; }
  return r;
};

// dbl-2009-l
function jacDouble(X, Y, Z) {
  const a = sqrFp(X), b = sqrFp(Y), c = sqrFp(b);
  const d = mulFp(2n, subFp(subFp(sqrFp(addFp(X, b)), a), c));
  const e = mulFp(3n, a), f = sqrFp(e);
  const nx = subFp(f, mulFp(2n, d));
  const ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8n, c));
  const nz = mulFp(2n, mulFp(Y, Z));
  return [nx, ny, nz];
}

// mirror contract: returns (X,Y,Z); assumes neither is infinity (Z!=0)
function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  const z1z1 = sqrFp(aZ), z2z2 = sqrFp(bZ);
  const u1 = mulFp(aX, z2z2), u2 = mulFp(bX, z1z1);
  const s1 = mulFp(mulFp(aY, bZ), z2z2), s2 = mulFp(mulFp(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = subFp(u2, u1), i2 = sqrFp(mulFp(2n, h)), j = mulFp(h, i2);
  const rr = mulFp(2n, subFp(s2, s1)), v = mulFp(u1, i2);
  const nx = subFp(subFp(sqrFp(rr), j), mulFp(2n, v));
  const ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2n, mulFp(s1, j)));
  const nz = mulFp(mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h), 1n);
  return [nx, ny, nz];
}

function scalarMultAcc(accX, accY, accZ, baseX, baseY, k) {
  let rX = 0n, rY = 1n, rZ = 0n;
  let bX = baseX, bY = baseY, bZ = 1n;
  for (let i = 0n; i < 254n; i++) {
    if (((k >> i) & 1n) === 1n) {
      if (rZ === 0n) { [rX, rY, rZ] = [bX, bY, bZ]; }
      else { [rX, rY, rZ] = jacAdd(rX, rY, rZ, bX, bY, bZ); }
    }
    if (bZ !== 0n && bY !== 0n) { [bX, bY, bZ] = jacDouble(bX, bY, bZ); }
  }
  // acc = acc + R
  if (rZ !== 0n) { [accX, accY, accZ] = jacAdd(accX, accY, accZ, rX, rY, rZ); }
  return [accX, accY, accZ];
}

// IC point coords are bare 77-digit JSON numbers -> quote the standalone big-number
// lines so JSON.parse keeps full precision, then BigInt them.
const raw = readFileSync(join(here, 'vkx_vectors.json'), 'utf8');
const v = JSON.parse(raw.replace(/^(\s*)(\d{16,})(,?)\s*$/gm, '$1"$2"$3'));
const ic0 = v.ic0.map(BigInt), ic1 = v.ic1.map(BigInt), ic2 = v.ic2.map(BigInt);
const input0 = BigInt(v.input0), input1 = BigInt(v.input1);
const expected = v.expected.map(BigInt);

let [accX, accY, accZ] = [ic0[0], ic0[1], 1n];
[accX, accY, accZ] = scalarMultAcc(accX, accY, accZ, ic1[0], ic1[1], input0);
[accX, accY, accZ] = scalarMultAcc(accX, accY, accZ, ic2[0], ic2[1], input1);

const zInv = modpow(accZ, p - 2n, p);
const zInv2 = sqrFp(zInv), zInv3 = mulFp(zInv2, zInv);
const affX = mulFp(accX, zInv2);
const affY = mulFp(accY, zInv3);

console.log('contract affX:', affX.toString());
console.log('contract affY:', affY.toString());
console.log('expected affX:', expected[0].toString());
console.log('expected affY:', expected[1].toString());
const match = affX === expected[0] && affY === expected[1];
console.log('MATCH:', match);
process.exit(match ? 0 : 1);
