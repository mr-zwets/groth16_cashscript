import {bn254} from '@noble/curves/bn254.js';
const {Fp,Fp2,Fp6,Fp12}=bn254.fields; const BN_X=4965661367192848881n;
const p = Fp.ORDER;
const r = bn254.fields.Fr.ORDER;
const P12 = p ** 12n - 1n;
const q = p;
export const LAMBDA = (6n * BN_X + 2n) + q - q ** 2n + q ** 3n;
export const SIX_X_PLUS_2 = 6n * BN_X + 2n;

// ---- Fp12 helpers (noble tower) ----
const tup = (a) => [a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0, a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1];
export const eq12 = (a, b) => { const x = tup(a), y = tup(b); return x.every((v, i) => v === y[i]); };
const isOne = (a) => eq12(a, Fp12.ONE);
const f6 = (t) => Fp6.create({ c0: Fp2.fromBigTuple([t[0], t[1]]), c1: Fp2.fromBigTuple([t[2], t[3]]), c2: Fp2.fromBigTuple([t[4], t[5]]) });
export const mk12 = (lo, hi) => Fp12.create({ c0: f6(lo), c1: f6(hi) });
const mul = (a, b) => Fp12.mul(a, b), inv = (a) => Fp12.inv(a), sqr = (a) => Fp12.sqr(a);
export const fp12limbsOf = tup;
const powExact = (a, e) => { let res = Fp12.ONE, base = a; while (e > 0n) { if (e & 1n) res = mul(res, base); base = sqr(base); e >>= 1n; } return res; };
export const frob = (a, n) => Fp12.frobeniusMap(a, n);

// ---- 27th root of unity (noble tower), cubic non-residue in Fp6 (only c0.c2 nonzero) ----
export const ROOT27 = mk12([0n, 0n, 0n, 0n,
  18017241959182010774688792132341824651274886350515952296967734324480226243499n,
  8310587989442958350646884634893221121607168288938349542082022013494928077472n], [0n, 0n, 0n, 0n, 0n, 0n]);
// Cube-root correction powers; the leader scaling selector uses SCALING below.
export const COSET27 = (() => { const a = []; let x = Fp12.ONE; for (let i = 0; i < 27; i++) { a.push(x); x = mul(x, ROOT27); } return a; })();

// ---- residue witness (gnark scaling + clean AMM cube-root) ----
const exp1 = P12 / 3n;
const modinv = (a, m) => { let [or, rr] = [((a % m) + m) % m, m], [os, s] = [1n, 0n]; while (rr) { const qn = or / rr; [or, rr] = [rr, or - qn * rr]; [os, s] = [s, os - qn * s]; } return ((os % m) + m) % m; };
const rInv = modinv(r, P12 / r);
const m_ = LAMBDA / (3n * r);
const mInv = modinv(m_, P12);
const U = P12 / 27n;
const kFac = (U % 3n === 2n) ? 1n : 2n;
const cubeExp = (kFac * U + 1n) / 3n;
function cubeRoot(Y) {
  const b = powExact(Y, U);
  let j = -1; for (let t = 0; t < 9; t++) if (eq12(COSET27[(3 * t) % 27], b)) { j = t; break; }
  if (j < 0) throw new Error('not a cube');
  const corr = ((-(kFac * BigInt(j))) % 27n + 27n) % 27n;
  return mul(powExact(Y, cubeExp), COSET27[Number(corr)]);
}
/** given the RAW Miller boundary fRaw, return { c, cInv, w } with c^lambda == fRaw*w. */
export const SCALING = mk12([0n,0n,0n,0n,1n,0n],[0n,0n,0n,0n,0n,0n]);
export function residueWitness(fRaw) {
  let w = null, rw = null;
  for (const cand of [Fp12.ONE, SCALING, sqr(SCALING)]) { const t = mul(fRaw, cand); if (isOne(powExact(t, exp1))) { w = cand; rw = t; break; } }
  if (!w) throw new Error('no cubic-residue scaling');
  rw = powExact(rw, rInv);
  rw = powExact(rw, mInv);
  const c = cubeRoot(rw);
  return { c, cInv: inv(c), w };
}
