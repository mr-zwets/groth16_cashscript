// Standalone op cost and bytes of msm-single's vkxMsm (sound GLV Straus vk_x) on the bch-spec VM.
// Compiles msm-single.mjs's CashScript (hash-guarded cashc zk-language build) as a bare contract
// VkxMsmSingle.spend(n0, n1, w, zInv) and runs it on the five fixtures and on forced witnesses
// with all 128 Straus additions (the worst case any witness can reach; same construction as
// densless-msm-spec-single/sweep.mjs). Reports op cost minus an empty-script baseline.
//
// External inputs (not on main): msm-single.mjs lives in chunked/bn254/densless-msm-spec-single/ on the
// single-input-spec branch (commit 5333ec5, draft PR #29), and it compiles with the zk-language cashc
// fork. Point MSM_SINGLE at that file (default: the same path in this checkout) and CASHC_ZK at the
// fork's packages/cashc/dist/index.js (msm-single.mjs reads CASHC_ZK itself). msm-single.mjs also loads
// the benchmark vectors through chunked/pairing/_millermath.mjs, which needs VERIFIER_DIR (a
// zk-verifier-bench checkout).
// Usage: VERIFIER_DIR=<zk-verifier-bench> MSM_SINGLE=<path>/msm-single.mjs CASHC_ZK=<path>/dist/index.js node msm.mjs
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {run, asm, num, vmCons, L} from './sscomp.mjs';
import {fx} from './witness.mjs';
import {pathToFileURL} from 'node:url';
import {bn254} from '@noble/curves/bn254.js';
import {witness} from '../../../../chunked/bn254/pairfold5-msm/vkx-msm-asm.mjs';
const MSM_SINGLE = process.env.MSM_SINGLE ? pathToFileURL(process.env.MSM_SINGLE).href : new URL('../../../../chunked/bn254/densless-msm-spec-single/msm-single.mjs', import.meta.url).href;
const msm = await import(MSM_SINGLE);
const bytes = msm.compile();
const P = msm.P, r = msm.R, LAM = msm.LAM, TABLE = msm.TABLE;
const mod = (x) => ((x % P) + P) % P, modr = (x) => ((x % r) + r) % r;
// forced witness (copied from densless-msm-spec-single/sweep.mjs)
let counter = 0;
const rnd = () => modr(BigInt('0x' + createHash('sha256').update(`msm-measure:${counter++}`).digest('hex')));
const Q0 = bn254.G1.Point.BASE.toAffine(), FINAL = bn254.G1.Point.fromAffine({x: BigInt(fx.vk.ic[0].x), y: BigInt(fx.vk.ic[0].y)}).subtract(bn254.G1.Point.BASE.multiply(1n << 64n)).toAffine();
const dblJ = ([X, Y, Z]) => { const a = mod(X * X), b = mod(Y * Y), c = mod(b * b), d = mod(4n * X * b), e = 3n * a, f = mod(e * e), nx = mod(f - 2n * d); return [nx, mod((d - nx) * e - 8n * c), mod(2n * Y * Z)]; };
const maddJ = ([X, Y, Z], [bx, by]) => { const z1z1 = mod(Z * Z), u2 = mod(bx * z1z1); assert(u2 !== X); const s2 = mod(mod(z1z1 * Z) * by), h = mod(u2 - X), rr = mod(s2 - Y); const hh = mod(h * h), hhh = mod(h * hh), vv = mod(hh * X), nx = mod(rr * rr - hhh - 2n * vv); return [nx, mod((vv - nx) * rr - Y * hhh), mod(Z * h)]; };
const entry = (half, idx) => { const e = TABLE.subarray(half * 960 + (idx - 1) * 64, half * 960 + idx * 64); return [BigInt('0x' + Buffer.from(e.subarray(0, 32)).reverse().toString('hex')), BigInt('0x' + Buffer.from(e.subarray(32)).reverse().toString('hex'))]; };
const forced = () => {
  const w = Buffer.from(Array.from({length: 64}, () => { const x = Number(rnd() % 225n); return (1 + (x % 15)) + 16 * (1 + Math.floor(x / 15)); }));
  let s0lo = 0n, s1lo = 0n, s0hi = 0n, s1hi = 0n, acc = [Q0.x, Q0.y, 1n];
  for (const b of w) {
    const lo = BigInt(b % 16), hi = BigInt(b >> 4);
    s0lo = 2n * s0lo + lo % 2n + (lo / 2n % 2n) * LAM; s1lo = 2n * s1lo + lo / 4n % 2n + (lo / 8n) * LAM;
    s0hi = 2n * s0hi + hi % 2n + (hi / 2n % 2n) * LAM; s1hi = 2n * s1hi + hi / 4n % 2n + (hi / 8n) * LAM;
    acc = dblJ(acc); acc = maddJ(acc, entry(0, b % 16)); acc = maddJ(acc, entry(1, b >> 4));
  }
  acc = maddJ(acc, [FINAL.x, FINAL.y]);
  return {n0: modr(s0hi * (1n << 64n) + s0lo), n1: modr(s1hi * (1n << 64n) + s1lo), w, zInv: bn254.fields.Fp.inv(acc[2])};
};
const measure = (n0, n1, w, zInv, vm) => {
  // CashScript argument order: last argument pushed first, first argument on top
  const pushes = [num(zInv), w, num(n1), num(n0)];
  const a = run(pushes, bytes, {vm}), b0 = run(pushes, asm('1'), {vm});
  return {err: a.err, op: a.cost - b0.cost};
};
const rows = [];
fx.fixtures.forEach((f, i) => { const [n0, n1] = f.publicInputs.map(BigInt); const m = witness(n0, n1, 0); rows.push({label: `fixture ${i}`, ...measure(n0, n1, m.w, m.zInv)}); });
for (let i = 0; i < 5; i++) { const f = forced(); rows.push({label: `forced-128 #${i}`, ...measure(f.n0, f.n1, f.w, f.zInv)}); }
const f0 = fx.fixtures[0].publicInputs.map(BigInt); const m0 = witness(f0[0], f0[1], 0);
rows.push({label: 'fixture 0 consensus', ...measure(f0[0], f0[1], m0.w, m0.zInv, vmCons)});
// the bare contract leaves its outputs on the stack, so a clean-stack error is the success case here
for (const x of rows) console.log(x.label.padEnd(22), (x.op / 1e6).toFixed(3) + 'M', !x.err || /unexpected number of items/.test(x.err) ? 'accepted' : x.err);
console.log(JSON.stringify({msmCodeBytes: bytes.length, witnessBytes: L.encodeDataPush(m0.w).length + L.encodeDataPush(num(m0.zInv)).length,
  typicalMaxM: Math.max(...rows.filter((x) => x.label.startsWith('fixture ')).map((x) => x.op)) / 1e6, worstForcedM: Math.max(...rows.filter((x) => x.label.startsWith('forced')).map((x) => x.op)) / 1e6}));
