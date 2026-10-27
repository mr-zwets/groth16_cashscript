// DESIGN-2 score model (angle B: structure). Calibrated on the measured fixture-0 build of bn-native-sound
// (code 75c780ae..78d7): per-role non-loop op and per-chunk loop op (x1.037 calibration), unlocking contents.
// Usage: node research/native-bn-design2/model.mjs   (from the repository root)
const D = new URL('../../chunked/bn254/', import.meta.url).href;
const {DIGITS} = await import(D + 'sound-si-gls/math.mjs');
const {BOUNDS} = await import(D + 'sound-si-gls/protocol.mjs');
const K = 1.037; const ch = []; let prev = 0;
BOUNDS.forEach((b) => { let nB = 0, add = 0; for (let e = prev; e < b; e++) { nB += DIGITS[e] ? 2 : 1; add += DIGITS[e] ? 1 : 0; }
  ch.push({a: prev, b, nB, rec: 192 + 32 * nB, ds: 64 * nB, op: K * ((b - prev) * 183000 + add * 152000 + 27000)}); prev = b; });
const pl = (n) => n + (n === 0 ? 1 : n < 76 ? 1 : n < 256 ? 2 : n < 65536 ? 3 : 5);
const sum = (arr, f) => arr.reduce((x, y) => x + f(y), 0);
const CUR_C = [9219, 9221, 8725], FIX = [886431, 839632, 2377322]; // measured: content (filler 0), op outside the event loop
// structural op deltas per role (design §3): R/defs, remote, transcript, params, layout
export const DELTA = [-33000 - 33000 - 13000 + 5000 - 1000, -33000 - 40000 + 20000 + 5000, -33000 + 5000 + 500];
export function evalCfg({k1, k2, C = 6710, Rlen = 52, margin = 0.06, p2s = false, nq = 114, variant = 'v2', extraOp = [0, 0, 0], extraC = [0, 0, 0]}) {
  const r = [ch.slice(0, k1), ch.slice(k1, k2), ch.slice(k2)];
  const S = r.map((x, i) => sum(x, (c) => c.rec) + (i === 2 ? 64 : 0)); const DS = r.map((x, i) => sum(x, (c) => c.ds) + (i === 2 ? 128 : 0));
  const loop = r.map((x) => sum(x, (c) => c.op)); const WQ = 32 * nq; const Rp = p2s ? 0 : pl(Rlen); const qd = (114 - nq) * 6600;
  let c, o;
  if (variant === 'v1') {
    c = [pl(S[0]) + pl(DS[0]) + pl(3767) + 1 + 66, pl(S[1]) + pl(224) + pl(DS[1]) + pl(3543) + 1 + 66, pl(96) + pl(642) + pl(S[2]) + pl(224) + pl(DS[2]) + 1 + pl(WQ) + 66];
    o = loop.map((l, i) => l + FIX[i] - (i === 2 ? qd : 0));
  } else {
    c = [pl(DS[0]) + pl(C) + 1 + Rp, pl(S[0]) + pl(S[1]) + pl(DS[1]) + 1 + Rp, pl(64) + pl(642) + pl(224) + pl(224) + pl(S[2]) + pl(DS[2]) + 1 + pl(WQ) + Rp];
    o = loop.map((l, i) => l + FIX[i] + DELTA[i] - (i === 2 ? qd : 0) + (c[i] - CUR_C[i]));
  }
  c = c.map((x, i) => x + extraC[i]); o = o.map((x, i) => x + extraOp[i]);
  const need = o.map((x) => Math.ceil(x / (800 * (1 - margin))) - 41); const u = c.map((x, i) => Math.max(x, need[i]));
  const score = sum(u, (x) => x) + 3 * (p2s ? Rlen : 35) + 149;
  return {k1, k2, c, o: o.map(Math.round), need, u, score, cap: o.every((x) => x <= 0.94 * 8032800), fits: c.every((x) => x <= 10000) && u.every((x) => x <= 10000)};
}
export function best(cf, margin) {
  let b = null;
  for (let k1 = 8; k1 <= 16; k1++) for (let k2 = k1 + 6; k2 <= 30; k2++) {
    const e = evalCfg({...cf, k1, k2, margin}), w = evalCfg({...cf, k1, k2, margin, nq: 132}); // worst-case quotient length
    if (!e.fits || !w.fits || !w.cap) continue; if (!b || e.score < b.score) b = e;
  }
  return b;
}
const B5 = {extraC: [0, 0, -64], extraOp: [-2000, 22000, 0]};
const CFGS = [
  {name: 'current (v1, calibration)', variant: 'v1'},
  {name: 'B1+B2 layout only (C 7,310)', C: 7310},
  {name: 'B1-B4 (C 6,710)', C: 6710},
  {name: 'B1-B4, C 6,860 (pessimistic)', C: 6860},
  {name: 'B1-B5', C: 6710, ...B5},
  {name: 'B1-B5 + P2S (B6)', C: 6710, p2s: true, ...B5},
  {name: 'B1-B5 + angle-A op -0.3M', C: 6710, extraC: B5.extraC, extraOp: B5.extraOp.map((x) => x - 100000)},
  {name: 'B1-B5 + angle-A op -0.6M', C: 6710, extraC: B5.extraC, extraOp: B5.extraOp.map((x) => x - 200000)},
];
if (import.meta.url === `file://${process.argv[1]}`) {
  for (const cf of CFGS) for (const m of [0.06, 0.04, 0.03, 0.02]) {
    const d = evalCfg({...cf, k1: 12, k2: 24, margin: m}), b = cf.variant === 'v1' ? d : best(cf, m);
    console.log(`${cf.name.padEnd(36)} m=${m} cuts[0,24,48,65]=${d.score} best=${b.score} cuts=[0,${2 * b.k1},${2 * b.k2},65] u=${b.u} c=${b.c} need=${b.need} op=${b.o}`);
  }
}
