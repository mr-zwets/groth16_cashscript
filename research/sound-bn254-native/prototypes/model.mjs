// Layout and score model for the bch-2026 multi-input SI-GLS split.
//
//   node research/sound-bn254-native/prototypes/model.mjs            (needs ranges.json from ranges.mjs)
//
// Loop op costs per chunk are MEASURED (ranges.json, fixture 0, real B slopes, libauth op-cost model).
// Setup / terminal / quotient costs are taken from the measured SI-GLS profile (profile.mjs) and adjusted as
// documented in the README ("Per-input fixed costs"). Byte counts are exact for the witness and estimated
// for the library code.
//
// A layout = number of inputs n, the B representation (affine prefix length m: events [0, m) affine with
// witnessed slopes, [m, 65) SI projective), the event range of each input, and the placement of the shared
// data blobs (library code+constants, delta-slope blob, WQ) in inputs. Per input i:
//   L_i = sum of the bytes it carries (<= 10,000, the standard unlocking cap; the bch-2026 item cap is also 10,000)
//   op_i <= 800 (41 + L_i)                                  (bch-2026 per-input budget, standard mode)
// score = sum_i (L_i + 35 locking + 40 outpoint/sequence + 3 varint) + 8 (version, locktime) + 4 (counts) + 10 (OP_RETURN output)
import {readFileSync} from 'node:fs';
import {DIGITS, NE} from '../../../chunked/bn254/sound-si-gls/math.mjs';

const R = JSON.parse(readFileSync(new URL('./ranges.json', import.meta.url)));
const CUTS = []; for (let e = 0; e <= 64; e += 2) CUTS.push(e); CUTS.push(65); // chunk c = events [CUTS[c], CUTS[c+1])
const NCH = CUTS.length - 1;                                                   // 33 chunks
const addsIn = (c) => DIGITS.slice(CUTS[c], CUTS[c + 1]).filter((d) => d).length;
const jAt = (e) => e + DIGITS.slice(0, e).filter((d) => d).length; // delta steps before event e

// ---- fixed op costs (standard mode) ----
export const OP = {
  setupPerInput: 870_000,  // MEASURED setup2.mjs (real 3-input bch-2026 tx): library load, layout pin, graph, digest list + challenges, own
                           //   delta slice, decode, handover: 0.32-0.36M; + SI-GLS in situ: powers 0.119M, GLS tables 0.358M, loop env 0.046M
  ownerChecks: 20_000,     // range checks of the statement words, curve checks of A and C, twist check of B, nibble mask
  terminalAffine: 540_000, // SI terminal 0.707M with the two B additions affine (2 x 95k instead of 2 x 180k)
  terminalProj: 707_000,   // SI terminal (measured): psi(B) adds, delta Frobenius lines, endpoint, Rconst, S_c(eta z), Frob W
  binding: 130_000,        // acc_k from the nibble strings (65 x 2 doubling-adds + TB lookups), mod-r check
  qPerWord: 6_470,         // SI quotient Horner (0.738M at n_q 114), per word
  final: 60_000,           // final identity, clean stack
};
// ---- bytes ----
export const BY = {
  codeAffine: 4900,  // SI code 4,057 - 440 (affine loop kernels) + setup by introspection (setup.mjs ~1.1k for the owner role) + handover
  codeHybrid: 5930,  // both kernel sets (SI projective BADD 590 + inline kBDbl ~440)
  consts: 1460 + 96, // SI field constants 1,386 + other data 74 + the three delta-slice digests
  deltaStartPerInput: 128, // (x_j, c_{j-1}) of the delta recursion at each later input's first step (VK constants)
  deltaSlope: 64, digestList: 96,
  redeem: 57, locking: 35, txPerInput: 43, txFixed: 22,
  stmt: 320 + 130 + 192, state: 192, slope: 64, handoverAffine: 224, handoverProj: 288, pushHdr: 3, // handover: T (4 or 6 words), F+-, R
};
const nq = Number(process.env.NQ ?? 114);
const NQ_MAX = 132;
export const CAP = Number(process.env.CAP ?? 9800); // per-input unlocking bytes at the scored witness (leaves room for a filler up to 10,000)
export const MARGIN = Number(process.env.MARGIN ?? 0.02); // required op margin of every input at the scored witness (filler included)

export function evaluate({n, m, cuts, amode = 'affine'}) {
  const wDbl = amode === 'affineN' ? 32 : 64, wAdd = amode === 'affine' ? 64 : 32;
  // cuts: chunk indices where inputs start: [0, c1, c2, ..., NCH]
  const ins = [];
  for (let i = 0; i < n; i++) {
    let op = OP.setupPerInput, bytes = BY.redeem + 1 + BY.pushHdr * 4; let slopes = 0, states = 0;
    for (let c = cuts[i]; c < cuts[i + 1]; c++) {
      const aff = CUTS[c + 1] <= m;
      op += aff ? R.chunks[amode][c] : R.chunks.proj[c];
      if (c > cuts[i]) op -= aff ? R[amode + 'PerRangeConst'] : R.projPerRangeConst; // chunks measured alone vs inside one loop (calibrated on the whole loop)
      if (aff) slopes += (CUTS[c + 1] - CUTS[c]) * wDbl + addsIn(c) * wAdd;
      states += 1;
    }
    bytes += states * BY.state + slopes;
    const hand = i > 0 ? (CUTS[cuts[i]] < m ? BY.handoverAffine : BY.handoverProj) : 0; bytes += hand;
    const B = {redeemAndHeaders: BY.redeem + 1 + BY.pushHdr * 4, states: states * BY.state, bWitness: slopes, handover: hand};
    const O = {setup: OP.setupPerInput, loop: op - OP.setupPerInput};
    ins.push({i, events: [CUTS[cuts[i]], CUTS[cuts[i + 1]]], op, bytes, data: [], B, O});
  }
  const last = ins[n - 1];
  last.op += (m >= NE ? OP.terminalAffine + 2 * 0 : OP.terminalProj) + OP.binding + OP.qPerWord * nq + OP.final;
  Object.assign(last.O, {terminal: m >= NE ? OP.terminalAffine : OP.terminalProj, binding: OP.binding, quotient: OP.qPerWord * nq, final: OP.final});
  if (m >= NE) { last.bytes += 2 * wAdd; last.B.bWitness += 2 * wAdd; } // the two terminal B additions
  ins[0].op += OP.ownerChecks; ins[0].bytes += BY.stmt + BY.digestList; ins[0].O.ownerChecks = OP.ownerChecks; ins[0].B.statementAndDigests = BY.stmt + BY.digestList;
  // movable blobs: the library, WQ, and each input's delta slice (authenticated by its own digest; read by
  // introspection when it is not local: +25k op for its user); every placement is tried
  const blobs = [
    ...(process.env.SPLITLIB ? [{name: 'code', bytes: (m > 0 && m < NE ? BY.codeHybrid : BY.codeAffine) + 32}, {name: 'consts', bytes: BY.consts + BY.deltaStartPerInput * (n - 1)}]
      : [{name: 'library', bytes: (m > 0 && m < NE ? BY.codeHybrid : BY.codeAffine) + BY.consts + BY.deltaStartPerInput * (n - 1)}]),
    {name: 'WQ', bytes: 32 * nq, reserve: 32 * (NQ_MAX - nq)},
    ...ins.map((x, i) => { const j0 = jAt(x.events[0]), j1 = jAt(x.events[1]) + (i === n - 1 ? 2 : 0); return {name: 'DS' + i, bytes: BY.deltaSlope * (j1 - j0), user: i}; }),
  ];
  let best = null;
  const place = (k, at) => {
    if (k < blobs.length) { for (let h = 0; h < n; h++) place(k + 1, [...at, h]); return; }
    const X = ins.map((x) => ({...x, data: [...x.data], B: {...x.B}, O: {...x.O}}));
    blobs.forEach((bl, k2) => { const h = at[k2]; X[h].bytes += bl.bytes; X[h].data.push(bl.name); X[h].B[bl.name] = bl.bytes;
      if (bl.user !== undefined && bl.user !== h) { X[bl.user].op += 25_000; X[bl.user].O.remoteReads = (X[bl.user].O.remoteReads ?? 0) + 25_000; }
      if (bl.name === 'WQ' && h !== 0) X.forEach((x) => { x.op += 20_000; x.O.remoteReads = (x.O.remoteReads ?? 0) + 20_000; }); });
    for (const x of X) { // liveness at the quotient cap
      const extraBytes = x.data.includes('WQ') ? 32 * (NQ_MAX - nq) : 0, extraOp = x.i === n - 1 ? OP.qPerWord * (NQ_MAX - nq) : 0;
      const need = Math.ceil((x.op + extraOp) / (800 * (1 - MARGIN))) - 41 - (x.bytes + extraBytes);
      if (x.bytes + extraBytes + Math.max(0, need) > 10_000) return;
    }
    let fill = 0;
    for (const x of X) { const need = Math.ceil(x.op / (800 * (1 - MARGIN))) - 41 - x.bytes; x.fill = Math.max(0, need); x.bytes += x.fill; fill += x.fill; x.B.filler = x.fill; if (x.bytes > CAP) return; x.budget = 800 * (41 + x.bytes); x.margin = 1 - x.op / x.budget; }
    const content = X.reduce((s2, x) => s2 + x.bytes, 0);
    if (!best || content < best.content) best = {X, fill, content};
  };
  place(0, []);
  if (!best) return null;
  ins.splice(0, ins.length, ...best.X); const fill = best.fill;
  const content = ins.reduce((s, x) => s + x.bytes, 0);
  const score = content + n * (BY.locking + BY.txPerInput) + BY.txFixed;
  return {n, m, amode, cuts, ins, fill, content, op: ins.reduce((s, x) => s + x.op, 0), score};
}

// search: n in {3, 4}, m over chunk boundaries (0 = all projective, 65 = all affine), input cuts by brute force
export function search({ns = [3, 4], ms, amodes = ['affine', 'affineAN', 'affineN'], stride = 1} = {}) {
  ms ??= [...CUTS];
  const best = [];
  for (const amode of amodes) for (const n of ns) for (const m of ms) {
    let top = null;
    const rec = (cuts) => {
      if (cuts.length === n) { const r = evaluate({n, m, cuts: [...cuts, NCH], amode}); if (r && (!top || r.score < top.score)) top = r; return; }
      for (let c = cuts.at(-1) + 1; c <= NCH - (n - cuts.length); c++) if (c % stride === 0) rec([...cuts, c]);
    };
    rec([0]);
    if (top) best.push(top);
  }
  return best.sort((a, b) => a.score - b.score);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const show = (r) => `${r.amode.padEnd(8)} n=${r.n} m=${String(r.m).padStart(2)} score=${r.score} content=${r.content} fill=${r.fill} op=${(r.op / 1e6).toFixed(2)}M | ` +
    r.ins.map((x) => `[${x.events}] ${x.bytes}B ${(x.op / 1e6).toFixed(2)}M ${(100 * x.margin).toFixed(1)}% ${x.data.join('+')}`).join(' | ');
  const runs = [
    ['all-affine inverse-norm, 3 inputs (DESIGN)', {ns: [3], ms: [65], amodes: ['affineN']}],
    ['all-affine inverse-norm, 4 inputs', {ns: [4], ms: [65], amodes: ['affineN'], stride: 2}],
    ['all-affine slope witnesses, 3 inputs', {ns: [3], ms: [65], amodes: ['affine']}],
    ['all-affine adds inv-norm, dbls slope, 3 inputs', {ns: [3], ms: [65], amodes: ['affineAN']}],
    ['hybrid affine-slope prefix + SI projective', {ns: [3], ms: [36, 40, 44, 48], amodes: ['affine', 'affineAN']}],
    ['hybrid affine-inv-norm prefix + SI projective', {ns: [3], ms: [48, 54, 60], amodes: ['affineN']}],
    ['all SI projective, 4 inputs', {ns: [4], ms: [0], amodes: ['affine'], stride: 2}],
  ];
  const out = {};
  for (const [label, opt] of runs) { const r = search(opt)[0]; out[label] = r ?? null; console.log(label.padEnd(48), r ? show(r) : 'infeasible'); }
  if (process.env.OUT) (await import('node:fs')).writeFileSync(process.env.OUT, JSON.stringify(out, null, 1));
}
