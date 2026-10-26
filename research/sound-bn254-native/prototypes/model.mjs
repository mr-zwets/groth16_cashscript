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

// ---- fixed op costs (standard mode) ----
export const OP = {
  setupPerInput: 800_000,  // library load+hash 50k, delta blob 45k, graph 2k, transcript 110k, decode 20k, powers 119k, GLS tables 358k, env 46k, handover 30k
  ownerChecks: 30_000,     // range checks of the statement words, curve checks of A and C, twist check of B, nibble mask
  terminalAffine: 540_000, // SI terminal 0.707M with the two B additions affine (2 x 95k instead of 2 x 180k)
  terminalProj: 707_000,   // SI terminal (measured): psi(B) adds, delta Frobenius lines, endpoint, Rconst, S_c(eta z), Frob W
  binding: 130_000,        // acc_k from the nibble strings (65 x 2 doubling-adds + TB lookups), mod-r check
  qPerWord: 6_470,         // SI quotient Horner (0.738M at n_q 114), per word
  final: 60_000,           // final identity, clean stack
};
// ---- bytes ----
export const BY = {
  codeAffine: 4000,  // SI code 4,057 - 440 (affine loop kernels) + ~380 (graph check, library loader, transcript gather, handover)
  codeHybrid: 5030,  // both kernel sets (SI projective BADD 590 + inline kBDbl ~440)
  consts: 1460 + 32, // SI field constants 1,386 + other data 74 + hash of the delta blob
  deltaStartPerInput: 128, // (x_j, c_{j-1}) of the delta recursion at each later input's first step (VK constants)
  deltaSlopes: 88 * 64,
  redeem: 55, locking: 35, txPerInput: 43, txFixed: 22,
  stmt: 320 + 130 + 192, state: 192, slope: 64, handoverAffine: 160, handoverProj: 224, pushHdr: 3,
};
const nq = Number(process.env.NQ ?? 114);
const NQ_MAX = 132;
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
      if (aff) slopes += (CUTS[c + 1] - CUTS[c]) * wDbl + addsIn(c) * wAdd;
      states += 1;
    }
    bytes += states * BY.state + slopes;
    if (i > 0) bytes += CUTS[cuts[i]] < m ? BY.handoverAffine : BY.handoverProj;
    ins.push({i, events: [CUTS[cuts[i]], CUTS[cuts[i + 1]]], op, bytes, data: []});
  }
  const last = ins[n - 1];
  last.op += (m >= NE ? OP.terminalAffine + 2 * 0 : OP.terminalProj) + OP.binding + OP.qPerWord * nq + OP.final;
  if (m >= NE) last.bytes += 2 * wAdd; // the two terminal B additions
  ins[0].op += OP.ownerChecks; ins[0].bytes += BY.stmt;
  // shared blobs, placed greedily into the inputs with the largest budget deficit
  const blobs = [
    {name: 'library', bytes: (m > 0 && m < NE ? BY.codeHybrid : BY.codeAffine) + BY.consts + BY.deltaStartPerInput * (n - 1)},
    {name: 'delta-slopes', bytes: BY.deltaSlopes},
    {name: 'WQ', bytes: 32 * nq},
  ];
  for (const b of blobs.sort((x, y) => y.bytes - x.bytes)) {
    const cand = ins.filter((x) => x.bytes + b.bytes + (b.name === 'WQ' ? 32 * (NQ_MAX - nq) : 0) <= 10_000).sort((x, y) => (y.op / 800 - 41 - y.bytes) - (x.op / 800 - 41 - x.bytes));
    if (!cand.length) return null;
    cand[0].bytes += b.bytes; cand[0].data.push(b.name);
  }
  // liveness at the quotient cap: the WQ holder carries 32 NQ_MAX bytes, the last input runs NQ_MAX Horner steps
  for (const x of ins) {
    const extraBytes = x.data.includes('WQ') ? 32 * (NQ_MAX - nq) : 0, extraOp = x === last ? OP.qPerWord * (NQ_MAX - nq) : 0;
    const need = Math.ceil((x.op + extraOp) / (800 * (1 - MARGIN))) - 41 - (x.bytes + extraBytes);
    if (x.bytes + extraBytes + Math.max(0, need) > 10_000) return null;
  }
  // zero filler where an input's op exceeds (1 - MARGIN) of its budget (counts as bytes)
  let fill = 0;
  for (const x of ins) { const need = Math.ceil(x.op / (800 * (1 - MARGIN))) - 41 - x.bytes; x.fill = Math.max(0, need); x.bytes += x.fill; fill += x.fill; if (x.bytes > 10_000) return null; x.budget = 800 * (41 + x.bytes); x.margin = 1 - x.op / x.budget; }
  const content = ins.reduce((s, x) => s + x.bytes, 0);
  const score = content + n * (BY.locking + BY.txPerInput) + BY.txFixed;
  return {n, m, amode, cuts, ins, fill, content, op: ins.reduce((s, x) => s + x.op, 0), score};
}

// search: n in {3, 4}, m over chunk boundaries (0 = all projective, 65 = all affine), input cuts by brute force
export function search({ns = [3, 4], ms, amodes = ['affine', 'affineAN', 'affineN']} = {}) {
  ms ??= [...CUTS];
  const best = [];
  for (const amode of amodes) for (const n of ns) for (const m of ms) {
    let top = null;
    const rec = (cuts) => {
      if (cuts.length === n) { const r = evaluate({n, m, cuts: [...cuts, NCH], amode}); if (r && (!top || r.score < top.score)) top = r; return; }
      for (let c = cuts.at(-1) + 1; c <= NCH - (n - cuts.length); c++) rec([...cuts, c]);
    };
    rec([0]);
    if (top) best.push(top);
  }
  return best.sort((a, b) => a.score - b.score);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const res = search();
  const show = (r) => `${r.amode.padEnd(8)} n=${r.n} m=${String(r.m).padStart(2)} score=${r.score} content=${r.content} fill=${r.fill} op=${(r.op / 1e6).toFixed(2)}M | ` +
    r.ins.map((x) => `[${x.events}] ${x.bytes}B ${(x.op / 1e6).toFixed(2)}M ${(100 * x.margin).toFixed(1)}% ${x.data.join('+')}`).join(' | ');
  console.log('best 8:'); for (const r of res.slice(0, 8)) console.log(show(r));
  for (const amode of ['affine', 'affineAN', 'affineN']) for (const m of [0, 65]) for (const n of [3, 4]) { const r = res.find((x) => x.m === m && x.n === n && x.amode === amode); if (r) console.log(`${m ? 'all-affine' : 'all-proj'}: ${show(r)}`); }
  if (process.env.OUT) (await import('node:fs')).writeFileSync(process.env.OUT, JSON.stringify(res.slice(0, 20), null, 1));
}
