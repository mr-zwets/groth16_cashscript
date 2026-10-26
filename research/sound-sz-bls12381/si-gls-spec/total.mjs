// Size and op-cost model of BLS12-381 SI-GLS (one P2SH32 input, bch-spec), from the measured BLS kernels (kernels.json),
// the protocol reference's witness shapes (proto.mjs, run here), and per-category glue calibrated on the BUILT BN254
// SI-GLS (chunked/bn254/sound-si-gls, profile.mjs on fixture 0: actual op vs its research kernels).
//   node total.mjs [--layout=a2] [--json]
// Searches eaff (number of leading events whose B walk is affine with witnessed slopes) so that the worst liveness
// witness (smallest quotient: all GLS digits 0) stays within MARGIN of the budget in standard mode, and reports the
// score per fixture. Budget = (10,000 + unlocking length) * 800.
import {readFileSync, writeFileSync} from 'node:fs';
import {prove, FIXTURES, LAYOUTS, worstBound} from './proto.mjs';
import {BITS, NE} from './blsmath.mjs';
const K = JSON.parse(readFileSync(new URL('./kernels.json', import.meta.url)));
const arg = (k, d) => { const a = process.argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split('=')[1] : d; };
const MARGIN = Number(arg('margin', '0.05'));
const kop = (n) => K[n].opCost, kb = (n) => K[n].bytes;
const W = 48, PUSHW = 1 + W; // field word, in-code push of a field constant
// ---- calibration from the built BN254 SI-GLS (profile.mjs, fixture 0, standard; research kernel -> actual) ----
const CAL = {
  bdbl: 143156 / 142079,      // loop:bdbl 9.305M / 65
  badd: 185762 / 184514,      // add fn 3.901M / 21
  addGlue: 14300,             // loop:add 0.300M / 21 (S_c fetch, delta add set-up, digit branch)
  dstep: 49000 / 46390,       // dstep fn 4.31M / 88
  eventGlue: 4750,            // loopend 0.165M + digit 0.098M + dstep glue 0.046M, per event
  stateGlue: 14700,           // bnd 0.733M/33 = 22.2k minus the residual+fold part of the kernel; +eval fn, +RD fn measured separately
  qGlue: 1500,                // quotient section per word beyond Horner/4 and the RD decode
};
// slope words: a witnessed affine slope is 2 words decoded from WS (RD) and fetched (2 * ~350 ROLL)
const SLOPE_OP = 2 * K.decodeWord.perWord + 700 + 2 * 250; // + the 2 slope-check NOT/VERIFY pairs
const affAddCheck = 600; // (x - xB) != 0 test: 2 x (0NOTEQUAL) + BOOLOR + VERIFY on already reduced values

export function model({layout, eaff, nq, nStatesOverride}) {
  const nAddAff = BITS.slice(0, eaff).filter((b) => b).length, nAddProj = BITS.slice(eaff).filter((b) => b).length;
  const nDblAff = eaff, nDblProj = NE - eaff, nSlopes = nDblAff + nAddAff, nDelta = NE + BITS.filter((b) => b).length;
  const states = nStatesOverride ?? layout.length - 1;
  const bytes = {}, ops = {};
  // ---------- unlocking: <WQ> <WS> <redeem> ----------
  bytes.statement = 8 * W + 2 * 32;          // x_A, y_A, x_B(2), y_B(2), x_C, y_C (48 B), n0, n1 (32 B)
  bytes.glsNibbles = 2 * 64;                 // byte j = bit 63-j of a_{k,0..3}
  bytes.residueRoot = 6 * W;
  bytes.states = states * 6 * W;
  bytes.bSlopes = nSlopes * 2 * W;
  bytes.wsPush = 3;
  bytes.quotient = nq * W + 3;
  bytes.redeemPush = 3;
  // ---------- redeem ----------
  bytes.deltaPile = nDelta * 2 * W + Math.ceil(nDelta * 2 * W / 480) * 3; // slope pile: 480-byte pushes (10 words)
  bytes.fieldConstants = PUSHW * (1 /* p */ + 1 /* eta */ + 2 /* gamma1 */ + 24 /* R_k0, R_k1 */ + 6 /* Rconst' */ + 4 /* delta start x, y */);
  bytes.otherData = 66 /* 0x0f mask */ + 9 /* |x| */ + 8 /* tag */ + 10;
  // code: BN SI-GLS code 4,057 B (functions + sections), adjusted: + affine B kernels and their glue, - the BN terminal
  // additions/Frobenius lines, + wider (48-byte) decode constants; kernels' own sizes from the BLS measurements.
  const bnCode = 4057, bnKernels = 590 /* BADD */ + 187 /* DSTEP */ + 424 /* bdbl inline */;
  bytes.code = bnCode - bnKernels + kb('B projective mixed add + line + c-mul') + kb('delta step, baked slope (dbl)') + 40 + kb('B projective dbl + line + F^2')
    + (eaff ? kb('B affine dbl + line + F^2, witnessed slope') + kb('B affine add + line + c-mul, witnessed slope') + 160 : 0) - 150 /* simpler terminal */ + 100;
  // ---------- op (standard) ----------
  ops.bDblProj = nDblProj * kop('B projective dbl + line + F^2') * CAL.bdbl;
  ops.bDblAff = nDblAff * (kop('B affine dbl + line + F^2, witnessed slope') * CAL.bdbl + SLOPE_OP);
  ops.bAddProj = nAddProj * (kop('B projective mixed add + line + c-mul') * CAL.badd + CAL.addGlue);
  ops.bAddAff = nAddAff * (kop('B affine add + line + c-mul, witnessed slope') * CAL.badd + CAL.addGlue + SLOPE_OP + affAddCheck);
  ops.delta = nDelta * kop('delta step, baked slope (dbl)') * CAL.dstep;
  ops.eventGlue = NE * CAL.eventGlue;
  ops.gls = K.glsLoop.opCost + 2 * 15000 /* init byte: lookups into S_c(-+z) */;
  ops.states = states * (kop('state eval + residual + rho fold') + 6 * K.decodeWord.perWord + CAL.stateGlue);
  ops.quotient = nq * (kop('Horner x4 words') / 4 + K.decodeWord.perWord + CAL.qGlue) + 20000;
  // set-up and terminal (BN actual 1.2M; BLS components measured where possible)
  ops.transcript = 20000 + Math.ceil((bytes.statement + bytes.glsNibbles + bytes.residueRoot + bytes.states + bytes.bSlopes + bytes.quotient + 80) / 64) * 192 + 3 * K.challenge.opCost;
  ops.parseChecks = 10 * K.decodeWord.perWord + 6 * K.decodeWord.perWord /* s^c */ + 8 * 7600 /* curve checks: 4 Fp + 4 Fp2-ish mulmods */ + 6 * 23000 /* B on twist (Fp2) */ + 40000 /* nibble mask, n < r, layout */;
  ops.powers = 30 * 7700;                    // z^2..z^6, eta z powers, t, xz2/xz2t/oP/yz3/yz3t for A and C, gamma1^2, gamma1^3
  ops.glsTables = 4 * kop('GLS table (16 entries, one sign, one group)') + 8 * kop('monic deg-6 eval at +-x') + 30000 /* TB, |x|^i */ + 50000;
  ops.terminal = kop('Frob(S_c) at +-x') + 2 * kop('monic deg-6 eval at +-x') /* S_c, Rconst' */ + 6 * 7700 + 4 * kop('Fp2 x const') /* endpoint */ + 2 * 25000 + 4 * 6000 /* binding: 2 exact compares */ + 60000 /* M(z), final */;
  ops.misc = 56000 /* p2sh */ + 46000 /* loop set-up */ + 54000 /* cleanup */;
  const U = Object.entries(bytes).reduce((a, [, b]) => a + b, 0);
  const redeem = bytes.deltaPile + bytes.fieldConstants + bytes.otherData + bytes.code;
  const op = Math.round(Object.values(ops).reduce((a, b) => a + b, 0));
  const budget = (10000 + U) * 800;
  return {bytes, ops, unlocking: U, redeem, ws: bytes.statement + bytes.glsNibbles + bytes.residueRoot + bytes.states + bytes.bSlopes, wq: nq * W,
    score: 35 + U + 63, op, budget, pct: op / budget, opConsensus: op - Math.ceil((U - redeem) / 64) * 128};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = {};
  for (const lname of (arg('layout', 'a2,u2')).split(',')) {
    const layout = LAYOUTS[lname];
    const nqOf = {}; for (const [name, fx] of Object.entries(FIXTURES)) nqOf[name] = (e) => prove(fx, {eaff: e, layout}).nq;
    // liveness: the smallest quotient is the all-zero-digit statement ("zero")
    let best = null;
    const fixed = arg('eaff', null);
    for (let eaff = fixed === null ? 0 : Number(fixed); eaff <= (fixed === null ? NE : Number(fixed)); eaff++) {
      const live = model({layout, eaff, nq: nqOf.zero(eaff)});
      if (fixed === null && live.op > (1 - MARGIN) * live.budget) continue;
      const prim = model({layout, eaff, nq: nqOf.committed(eaff)});
      if (!best || prim.score < best.prim.score) best = {eaff, live, prim};
    }
    const {eaff} = best; const wb = worstBound(layout, eaff);
    const fx = Object.fromEntries(Object.keys(FIXTURES).map((n) => { const nq = nqOf[n](eaff); const m = model({layout, eaff, nq}); return [n, {nq, score: m.score, opM: +(m.op / 1e6).toFixed(3), budgetM: +(m.budget / 1e6).toFixed(3), pct: +(100 * m.op / m.budget).toFixed(2)}]; }));
    const cap = model({layout, eaff, nq: wb.nqMax});
    out[lname] = {layout, eaff, NQ_MAX: wb.nqMax, primary: {score: best.prim.score, unlocking: best.prim.unlocking, redeem: best.prim.redeem, ws: best.prim.ws, wq: best.prim.wq,
      opStandard: best.prim.op, opConsensus: best.prim.opConsensus, budget: best.prim.budget, pct: +(100 * best.prim.pct).toFixed(2), bytes: best.prim.bytes,
      opsM: Object.fromEntries(Object.entries(best.prim.ops).map(([a, x]) => [a, +(x / 1e6).toFixed(3)]))},
    liveness: {witness: 'zero statement (all digits 0, smallest quotient)', nq: nqOf.zero(eaff), op: best.live.op, budget: best.live.budget, pct: +(100 * best.live.pct).toFixed(2), marginOp: best.live.budget - best.live.op},
    cap: {nq: wb.nqMax, score: cap.score, pct: +(100 * cap.pct).toFixed(2), unlocking: cap.unlocking}, fixtures: fx};
    console.log(`layout ${lname}: eaff ${eaff}, NQ_MAX ${wb.nqMax}; primary score ${best.prim.score} (unlocking ${best.prim.unlocking}: redeem ${best.prim.redeem}, WS ${best.prim.ws}, WQ ${best.prim.wq}); op ${(best.prim.op / 1e6).toFixed(2)}M / ${(best.prim.budget / 1e6).toFixed(2)}M (${(100 * best.prim.pct).toFixed(1)}%); liveness ${(100 * best.live.pct).toFixed(1)}% at nq ${nqOf.zero(eaff)}; cap ${cap.score} B ${(100 * cap.pct).toFixed(1)}%`);
    for (const [n, v] of Object.entries(fx)) console.log('   ', n.padEnd(13), JSON.stringify(v));
  }
  if (process.argv.includes('--json')) writeFileSync(new URL('./total.json', import.meta.url), JSON.stringify(out, null, 1));
  if (process.argv.includes('--verbose')) console.log(JSON.stringify(out, null, 1));
}
