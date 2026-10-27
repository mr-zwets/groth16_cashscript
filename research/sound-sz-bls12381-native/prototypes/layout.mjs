// Cost model and layout search for the multi-input bch-2026 BLS12-381 SI-GLS verifier.
// Every op figure is a VM measurement from worker.mjs / head.mjs / glue.mjs / measure.mjs (consensus op cost of the
// spec VM, identical formula to bch-2026), plus the standard-mode hashing surcharge (128 per digest iteration)
// and explicit glue allowances (marked EST). Bytes are exact layout sizes except the shared program blob (EST).
//   node layout.mjs            -> best layouts for n = 4, 5 and the per-input table of the best one
import {writeFileSync} from 'node:fs';
import {chunkEvents, isAdd, NCHUNK} from './protocol.mjs';

// ---------------- measured op costs (consensus) ----------------
export const OPC = {
  dblAff: 152_800, dblProj: 232_500, dstep: 80_600, gls: 34_200 /* worst case: dense nibbles (worst.mjs) */, loopGlue: Number(process.env.GLUE ?? 4_000) /* EST: loop/schedule control per event */,
  bound: 57_000, addAff: 154_300, addProj: 332_000,
  setup: 117_000 + 630_500 + 30_600 + 35_400, // env, GLS tables, S_c(+-z), start EV
  terminal: 176_400, endpointAff: 44_900, endpointProj: 98_100 /* measured: worker.mjs 23 32 55 */, projToAff: 50_000 /* EST: witnessed affine T check */,
  head: {transcript: 66_500, statement: 32_500, curves: 91_300, binding: 319_100, hornerPerWord: 8_000, hornerFixed: 20_000, final: 97_700},
  pinPerInput: 3_000, loaderFixed: 2_000, claimCheck: 600, decodeWord: 1_300, cleanup: 3_000,
};
const SHA_ITER = (len) => Math.ceil((len + 9) / 64);
const STD_SURCHARGE = 128; // standard - consensus cost per digest iteration
// ---------------- bytes ----------------
export const BYTES = {
  blobMixed: Number(process.env.BLOB ?? 5_700), blobAffOnly: Number(process.env.BLOB ?? 5_700) - 400 /* EST: shared program incl. R/eta/p/r constants */, redeem: 54, locking: 35, txPerInput: 43, txFixed: 20,
  stmt: 864, claimsHead: 96, Rt: 48, Tt: 192, Tproj: 288, state: 288, slope: 96, dslope: 96, termConsts: 960, constHash: 32,
};
const RELOCATE = process.env.RELOCATE !== '0';
const ownData = (x, i, nq) => x.u - BYTES.redeem - 60 - (i === 0 ? 48 * nq + BYTES.claimsHead : 0); // relocatable data (the head keeps WQ and its claims)
const hdr = (n) => (n === 0 ? 0 : n <= 75 ? 1 : n <= 255 ? 2 : 3);
const push = (n) => n + hdr(n);

// events of a chunk range, delta steps, affine slopes
function rangeInfo(j0, j1, E_p) {
  const evs = []; for (let j = j0; j < j1; j++) evs.push(...chunkEvents(j));
  const adds = evs.filter(isAdd).length; const aff = evs.filter((e) => e < E_p); const proj = evs.filter((e) => e >= E_p);
  const slopes = aff.reduce((s, e) => s + (isAdd(e) ? 2 : 1), 0);
  return {evs, adds, nEv: evs.length, nAff: aff.length, nProj: proj.length, addsAff: aff.filter(isAdd).length, addsProj: proj.filter(isAdd).length, slopes, dsteps: evs.length + adds,
    states: Math.max(0, Math.min(j1, NCHUNK - 1) - j0), terminal: j1 === NCHUNK && j1 > j0, chunks: j1 - j0};
}
// one input: bytes (excluding the blob, added by the carrier) and op (std/cons) for a given n_q
function inputCost(i, n, [j0, j1], E_p, nq, U, blobBytes, carrier) {
  const R = rangeInfo(j0, j1, E_p); const head = i === 0; const miller = j1 > j0;
  // ---- bytes (pushes) ----
  const pushes = [];
  if (head) { pushes.push(BYTES.stmt + (miller ? R.states * BYTES.state + R.slopes * BYTES.slope : 0)); pushes.push(48 * nq); pushes.push(BYTES.claimsHead); }
  else if (miller) pushes.push(R.states * BYTES.state + R.slopes * BYTES.slope);
  if (miller) { pushes.push(R.dsteps * BYTES.dslope + (R.terminal ? BYTES.termConsts : 0)); if (!R.terminal) pushes.push(BYTES.Rt + BYTES.Tt + (R.nProj && !R.terminal ? 0 : 0)); else pushes.push(BYTES.Rt); }
  if (i === carrier) pushes.push(blobBytes);
  const u = pushes.reduce((s, x) => s + push(x), 0) + BYTES.redeem;
  const bb = {redeem: BYTES.redeem};
  if (head) { bb.WQ = push(48 * nq); bb.claimsZRho = push(BYTES.claimsHead); bb.statement = BYTES.stmt; }
  if (miller) { bb.states = R.states * BYTES.state; bb.Bslopes = R.slopes * BYTES.slope; bb.deltaConsts = R.dsteps * BYTES.dslope; if (R.terminal) bb.termConsts = BYTES.termConsts; bb.Rt = BYTES.Rt; if (!R.terminal) bb.Tt = BYTES.Tt; }
  if (i === carrier) bb.blob = blobBytes;
  bb.headers = u - Object.values(bb).reduce((a2, b2) => a2 + b2, 0);
  // ---- op ----
  let op = 0, it = 0; const ob = {}; const add = (k2, v2) => { ob[k2] = (ob[k2] ?? 0) + v2; op += v2; };
  // loader: read the carrier's unlocking, 2 splits, hash the blob, define/invoke
  add('loader', 3 * U[carrier] + blobBytes + OPC.loaderFixed); it += SHA_ITER(blobBytes);
  add('pins', n * OPC.pinPerInput); it += 2 * n; // HASH256 of each ~100-byte redeem template
  add('cleanup', OPC.cleanup);
  if (miller) {
    if (!head) add('readHead', 3 * U[0] + 25 * OPC.decodeWord);              // statement, z, rho, s^c, nibbles from the head
    if (j0 > 0) add('readPred', 3 * U[i - 1] + 10 * OPC.decodeWord);         // start state + T from the predecessor
    add('constCheck', BYTES.dslope * R.dsteps + 2000); it += SHA_ITER(R.dsteps * BYTES.dslope + (R.terminal ? BYTES.termConsts : 0));
    add('setup', OPC.setup);
    add('Bdbl', R.nAff * OPC.dblAff + R.nProj * OPC.dblProj); add('Badd', R.addsAff * OPC.addAff + R.addsProj * OPC.addProj);
    add('delta', R.dsteps * OPC.dstep); add('gls', R.nEv * OPC.gls); add('loopGlue', R.nEv * OPC.loopGlue);
    add('boundaries', (R.chunks - (R.terminal ? 1 : 0)) * OPC.bound);
    if (R.terminal) add('terminal', OPC.terminal + (R.nProj ? OPC.endpointProj : OPC.endpointAff));
    else { add('claims', 2 * OPC.claimCheck); if (R.nProj) add('projToAff', OPC.projToAff); }
    add('claims', OPC.claimCheck);
  }
  if (head) {
    let rd = 0; for (let j = 1; j < n; j++) rd += 3 * U[j]; add('headReads', rd);
    const regionBytes = BYTES.stmt + 31 * BYTES.state + 0; it += 40 + SHA_ITER(48 * nq) + Math.ceil(regionBytes / 64);
    const H = OPC.head; add('headTranscript', H.transcript); add('headStatement', H.statement + H.curves); add('headBinding', H.binding); add('headHorner', H.hornerFixed + H.hornerPerWord * nq); add('headFinal', H.final);
  }
  ob.hashSurchargeStd = STD_SURCHARGE * it;
  return {u, opCons: op, opStd: op + STD_SURCHARGE * it, iters: it, R, bytes: bb, ops: ob};
}
export const NQ_MIN = Number(process.env.NQ_MIN ?? 70), MARGIN = Number(process.env.MARGIN ?? 0.015);
export function evaluate(n, owners, E_p, {nq = 70, carrier = null, blobBytes = null, nqWorst = [NQ_MIN, 127]} = {}) {
  blobBytes ??= E_p <= 63 ? BYTES.blobMixed : BYTES.blobAffOnly;
  // carrier: the input with the most spare budget (choose by trying all)
  const tryCarrier = (c) => {
    const run = (nqx) => {
      let U = Array(n).fill(5000);
      for (let k = 0; k < 4; k++) { const c2 = owners.map((o, i) => inputCost(i, n, o, E_p, nqx, U, blobBytes, c)); U = c2.map((x) => x.u); }
      return owners.map((o, i) => inputCost(i, n, o, E_p, nqx, U, blobBytes, c));
    };
    // relocation: data pushes may live in any sibling's unlocking (pinned by that sibling's SIZE checks, hash-committed
    // or hash-checked as before); the owner reads the holder once (3 op per holder byte, charged to the owner).
    // moved[i] = net bytes held for others (> 0) or given away (< 0). Then fixed pads cover what is still missing.
    const cases0 = [nq, ...nqWorst].map(run);
    const need = (cs, i) => Math.ceil((cs[i].opStd * (1 + MARGIN)) / 800) - 41 - cs[i].u; // > 0: needs bytes
    const moved = Array(n).fill(0); const extraOp = Array(n).fill(0);
    if (RELOCATE) for (let round = 0; round < 3; round++) {
      const def = owners.map((_, i) => Math.max(...cases0.map((cs) => need(cs, i) - moved[i] + extraOp[i] / 800)));
      for (let d = 0; d < n; d++) { if (def[d] <= 0) continue;
        for (let s = 0; s < n && def[d] > 0; s++) { if (s === d) continue; const spare = -Math.max(...cases0.map((cs) => need(cs, s) - moved[s] + extraOp[s] / 800 + (moved[s] < 0 ? 0 : 0))) - 40;
          const capD = 10_000 - Math.max(...cases0.map((cs) => cs[d].u + moved[d])) - 3;
          const amt = Math.floor(Math.min(def[d], spare, capD, ownData(cases0[0][s], s, nq) - (s === c ? push(blobBytes) : 0) + Math.min(0, moved[s]))); if (amt <= 0) continue;
          moved[d] += amt; moved[s] -= amt; extraOp[s] += 3 * 10_000 / 3 + 3 * (cases0[0][d].u + moved[d]); def[d] -= amt; } }
    }
    const cases = cases0.map((cs) => cs.map((x, i) => ({...x, u: x.u + moved[i], opStd: x.opStd + extraOp[i], opCons: x.opCons + extraOp[i]})));
    const pads = owners.map((_, i) => Math.max(0, ...cases.map((cs) => Math.ceil((cs[i].opStd * (1 + MARGIN)) / 800) - 41 - cs[i].u)));
    const fin = cases.map((cs) => cs.map((x, i) => ({...x, u: x.u + (pads[i] ? push(pads[i]) : 0), pad: pads[i], moved: moved[i]})));
    const ok = fin.every((cs) => cs.every((x) => x.u <= 10_000));
    const score = fin[0].reduce((s, x) => s + x.u, 0) + 78 * n + 20;
    return {ok, score, inputs: fin[0], worst: fin.slice(1), pads, carrier: c};
  };
  let best = null; for (let c = 0; c < n; c++) { const r = tryCarrier(c); if (r.ok && (!best || r.score < best.score)) best = r; }
  return best;
}
// enumerate contiguous partitions of the 32 chunks into n ranges (input 0 = head may own a prefix, possibly empty)
function* partitions(n, lo = 0, hi = NCHUNK) {
  if (n === 1) { yield [[lo, hi]]; return; }
  for (let c = lo; c <= hi; c++) for (const rest of partitions(n - 1, c, hi)) yield [[lo, c], ...rest];
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const results = {};
  for (const n of (process.env.NS ?? '4,5').split(',').map(Number)) {
    let best = null;
    for (const owners of partitions(n)) {
      if (owners.slice(1).some(([a, b]) => b <= a)) continue; // every worker owns at least one chunk
      for (const E_p of [64, 60, 56, 52, 48, 44, 40, 36, 32]) {
        const r = evaluate(n, owners, E_p); if (r && (!best || r.score < best.score)) best = {...r, owners, E_p};
      }
    }
    results[n] = best;
    if (process.env.DETAIL) for (const [i, x] of best.inputs.entries()) console.log('  in' + i, JSON.stringify(x.bytes), JSON.stringify(x.ops));
    console.log(`n=${n}: score ${best.score}  owners ${JSON.stringify(best.owners)}  projective from event ${best.E_p}  carrier ${best.carrier}`);
    for (const [i, x] of best.inputs.entries()) {
      const bud = 800 * (41 + x.u);
      console.log(`  in${i}: U ${x.u} (pad ${x.pad}, holds ${x.moved})  op std ${x.opStd} cons ${x.opCons}  budget ${bud}  margin std ${(bud - x.opStd)} (${(100 * (bud - x.opStd) / bud).toFixed(1)}%)  events ${x.R.nEv} (aff ${x.R.nAff}, proj ${x.R.nProj}) chunks ${x.R.chunks}`);
    }
    for (const [w, cs] of best.worst.entries()) console.log(`  worst nq=${[NQ_MIN, 127][w]}: ` + cs.map((x, i) => `in${i} U ${x.u} margin ${800 * (41 + x.u) - x.opStd}`).join(' | '));
  }
  writeFileSync(new URL('./layout.json', import.meta.url), JSON.stringify(results, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 1));
}
