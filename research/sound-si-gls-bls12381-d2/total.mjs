// Totals for the BLS12-381 SI-GLS design: op cost by section and bytes by component, calibrated on the
// BUILT BN254 sound-si-gls verifier. Each BLS section = (measured BLS kernel op, kernels.json) x count
// + the BN verifier's measured glue for that section (bn-profile.txt, standard mode, fixture 0), scaled
// where the glue handles 48-byte instead of 32-byte words. Prints the baseline and the optional variants,
// and the padding needed for a target liveness margin.
//   node total.mjs            MARGIN=0.05 (default) | GLUE=1.0 (extra multiplier on all glue terms)
import {readFileSync} from 'node:fs';
import {NE, NADD} from './math.mjs';
import {layoutFor, nqMax, DEFAULT_BOUNDS} from './protocol.mjs';

const K = JSON.parse(readFileSync(new URL('./kernels.json', import.meta.url)));
const MARGIN = Number(process.env.MARGIN ?? 0.05), GLUE = Number(process.env.GLUE ?? 1.0);
const L = layoutFor(DEFAULT_BOUNDS), NQ = nqMax(L), NS = L.NSTATES;
const NDSTEP = NE + NADD;               // 68 delta lines
const NGLS = NE + 1;                     // 64 nibble events (bit 63 at the initial step)

// ---- BN calibration (bn-profile.txt, standard mode; counts: 65 events, 21 + 2 additions, 88 delta steps, 33 states, 114 Q words) ----
const BN = {
  dstepFn: (3.189e6 + 1.029e6 + 0.097e6) / 88,         // per delta step incl. slope read
  glsSection: 1.315e6 / 65,                            // per event
  eventCtl: (0.300e6 + 0.165e6 + 0.098e6 + 0.046e6) / 65, // add test, loop end, digit, dstep picks
  bndTotal: 0.733e6 + 0.521e6 + 0.286e6 + 0.026e6,     // 33 boundaries + the per-event boundary test
  quotient: 0.574e6 + 0.164e6, nqWords: 114, horner4Steps: 29,
  setup: {transcript: 0.099e6, parse: 0.104e6 + 0.112e6, powers: 0.119e6, glsTables: 0.194e6 + 0.126e6 + 0.038e6, loopSetup: 0.046e6, terminalOther: 0.219e6 + 0.032e6, cleanup: 0.054e6, p2sh: 0.056e6},
  bytes: {redeem: 11182, code: 4057, constants: 1386, other: 74, WS: 6978, WQfix0: 3648},
};
const glueOf = (bnTotal, bnKernel) => bnTotal - bnKernel;

function model({affineDbl = 0, bakedDelta = 0} = {}) {
  const op = {};
  op['B doubling (63)'] = (NE - affineDbl) * K.blsBDbl.op + affineDbl * (K.optBDblAffine.op + 1700 * GLUE);
  op['B addition + c^-1 (5)'] = NADD * K.blsBAdd.op;
  const dGlue = glueOf(BN.dstepFn, K.bnDStep.op) * 1.2 * GLUE;     // 96-byte slope reads instead of 64
  const bakedLine = 0.40 * K.blsDStep.op;                            // option: line from 4 baked words (BN: 18.8k vs 46.6k)
  op['delta steps (68)'] = (NDSTEP - bakedDelta) * (K.blsDStep.op + dGlue) + bakedDelta * (bakedLine + dGlue * 1.5);
  op['GT-GLS (64 nibbles)'] = NGLS * (K.blsGlsMul.op + glueOf(BN.glsSection, K.bnGlsMul.op) * 1.1 * GLUE);
  op['event control (63)'] = NE * BN.eventCtl * GLUE;
  const bnBndKernels = 33 * (K.bnEval.op + K.bnRD6.op + K.bnFold.op);
  op[`state boundaries (${NS})`] = NS * (K.blsEval.op + K.blsRD6.op + K.blsFold.op) + (BN.bndTotal - bnBndKernels) * (NE / 65) * 1.1 * GLUE;
  const steps = Math.ceil(NQ / 4), bnQGlue = BN.quotient - BN.horner4Steps * K.bnHorner4.op - 116 * K.bnRD6.op / 6;
  op[`quotient (${NQ} words, fixed)`] = steps * K.blsHorner4.op + 4 * steps * K.blsRD6.op / 6 + (bnQGlue / 114) * NQ * 1.2 * GLUE;
  const s = BN.setup, wsRatio = (L.WS_SIZE + 48 * NQ) / (BN.bytes.WS + BN.bytes.WQfix0);
  op['setup: transcript'] = s.transcript * wsRatio;
  op['setup: parse + curve checks'] = s.parse * 1.8;
  op['setup: powers of z, eta z, Frob consts'] = s.powers * 1.8;
  op['setup: GLS tables (4 x 16 products, 8 rep evals)'] = 4 * K.blsTableMul.op + 8 * K.blsEval.op + 0.038e6 * 1.5;
  op['setup: loop setup'] = s.loopSetup * 1.5;
  op['terminal (endpoint, Rconst, Frob(S_c), fold, binding)'] = s.terminalOther * 1.8 * 0.8;
  op['cleanup + P2SH32 redeem hash'] = s.cleanup + s.p2sh * 1.13;
  const total = Object.values(op).reduce((a, b) => a + b, 0);
  // ---- bytes ----
  const by = {};
  by['code (BN 4,057 B: +27 B6 dbl kernel, -200 B terminal, +16 p)'] = 3900 + (affineDbl ? 300 : 0) + (bakedDelta ? 80 : 0);
  by['field constants (33 x 49 B: R_{k,0/1} 24, Rconst 6, gamma1 2, eta 1) + T'] = 33 * 49 + 9;
  by['delta slope pile (68 x 96 B + 9 piece headers)'] = NDSTEP * 96 + 27 + bakedDelta * 96;
  by['other data (tag, schedule, separators)'] = 100;
  const redeem = Object.values(by).reduce((a, b) => a + b, 0);
  const WSb = L.WS_SIZE + affineDbl * 96, WQb = 48 * NQ;
  const natural = redeem + WSb + WQb + 9;
  const needU = Math.ceil(total / ((1 - MARGIN) * 800) - 10000);
  const pad = Math.max(0, needU - natural);
  return {op, total, by, redeem, WS: WSb, WQ: WQb, natural, pad, unlocking: natural + pad, score: natural + pad + 35 + 63,
    marginNoPad: 1 - total / ((10000 + natural) * 800)};
}

const fmt = (x) => (x / 1e6).toFixed(3) + 'M';
const base = model();
console.log(`layout: ${NS} states (bounds ${DEFAULT_BOUNDS.join(',')}), WS ${L.WS_SIZE} B, WQ fixed ${NQ} words = ${48 * NQ} B\n`);
console.log('OP (worst case: every Q word full length)'); for (const [k, v] of Object.entries(base.op)) console.log('  ' + k.padEnd(56), fmt(v).padStart(9));
console.log('  ' + 'TOTAL'.padEnd(56), fmt(base.total).padStart(9));
console.log('\nBYTES'); for (const [k, v] of Object.entries(base.by)) console.log('  ' + k.padEnd(72), String(v).padStart(6));
console.log('  ' + 'redeem'.padEnd(72), String(base.redeem).padStart(6));
console.log('  ' + `WS (${L.WS_SIZE}) + WQ (${48 * NQ}) + 3 push headers`.padEnd(72), String(base.WS + base.WQ + 9).padStart(6));
console.log('  ' + 'unlocking without padding'.padEnd(72), String(base.natural).padStart(6), ` margin without padding ${(100 * base.marginNoPad).toFixed(1)}%`);
console.log('  ' + `padding for a ${100 * MARGIN}% margin`.padEnd(72), String(base.pad).padStart(6));
console.log('  ' + 'unlocking'.padEnd(72), String(base.unlocking).padStart(6));
console.log('  ' + 'score (+35 locking, +63 tx)'.padEnd(72), String(base.score).padStart(6));
console.log('\nVARIANTS (same margin)');
const rows = [['baseline (uniform projective B, delta recursion)', base]];
for (const n of [6, 10, 12, 16]) rows.push([`option A: first ${n} doublings affine with witnessed slopes`, model({affineDbl: n})]);
for (const n of [10, 15, 20]) rows.push([`option B: ${n} delta lines fully baked (lambda, c)`, model({bakedDelta: n})]);
for (const [name, m] of rows) console.log('  ' + name.padEnd(60), `op ${fmt(m.total)}  natural ${m.natural}  pad ${m.pad}  unlocking ${m.unlocking}  score ${m.score}`);
