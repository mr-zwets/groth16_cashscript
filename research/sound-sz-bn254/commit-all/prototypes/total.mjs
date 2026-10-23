// Revised total for commit-all from the VM measurements in this directory (numbers copied from
// the outputs of miller.mjs, gt.mjs, pipeline.mjs, setup.mjs; see the comments) and a balance
// search over the line implementations. score = max(unlock bytes, op/800 - 10,000) + 100 B tx.
// Every constant below is an output of those scripts (run them to re-derive it).
// Usage: node total.mjs   (FIX=0 for the fixture-0 witness shape; default FIX=4, the worst fixture)
// ---------- Miller section (miller.mjs, consensus = standard, fixture-0 proof, real 6x+2 schedule)
const MILLER = {
  anchorOp: 19095452,              // B projective (88 lines) + delta baked-lambda (88 lines), incl. 65 fold squarings,
                                   // 21 chat mults, psi x6, tie check (node miller.mjs proj lam pick)
  // per-line op deltas from the variant totals (aff/lam 13.00M, proj/lamb 15.68M, proj/proj 26.94M; 88 lines each)
  dBaff: -(19095452 - 12999523) / 88,    // B affine (witnessed, checked slopes) instead of projective
  dDlamb: -(19095452 - 15680732) / 88,   // delta (lambda, b) baked instead of lambda-only
  dDproj: (26940103 - 19095452) / 88 + 3000, // delta projective via the shared projective kernels (+3k arrangement)
  // code bytes of each kernel type (solved from the fused function sizes EV/AD of the five variants)
  code: {Bproj: 493 + 587, Baff: 256 + 268, Dlam: 184 + 188, Dlamb: 59 + 54, DprojWrap: 80, fixed: 322 + 106 + 36 + 40},
  driver: 702,                     // main: invokes (232) + picks/negations (470)
};
// ---------- GT block (gt.mjs)
const GT = {
  op: 2 * (34801 + 24560 + 34758) + 2 * 6883   // phi^1..3(G_i) exact + evaluation at +-z, and G_i itself
    + 2503552                                  // GTE: decode + conditional (swapped) fold mults + S_i accumulation, densest of 3000 random inputs
    + (34801 + 24560 + 34758) + 6883 + 6883    // phi^1..3(chat), chat, K evaluations
    + 3 * 5000,                                // eps(gamma_w,j) * z, j = 1..3
  bytes: 93 + 612 + (351 + 173 + 351 + 45) + 2 * 198 + 198 + 3 * 33, // GTE + branch fns + FROB kernels (consts inline) + G_1, G_2, K + p^j mod r
};
// ---------- states / quotient / transcript (pipeline.mjs, standard mode) and witness shape (reference.mjs)
// FIX=4 (default, the worst fixture): 31 states, deg Q = 265 -> 133 odd coefficients, 17 pieces of 8 limbs
//   (136 limbs, top piece zero-padded); pipeline measured as `pipeline.mjs 32 133` (one boundary spare).
// FIX=0: 32 states, deg Q = 245 -> 123 odd coefficients, 16 pieces; `pipeline.mjs 32 123`.
// Push overhead: 192-B push = OP_PUSHDATA1 + 1 length byte (194 B); 256-B and 320-B pushes = OP_PUSHDATA2 + 2 (+3 B).
const SHAPES = {4: {states: 31, pieces: 17, pipeOp: 2090689}, 0: {states: 32, pieces: 16, pipeOp: 2033261}};
const SHAPE = SHAPES[process.env.FIX ?? 4];
const PIPE = {op: SHAPE.pipeOp, codeBytes: 1100};
const WITNESS = {statesQ: SHAPE.states * 194 + SHAPE.pieces * (256 + 3), chat: 194, stmt: 323, digits: 132, mask: 10};
// ---------- setup (setup.mjs) and misc
const SETUP = {op: 95027, bytes: 593};
const MISC = {
  op: 65 * 1500        // per-event driver: mask bit test, chunk-length counter (review fix 4), GTE invoke
    + 23 * 5000        // review fix 6 (optional): Z != 0 (sign-safe, mod p) at the 23 projective additions
    + 40000,           // P2SH32 redeem hash, standard rate
  bytes: 132 /* delta start */ + 33 /* tag */ + 34 /* p */ + 200 /* glue */,
};
const fixedOp = GT.op + PIPE.op + SETUP.op + MISC.op;
const fixedBytes = GT.bytes + PIPE.codeBytes + SETUP.bytes + MISC.bytes + Object.values(WITNESS).reduce((a, b) => a + b, 0);
function config(nBaff, nDlamb, nDproj) {
  const L = 88, nDlam = L - nDlamb - nDproj;
  const op = MILLER.anchorOp + nBaff * MILLER.dBaff + nDlamb * MILLER.dDlamb + nDproj * MILLER.dDproj + fixedOp;
  const c = MILLER.code;
  const code = c.fixed + (nBaff < L ? c.Bproj : 0) + (nBaff > 0 ? c.Baff : 0) + (nDlam > 0 ? c.Dlam : 0) + (nDlamb > 0 ? c.Dlamb : 0) + (nDproj > 0 ? c.DprojWrap + (nBaff === L ? c.Bproj : 0) : 0);
  const bytes = fixedBytes + code + MILLER.driver + nBaff * 66 + nDlam * 66 + (nDlam ? 132 : 0) + nDlamb * 132 + 2 * nDproj;
  return {nBaff, nDlam, nDlamb, nDproj, bytes: Math.round(bytes), opM: +(op / 1e6).toFixed(2), opEq: Math.round(op / 800 - 10000), score: Math.round(Math.max(bytes, op / 800 - 10000) + 100)};
}
let best = null;
for (let a = 0; a <= 88; a++) for (let lb = 0; lb <= 88; lb++) for (let pj = 0; pj + lb <= 88; pj++) { const r = config(a, lb, pj); if (!best || r.score < best.score) best = r; }
console.log('fixed (non-line) op', (fixedOp / 1e6).toFixed(2) + 'M', 'fixed bytes', fixedBytes);
console.log('pure configurations:');
for (const [a, lb, pj, name] of [[0, 0, 0, 'B proj + delta lambda'], [0, 88, 0, 'B proj + delta (lambda,b)'], [0, 0, 88, 'B proj + delta proj'], [88, 0, 0, 'B affine + delta lambda'], [88, 88, 0, 'B affine + delta (lambda,b)']])
  console.log(' ', name.padEnd(30), JSON.stringify(config(a, lb, pj)));
console.log('best mix:', JSON.stringify(best), 'op over budget (B-equivalent):', best.opEq - best.bytes);
export {best, config};
