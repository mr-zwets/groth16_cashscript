// Event schedule, per-event factor degrees and checkpoint segmentation for the hybrid-direct
// protocol. Exported for ref.mjs and model.mjs.
import {pathToFileURL} from 'node:url';
export const BN_X = 4965661367192848881n;
// NAF digits of 6x+2 without the leading 1, exactly as densless-recovered/witness.mjs
export const digits = (() => {
  const d = [];
  for (let n = 6n * BN_X + 2n; n > 1n; n >>= 1n) {
    if (!(n & 1n)) d.unshift(0);
    else if ((n & 3n) === 3n) { d.unshift(-1); n++; }
    else d.unshift(1);
  }
  return d;
})();
export const EVENTS = digits.length; // 65
export const LAST = EVENTS - 1;
export const LINE_DEG = 9;   // y_P + (-lambda x_P) X + beta X^3, Fp2 coefficients -> X^6 shifts
export const TAU_DEG = 11;   // 1 + X g(X^2), g in Fp6 (tower limbs) -> degree 1 + 10
// lines per event: 3 doubling lines, +3 addition lines when the digit is nonzero, +6 Frobenius
// lines (psi(Q), -psi^2(Q) for each of the 3 pairs) in the last event.
export const linesIn = (e) => 3 + (digits[e] ? 3 : 0) + (e === LAST ? 6 : 0);
// factor degree of event e: lines, the c^{-d} fold, and the baked e(alpha,beta) Miller value K
// (torus-normalized, degree 11) multiplied once in the last event.
export const phiDeg = (e) => LINE_DEG * linesIn(e) + (digits[e] ? TAU_DEG : 0) + (e === LAST ? TAU_DEG : 0);
// degree of R_j = (tau(G_prev)^(2^m) * prod of event factors with their squarings) * tau(-G_j)
export const segDeg = (a, b) => {
  let d = TAU_DEG;
  for (let e = a; e <= b; e++) d = 2 * d + phiDeg(e);
  return d + TAU_DEG;
};
// number of odd coefficients of Q_j = (R(X) - R(-X)) / M, deg Q = D - 12
export const qOdd = (D) => Math.floor((D - 12 + 1) / 2);
// Greedy segmentation under a degree cap (contiguous, monotone -> greedy minimizes count)
export const segment = (cap) => {
  const segs = []; let a = 0;
  while (a < EVENTS) {
    let b = a;
    if (segDeg(a, a) > cap) return null;
    while (b + 1 < EVENTS && segDeg(a, b + 1) <= cap) b++;
    segs.push([a, b]); a = b + 1;
  }
  return segs;
};
// byte-optimal segmentation: states 6 limbs each, Q odd coefficients; per-limb push bytes `w`
export const bestSegmentation = (w = 33.5) => {
  let best = null;
  for (let cap = 40; cap <= 2000; cap++) {
    const segs = segment(cap); if (!segs) continue;
    const D = Math.max(...segs.map(([a, b]) => segDeg(a, b)));
    const bytes = w * (6 * segs.length + qOdd(D));
    if (!best || bytes < best.bytes) best = {cap, D, segs, J: segs.length, nQ: qOdd(D), bytes};
  }
  return best;
};
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log('events', EVENTS, 'nonzero digits', digits.filter(Boolean).length,
    'lines', Array.from({length: EVENTS}, (_, e) => linesIn(e)).reduce((a, b) => a + b, 0));
  for (const cap of [100, 150, 200, 250, 300, 400, 600]) {
    const s = segment(cap); if (!s) { console.log(cap, 'infeasible'); continue; }
    const D = Math.max(...s.map(([a, b]) => segDeg(a, b)));
    console.log(`cap ${cap}: J=${s.length} maxDeg=${D} nQ=${qOdd(D)} bytes~${Math.round(33.5 * (6 * s.length + qOdd(D)))}`);
  }
  const b = bestSegmentation();
  console.log('best', {cap: b.cap, D: b.D, J: b.J, nQ: b.nQ, bytes: Math.round(b.bytes)});
  console.log('segments', JSON.stringify(b.segs));
}
