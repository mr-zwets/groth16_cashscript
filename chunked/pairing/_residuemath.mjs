// Residue-method math for the witnessed final-exponentiation (ePrint 2024/640) + the
// c^-(6x+2)-fused Miller loop. Built on _millermath (noble tower, matching the .cash).
//
//   verifier relation (terminal tail):  fF * w * c^q^2 == c^q * c^q^3
//   where fF = fRaw * c^-(6x+2) (folded into the Miller loop), c,w the residue witness.
//   Equivalent to c^lambda == fRaw*w with lambda = 6x+2 + q - q^2 + q^3, i.e. the pairing
//   product finalExp == 1. Witness from gnark's finalExpWitness (scaling + r,m,cube roots).
import {
  bn254, Fp, Fp2, Fp6, Fp12, BN_X, ATE_NAF,
  pairsFor, millerBatchOps, singlePairMiller, pointDouble, pointAdd, lineFn, lineUnitFn, psi,
} from './_millermath.mjs';

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
const isZero6 = (a) => Fp6.eql(a, Fp6.ZERO);

// ---- 27th root of unity (noble tower), cubic non-residue in Fp6 (only c0.c2 nonzero) ----
export const ROOT27 = mk12([0n, 0n, 0n, 0n,
  18017241959182010774688792132341824651274886350515952296967734324480226243499n,
  8310587989442958350646884634893221121607168288938349542082022013494928077472n], [0n, 0n, 0n, 0n, 0n, 0n]);
// the baked 27-coset {ROOT27^j : j=0..26} the tail checks w against
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
export function residueWitness(fRaw) {
  let w = null, rw = null;
  for (const cand of [Fp12.ONE, ROOT27, sqr(ROOT27)]) { const t = mul(fRaw, cand); if (isOne(powExact(t, exp1))) { w = cand; rw = t; break; } }
  if (!w) throw new Error('no cubic-residue scaling');
  rw = powExact(rw, rInv);
  rw = powExact(rw, mInv);
  const c = cubeRoot(rw);
  return { c, cInv: inv(c), w };
}

// A nontrivial r-th root has k^lambda=1 because r divides lambda. If the
// residue root returned above is the quotient torus's unique infinity point,
// multiplying by k preserves the witness relation and moves it to the finite
// chart because k.c1 is nonzero. Thus every accepting quotient class has a
// complete six-limb representative [1 + u*W], without a fixture assumption.
const TORUS_KERNEL_SHIFT = bn254.pairing(bn254.G1.Point.BASE, bn254.G2.Point.BASE);
if (isZero6(TORUS_KERNEL_SHIFT.c1) || !eq12(powExact(TORUS_KERNEL_SHIFT, LAMBDA), Fp12.ONE)) {
  throw new Error('invalid BN254 quotient-torus kernel shift');
}
export function residueTorusWitness(fRaw) {
  const witness = residueWitness(fRaw);
  const c = isZero6(witness.c.c0) ? mul(witness.c, TORUS_KERNEL_SHIFT) : witness.c;
  if (isZero6(c.c0)) throw new Error('failed to move residue root into the finite torus chart');
  const u = Fp6.mul(c.c1, Fp6.inv(c.c0));
  return { c, cInv: inv(c), u };
}

// ---- c^-(6x+2)-FUSED batched Miller ----------------------------------------------------
// Same flat op list as millerBatchOps, but after each NAF-step squaring we fold one factor
// of c^-1 (digit +1) or c (digit -1) into the shared f, so that across the loop f accumulates
// c^-(6x+2) alongside f_{6x+2}. New op type {t:'cf', neg} (c-fold). c,cInv are CONSTANT state
// carried (12+12 limbs) so each chunk can multiply by them. states[i] = {f, Rs, c, cInv}.
export function millerFusedOps(pairs, c, cInv, { fixedMiller = null } = {}) {
  // f_{6x+2} is built by 65 squarings with the leading 1 (2^65) preloaded by R=Q (naf() drops
  // the MSB, stopping at a>1). So we inject the MSB c-fold as a LEADING 'cf' (xcInv): squared 65
  // times -> c^-2^65; the per-NAF-digit folds add c^-V; total c-power = c^-(2^65+V) = c^-(6x+2).
  // fused f = base_f * cpow; c,cInv are CONSTANT carried state. ops/states mirror millerBatchOps.
  // OPTIMIZATION: pair 1 = e(alpha,beta) is a VK constant, so its ~89 line-folds are dropped from
  // the loop (skipPairs) and its single-pair Miller value f_{alpha,beta} is multiplied in once via
  // a 'cmul1' op (a constant fp12Mul the chunk bakes). Saves ~24M op (~12% of the miller).
  const base = millerBatchOps(pairs, { skipPairs: new Set([1]) });
  const fAB = fixedMiller ?? singlePairMiller(pairs[1]).f; // baked fixed-pair Miller value
  const ops = []; const states = [];
  // MSB optimization: the 2^65 term's c-fold is folded into the GENESIS f instead of a leading
  // fp12Mul op — we just initialize cpow = cInv (so the genesis fused f = ONE*cInv = cInv, committed
  // directly) and let the loop's 65 squarings carry it to c^-2^65. Saves one full fp12Mul (~417K).
  let cpow = cInv; let k = 0;
  for (let bi = 0; bi < base.ops.length; bi++) {
    const op = base.ops[bi];
    states.push({ f: mul(base.states[bi].f, cpow), Rs: base.states[bi].Rs.slice(), c, cInv });
    ops.push(op.t === 'sqr' ? { t: 'sqr' } : op);
    if (op.t === 'sqr') {
      cpow = sqr(cpow);
      const digit = ATE_NAF[k] ?? 0;
      if (digit !== 0) {
        states.push({ f: mul(base.states[bi + 1].f, cpow), Rs: base.states[bi + 1].Rs.slice(), c, cInv });
        ops.push({ t: 'cf', neg: digit === -1 }); // digit +1 -> xcInv ; -1 -> xc
        cpow = mul(cpow, digit === 1 ? cInv : c);
      }
      k++;
    }
  }
  // f after the loop = (f0*f2*f3) * c^-(6x+2); now multiply in the baked f_{alpha,beta} (one mul).
  const preF1 = mul(base.boundary, cpow);
  states.push({ f: preF1, Rs: base.states[base.states.length - 1].Rs.slice(), c, cInv });
  ops.push({ t: 'cmul1' }); // f *= f_{alpha,beta} (baked constant)
  const boundary = mul(preF1, fAB);
  states.push({ f: boundary, Rs: base.states[base.states.length - 1].Rs.slice(), c, cInv });
  return { ops, states, boundary, baseBoundary: base.boundary, cpowFinal: cpow, fAB };
}

// ---- affine runtime-G2 variant -------------------------------------------------------
// Only pair 0 has a runtime G2 point. Keep its Miller accumulator affine and witness each
// tangent/chord slope; pairs 2 and 3 retain their baked projective line coefficients. Every
// normalized runtime line has c2=-1, an Fp2 line scaling that disappears in final exponentiation.
const affineDouble = (point) => {
  const denominator = Fp2.mul(point.y, 2n);
  if (Fp2.eql(denominator, Fp2.ZERO)) throw new Error('affine Miller doubling denominator is zero');
  const slope = Fp2.div(Fp2.mul(Fp2.sqr(point.x), 3n), denominator);
  const x = Fp2.sub(Fp2.sqr(slope), Fp2.mul(point.x, 2n));
  const y = Fp2.sub(Fp2.mul(slope, Fp2.sub(point.x, x)), point.y);
  return {
    R: { x, y }, slope,
    coeffs: [Fp2.sub(point.y, Fp2.mul(slope, point.x)), slope, Fp2.neg(Fp2.ONE)],
  };
};
const affineAdd = (point, addend) => {
  const denominator = Fp2.sub(addend.x, point.x);
  if (Fp2.eql(denominator, Fp2.ZERO)) throw new Error('affine Miller addition denominator is zero');
  const slope = Fp2.div(Fp2.sub(addend.y, point.y), denominator);
  const x = Fp2.sub(Fp2.sub(Fp2.sqr(slope), point.x), addend.x);
  const y = Fp2.sub(Fp2.mul(slope, Fp2.sub(point.x, x)), point.y);
  return {
    R: { x, y }, slope,
    coeffs: [Fp2.sub(point.y, Fp2.mul(slope, point.x)), slope, Fp2.neg(Fp2.ONE)],
  };
};

export function millerFusedAffineOps(pairs, c, cInv, { unitLines = false, torusU = null, fixedMiller = null } = {}) {
  const raw = millerFusedOps(pairs, c, cInv, { fixedMiller });
  const pairData = pairs.map((pair) => {
    const P = pair.P.toAffine();
    const infinity = pair.P.equals(bn254.G1.Point.ZERO);
    const invY = unitLines && !infinity ? Fp.inv(P.y) : null;
    let u = null, v = null;
    if (unitLines) {
      u = infinity ? 0n : Fp.neg(Fp.mul(P.x, invY));
      v = infinity ? 0n : Fp.neg(invY);
    }
    return {
      P, Q: pair.Q.toAffine(),
      u, v,
    };
  });
  const lineCoeffs = (coeffs) => {
    if (!unitLines) return coeffs;
    if (Fp2.eql(coeffs[2], Fp2.ZERO)) throw new Error('unit Miller line has zero c2');
    const scale = Fp2.neg(Fp2.inv(coeffs[2]));
    return [Fp2.mul(coeffs[0], scale), Fp2.mul(coeffs[1], scale), Fp2.ONE];
  };
  const foldLine = (value, coeffs, j) => {
    const normalized = lineCoeffs(coeffs);
    return {
      coeffs: normalized,
      f: unitLines
        ? lineUnitFn(value, normalized[0], normalized[1], pairData[j].u, pairData[j].v)
        : lineFn(value, normalized[0], normalized[1], normalized[2], pairData[j].P.x, pairData[j].P.y),
    };
  };
  const ops = [];
  const states = [];
  const fAbTorus = isZero6(raw.fAB.c0) ? null : Fp6.mul(raw.fAB.c1, Fp6.inv(raw.fAB.c0));
  if (torusU !== null && fAbTorus === null) {
    throw new Error('the fixed alpha/beta Miller value has no finite quotient-torus coordinate');
  }
  let f = torusU === null ? cInv : Fp12.create({ c0: Fp6.ONE, c1: Fp6.neg(torusU) });
  let runtimeR = { ...pairData[0].Q };
  for (const rawOp of raw.ops) {
    states.push({ f, Rs: [runtimeR], c, cInv });
    const op = { ...rawOp, affineSlopes: [] };
    if (op.t === 'sqr') f = Fp12.sqr(f);
    else if (op.t === 'cf') {
      if (torusU === null) {
        f = Fp12.mul(f, op.neg ? c : cInv);
      } else {
        const foldU = op.neg ? torusU : Fp6.neg(torusU);
        f = Fp12.create({
          c0: Fp6.add(f.c0, Fp6.mulByNonresidue(Fp6.mul(f.c1, foldU))),
          c1: Fp6.add(f.c1, Fp6.mul(f.c0, foldU)),
        });
      }
    } else if (op.t === 'cmul1') {
      if (torusU === null) {
        f = Fp12.mul(f, raw.fAB);
      } else {
        f = Fp12.create({
          c0: Fp6.add(f.c0, Fp6.mulByNonresidue(Fp6.mul(f.c1, fAbTorus))),
          c1: Fp6.add(f.c1, Fp6.mul(f.c0, fAbTorus)),
        });
      }
    } else if (op.j !== 0) {
      const triples = op.t === 'pp' ? op.coeffs : [op.coeffs];
      const normalized = [];
      for (const coeffs of triples) {
        const folded = foldLine(f, coeffs, op.j);
        f = folded.f;
        normalized.push(folded.coeffs);
      }
      op.coeffs = op.t === 'pp' ? normalized : normalized[0];
    } else if (op.t === 'dl') {
      const step = affineDouble(runtimeR);
      runtimeR = step.R;
      op.affineSlopes.push(step.slope);
      f = foldLine(f, step.coeffs, 0).f;
    } else if (op.t === 'al') {
      const step = affineAdd(runtimeR, {
        x: pairData[0].Q.x,
        y: op.neg ? Fp2.neg(pairData[0].Q.y) : pairData[0].Q.y,
      });
      runtimeR = step.R;
      op.affineSlopes.push(step.slope);
      f = foldLine(f, step.coeffs, 0).f;
    } else {
      const [q1x, q1y] = psi(pairData[0].Q.x, pairData[0].Q.y);
      const q1 = { x: q1x, y: q1y };
      const first = affineAdd(runtimeR, q1);
      runtimeR = first.R;
      op.affineSlopes.push(first.slope);
      f = foldLine(f, first.coeffs, 0).f;
      const [q2x, q2y] = psi(q1.x, q1.y);
      const q2 = { x: q2x, y: q2y };
      const second = affineAdd(runtimeR, { x: q2.x, y: Fp2.neg(q2.y) });
      runtimeR = second.R;
      op.affineSlopes.push(second.slope);
      f = foldLine(f, second.coeffs, 0).f;
    }
    ops.push(op);
  }
  states.push({ f, Rs: [runtimeR], c, cInv });
  return { ops, states, boundary: f, fAB: raw.fAB };
}

// ---- cInv-ONLY fused Miller (binary of 6x+2, threads only cInv) -----------------------
// Folds c^-(6x+2) = cInv^(6x+2) using ONLY cInv (every digit +1 in the binary expansion ->
// one fp12Mul by cInv). Threads only cInv (12 limbs, not c+cInv=24), so every chunk's covIn/
// covOut hash and blob shrink. c is NOT needed here — the residue TAIL takes c as a witness
// and pins it via c*cInv==ONE against the (committed) threaded cInv. State {f, Rs, cInv}.
export function millerFusedOpsCinv(pairs, cInv) {
  const six = SIX_X_PLUS_2;
  const L = six.toString(2).length; // 65
  const bitAt = (pos) => (six >> BigInt(pos)) & 1n; // pos 0..L-1
  const base = millerBatchOps(pairs);
  const ops = []; const states = [];
  let cpow = Fp12.ONE; let k = 0;
  for (let bi = 0; bi < base.ops.length; bi++) {
    const op = base.ops[bi];
    states.push({ f: mul(base.states[bi].f, cpow), Rs: base.states[bi].Rs.slice(), cInv });
    ops.push(op.t === 'sqr' ? { t: 'sqr' } : op);
    if (op.t === 'sqr') {
      cpow = sqr(cpow);
      if (bitAt(L - 1 - k) === 1n) { // MSB-first: step k processes binary bit (L-1-k)
        states.push({ f: mul(base.states[bi + 1].f, cpow), Rs: base.states[bi + 1].Rs.slice(), cInv });
        ops.push({ t: 'cf' }); // always x cInv
        cpow = mul(cpow, cInv);
      }
      k++;
    }
  }
  const boundary = mul(base.boundary, cpow);
  states.push({ f: boundary, Rs: base.states[base.states.length - 1].Rs.slice(), cInv });
  return { ops, states, boundary, cpowFinal: cpow };
}

// self-test when run directly
if (process.argv[1] && process.argv[1].endsWith('_residuemath.mjs')) {
  const { vec } = await import('./_millermath.mjs');
  const inputs = vec.publicInputs.map(BigInt);
  const pairs = pairsFor(inputs);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  console.log('c*cInv == 1 ?', isOne(mul(c, cInv)));
  const wIs = isOne(w) ? '1' : eq12(w, ROOT27) ? 'root27' : eq12(w, sqr(ROOT27)) ? 'root27^2' : '??';
  console.log('w =', wIs, '| w in COSET27 ?', COSET27.some((e) => eq12(e, w)));
  const fused = millerFusedOps(pairs, c, cInv);
  const expectFF = mul(fRaw, powExact(cInv, SIX_X_PLUS_2));
  console.log('fused boundary == fRaw*c^-(6x+2) ?', eq12(fused.boundary, expectFF));
  console.log('cpowFinal == c^-(6x+2) ?', eq12(fused.cpowFinal, powExact(cInv, SIX_X_PLUS_2)));
  // tail relation with fF = fused boundary
  const fF = fused.boundary;
  const tail = eq12(mul(mul(fF, w), frob(c, 2)), mul(frob(c, 1), frob(c, 3)));
  console.log('TAIL fF*w*c^q2 == c^q*c^q3 (frobenius) ?', tail);
  console.log('num fused ops =', fused.ops.length, '(base', millerBatchOps(pairs).ops.length, ') cf ops =', fused.ops.filter(o => o.t === 'cf').length);
  // cInv-only variant
  const fusedCi = millerFusedOpsCinv(pairs, cInv);
  console.log('\n[cInv-only] boundary == fRaw*c^-(6x+2) ?', eq12(fusedCi.boundary, expectFF));
  const fFci = fusedCi.boundary;
  const tailCi = eq12(mul(mul(fFci, w), frob(c, 2)), mul(frob(c, 1), frob(c, 3)));
  console.log('[cInv-only] TAIL holds ?', tailCi, '| cf ops =', fusedCi.ops.filter(o => o.t === 'cf').length);
}
