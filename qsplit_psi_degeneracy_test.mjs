// The binary prefixes 13,26,52,104 share factor 13 with h2, so an order-13 twist
// point reaches O during the walk. The compiled qsplit verifier uses affine tangent
// and chord equations, which require every denominator to be nonzero. This executes
// that exact fused affine/direct8 path for the complete order-13 subgroup, then checks
// that an ordinary G2 point completes and satisfies the terminal psi relation.
//
// Method: enumerate the complete order-13 subgroup of E'(Fp2), run each point through
// qsplitMillerFusedAffineDirect8Ops with the compiled pair schedule, and require the
// affine denominator check. Then apply the compiled affine psi comparison to ordinary G2.
import {
  Fp,
  Fp2,
  Fp12,
  qsplitPairsFor as pairsFor,
} from './chunked/bls12-381/_pairingmath.mjs';
import {
  qsplitFixedVkMiller,
  qsplitMillerFusedAffineDirect8Ops,
} from './chunked/bls12-381/_residuemath.mjs';
import { bls12_381 } from './chunked/bls12-381/_vkxmath.mjs';

const G2 = bls12_381.G2.Point;
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const X = 0xd201000000010000n;
const h2 = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n;
const mulAny = (Q, k) => { let res = G2.ZERO, base = Q; while (k > 0n) { if (k & 1n) res = res.add(base); base = base.double(); k >>= 1n; } return res; };

// psi from the contract's exact baked constants (Bls12381LazyG.cash lines 92-95)
const C1 = Fp2.fromBigTuple([0n, 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437n]);
const C2 = Fp2.fromBigTuple([2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530n, 1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257n]);
const conj2 = (v) => Fp2.create({ c0: v.c0, c1: Fp.neg(v.c1) });
const psiAff = (ax, ay) => ({ x: Fp2.mul(C1, conj2(ax)), y: Fp2.mul(C2, conj2(ay)) });

// Build an order-EXACTLY-13 twist point. v_13(h2)=2, so map a random full-group point into the
// 13-Sylow via [h2*r/13^2], then reduce to order 13. (Only order-exactly-13 B degenerate R_B
// through O at prefix 13; order 13*m>13 never hits O at step 3.)
let v = 0n, hh = h2; while (hh % 13n === 0n) { v++; hh /= 13n; }
const cofToSylow = (h2 * r) / (13n ** v);
const bTwist = Fp2.fromBigTuple([4n, 4n]);
const onCurveRhs = (x) => Fp2.add(Fp2.mul(Fp2.mul(x, x), x), bTwist);
const Fp2sqrt = (a) => { try { return Fp2.sqrt(a); } catch { return null; } };
let gen13 = null;
for (let i = 1n; i < 300n && !gen13; i++) {
  const x = Fp2.fromBigTuple([i, 1n]);
  const y = Fp2sqrt(onCurveRhs(x)); if (y === null) continue;
  let s = mulAny(G2.fromAffine({ x, y }), cofToSylow); if (s.is0()) continue;
  while (!mulAny(s, 13n).is0()) s = mulAny(s, 13n); // reduce to order exactly 13
  if (!s.is0() && mulAny(s, 13n).is0()) gen13 = s;
}
if (!gen13) { console.log('could not build order-13 generator'); process.exit(1); }
console.log('order-13 generator built; 13 | h2 =', h2 % 13n === 0n, ', 13 | |x| =', X % 13n === 0n);

const basePairs = pairsFor([123n, 456n]);
const runCompiledPath = (Bpt) => {
  const affineB = Bpt.toAffine();
  const pairs = basePairs.map((pr, i) => (i === 0 ? { ...pr, Q: Bpt } : pr));
  const trace = qsplitMillerFusedAffineDirect8Ops(pairs, Fp12.ONE, Fp12.ONE, {
    fixedMiller: qsplitFixedVkMiller(pairs, true),
    skipPairs: new Set([1, 2]),
  });
  return {
    affineB,
    endpoint: trace.states[trace.states.length - 1].Rs[0],
  };
};

const affinePsiPass = (endpoint, ax, ay) => {
  const ps = psiAff(ax, ay);
  return Fp2.eql(endpoint.x, ps.x) && Fp2.eql(endpoint.y, Fp2.neg(ps.y));
};

const denominatorMessage = /^affine BLS Miller (doubling|addition) denominator is zero$/;
let guardedCount = 0;
for (let j = 1n; j < 13n; j++) {
  const B = mulAny(gen13, j); // every nonzero order-13 point
  let guarded = false;
  let guard = '';
  try {
    runCompiledPath(B);
  } catch (error) {
    guard = error instanceof Error ? error.message : String(error);
    guarded = denominatorMessage.test(guard);
  }
  if (guarded) guardedCount += 1;
  console.log(`order-13 point ${j}: affine denominator guard=${guarded} (${guard})`);
}

let ordinaryCompleted = false;
let ordinaryPsiPass = false;
try {
  const { endpoint, affineB } = runCompiledPath(basePairs[0].Q);
  ordinaryCompleted = true;
  ordinaryPsiPass = affinePsiPass(endpoint, affineB.x, affineB.y);
} catch {}

console.log(`\norder-13 affine denominator guards: ${guardedCount}/12`);
console.log(`ordinary G2 path completed: ${ordinaryCompleted}`);
console.log(`ordinary G2 endpoint satisfies psi: ${ordinaryPsiPass}`);
const passed = guardedCount === 12 && ordinaryCompleted && ordinaryPsiPass;
console.log(passed
  ? '\nRESULT: compiled affine/direct8 path certificate passed.'
  : '\nRESULT: compiled affine/direct8 path certificate did not pass.');
if (!passed) process.exitCode = 1;
