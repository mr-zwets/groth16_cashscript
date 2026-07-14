// DECISIVE test for the note-2 concern: the NAF prefixes 13,26,52,104 share factor 13 with
// h2, so an attacker can supply an order-13 twist point B (passes on-curve) that drives R_B
// through O mid-walk. The homogeneous pointDouble/pointAdd have NO O special-case. Question:
// does any such bad B pass the fused psi check (R_B == -psi(B)) that is the ONLY guarantee
// B in G2 — the precondition the A/C cofactor-omission argument rests on?
//
// Method: enumerate the ENTIRE order-13 subgroup of E'(Fp2), run each point through the REAL
// contract walk (millerBatchOps, same formulas), and apply the EXACT contract psi compare.
import { Fp, Fp2, pairsFor, millerBatchOps } from './chunked/bls12-381/_pairingmath.mjs';
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
const runWalk = (Bpt) => {
  const a = Bpt.toAffine();
  const pairs = basePairs.map((pr, i) => (i === 0 ? { ...pr, Q: Bpt } : pr));
  const st = millerBatchOps(pairs);
  const Rb = st.states[st.states.length - 1].Rs[0]; // final R_B = [|x|]B (homogeneous)
  return { Rb, aff: a };
};

// exact contract compare: Rbx == psi(B).x * Rbz  AND  Rby == -psi(B).y * Rbz  (all in Fp2)
const contractPsiPass = (Rb, ax, ay) => {
  const ps = psiAff(ax, ay);
  const okX = Fp2.eql(Rb.x, Fp2.mul(ps.x, Rb.z));
  const okY = Fp2.eql(Rb.y, Fp2.mul(Fp2.neg(ps.y), Rb.z));
  return okX && okY;
};
// FIXED contract compare: same, but with the new guard `require(Rbz != 0)` in front.
const guardedPsiPass = (Rb, ax, ay) => !Fp2.eql(Rb.z, Fp2.ZERO) && contractPsiPass(Rb, ax, ay);

let badPassOld = false, badPassNew = false, degenCount = 0;
for (let j = 1n; j < 13n; j++) {
  const B = mulAny(gen13, j); // every nonzero order-13 point
  const { Rb, aff } = runWalk(B);
  const zZero = Fp2.eql(Rb.z, Fp2.ZERO);
  if (zZero) degenCount++;
  const oldPass = contractPsiPass(Rb, aff.x, aff.y);
  const newPass = guardedPsiPass(Rb, aff.x, aff.y);
  if (oldPass) badPassOld = true;
  if (newPass) badPassNew = true;
  console.log(`order-13 pt #${j}: Rb.z==0=${zZero}  UNGUARDED_pass=${oldPass}  GUARDED_pass=${newPass}`);
}

// control: an honest G2 point MUST still pass BOTH
const Bok = basePairs[0].Q;
const { Rb: RbOk, aff: affOk } = runWalk(Bok);
const okOld = contractPsiPass(RbOk, affOk.x, affOk.y);
const okNew = guardedPsiPass(RbOk, affOk.x, affOk.y);
console.log(`\nhonest G2 B: UNGUARDED_pass=${okOld} GUARDED_pass=${okNew} (both must be true)`);

console.log(`\ncollapsed (Rb.z==0) walks: ${degenCount}/12`);
console.log(`UNGUARDED: any bad B accepted = ${badPassOld}  (the bug)`);
console.log(`GUARDED  : any bad B accepted = ${badPassNew}  (must be false)`);
console.log(`GUARDED  : honest B still accepted = ${okNew}  (must be true)`);
console.log((!badPassNew && okNew)
  ? '\nRESULT: fix VERIFIED — guard rejects every order-13 B and preserves honest acceptance.'
  : '\n*** FIX FAILED ***');
