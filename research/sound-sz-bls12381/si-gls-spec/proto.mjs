// Protocol reference for BLS12-381 SI-GLS (design prototype): honest prover at the polynomial level, the
// value-level verifier (the +-z chains as the script would run them), the worst-case degree bound, and the
// quotient size, for a chosen chunk layout and affine/projective split of the B walk.
//
//   node proto.mjs [--fix=committed|proof1|dense|zero|max|msm-identity|all] [--eaff=N] [--layout=NAME] [--json]
//
// eaff: events 0..eaff-1 run the B walk in affine coordinates with witnessed slopes (line degree 8), events
// eaff..62 projectively (line degree 9). layout: the chunk boundaries (see LAYOUTS).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {
  F2, F12, Fr, G1, G2, p, r, AX, mod, inv, pmul, psub, padd, pneg, peval, pdivM, pmodM, isZero, deg, trim, Phi, f2,
  toPoly, fromPoly, monicRep, sameClass, frob1Monic, B_TWIST, psiAff, lineAffPoly, lineGenPoly, BITS, NE, ADD_EVENTS,
  slopeDbl, slopeAdd, miller, FE, LAMBDA, N6, N6R, glsDigits, glsFactorPoly, ETA, M,
} from './blsmath.mjs';

const arg = (k, d) => { const a = process.argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split('=')[1] : d; };
const flag = (k) => process.argv.includes(`--${k}`);

// ---------------- VK and fixtures (same VK and synthetic proofs as the bench's BLS12-381 FS-PIT entries) ----------------
const VK = {alpha: G1.BASE.multiply(3n), beta: G2.BASE.multiply(5n), gamma: G2.BASE.multiply(7n), delta: G2.BASE.multiply(11n), ic: [2n, 4n, 6n].map((k) => G1.BASE.multiply(k))};
const sm = (x) => mod(x, r);
const synthetic = (inputs, b, c) => { const vx = sm(2n + 4n * inputs[0] + 6n * inputs[1]); const rhs = sm(15n + vx * 7n + c * 11n); const a = sm(rhs * Fr.inv(b));
  return {inputs, proof: {a: G1.BASE.multiply(a), b: G2.BASE.multiply(b), c: G1.BASE.multiply(c)}}; };
export const FIXTURES = {
  committed: synthetic([123n, 456n], 1n, 13n),
  proof1: synthetic([135208n, 67633n], 17n, 19n),
  dense: synthetic([40792793307691160132937706698213704133054528069427933762012433436987942497952n, 20976222017425405296340351928930328963278634447870202382235661951061637561134n], 23n, 29n),
  zero: synthetic([0n, 0n], 31n, 37n),
  max: synthetic([r - 1n, r - 1n], 41n, 43n),
  'msm-identity': synthetic([3n, r - 2n], 47n, 53n),
};

// ---------------- chunk layouts: arrays of chunk lengths over events 0..62 (sum 63) ----------------
const pairsFrom = (start) => { const out = []; for (let e = start; e < NE; e += 2) out.push(Math.min(2, NE - e)); return out; };
export const LAYOUTS = {
  // [0] [1,2] [3,4] [5,6] ... : 32 chunks, 31 states; the addition at event 5 is the first event of its chunk
  u2: [1, ...pairsFrom(1)],
  // [0] [1,2] [3] [4,5] [6] [7,8] ... [61,62]: 33 chunks, 32 states; every addition is a single or second event
  a2: [1, 2, 1, 2, 1, ...pairsFrom(7)],
  // 3-event chunks after [0]: 22 chunks
  u3: [1, ...(() => { const o = []; for (let e = 1; e < NE; e += 3) o.push(Math.min(3, NE - e)); return o; })()],
};

// ---------------- the B walk lines (exact polynomials as the script computes them) ----------------
// affine: line (c, -lam, 1) at P = (xP, yP), degree 8. projective doubling of T = (X:Y:Z) (homogeneous, a = 0):
//   B = Y^2, C = Z^2, E = 3b'C, F = 3E, H = (Y+Z)^2 - B - C;  X3 = 2XY(B - F), Y3 = (B + F)^2 - 12E^2, Z3 = 4BH,
//   line (l0, l2, l3) = (B - E, -3X^2, H) = 2YZ * affine tangent.   degree 9.
// projective mixed addition T + Q: th = Y - yq Z, la = X - xq Z, C = th^2, D = la^2, E = la D, F = Z C, G = X D,
//   H = E + F - 2G;  X3 = la H, Y3 = th (G - H) - Y E, Z3 = Z E;  line (th xq - la yq, -th, la) = la * affine chord.
const b3 = F2.mul(B_TWIST, f2(3n, 0n));
const projDbl = ({X, Y, Z}) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(b3, C), F = F2.mul(E, f2(3n, 0n)), H = F2.sub(F2.sub(F2.sqr(F2.add(Y, Z)), B), C);
  const X3 = F2.mul(F2.mul(f2(2n, 0n), F2.mul(X, Y)), F2.sub(B, F)), Y3 = F2.sub(F2.sqr(F2.add(B, F)), F2.mul(f2(12n, 0n), F2.sqr(E))), Z3 = F2.mul(f2(4n, 0n), F2.mul(B, H));
  return {T: {X: X3, Y: Y3, Z: Z3}, l: [F2.sub(B, E), F2.neg(F2.mul(f2(3n, 0n), F2.sqr(X))), H]};
};
const projAdd = ({X, Y, Z}, q) => {
  const th = F2.sub(Y, F2.mul(q.y, Z)), la = F2.sub(X, F2.mul(q.x, Z)); const C = F2.sqr(th), D = F2.sqr(la), E = F2.mul(la, D), F = F2.mul(Z, C), G = F2.mul(X, D);
  const H = F2.sub(F2.add(E, F), F2.add(G, G));
  return {T: {X: F2.mul(la, H), Y: F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), Z: F2.mul(Z, E)}, l: [F2.sub(F2.mul(th, q.x), F2.mul(la, q.y)), F2.neg(th), la]};
};
const toAff = ({X, Y, Z}) => ({x: F2.div(X, Z), y: F2.div(Y, Z)});

// per-event factor lists: returns, for each event e, {lines: [poly...], addC: bool}; plus B endpoint and witness slopes
export function walkB(P0, Bpt, eaff) {
  const Pa = P0.toAffine(), Ba = Bpt.toAffine(); const ev = []; const slopes = [];
  let aff = {x: Ba.x, y: Ba.y}, proj = null;
  for (let e = 0; e < NE; e++) {
    const L = [];
    if (e < eaff) {
      const lam = slopeDbl(aff); assert.ok(F2.eql(F2.mul(F2.add(aff.y, aff.y), lam), F2.mul(f2(3n, 0n), F2.sqr(aff.x))), 'slope eq');
      slopes.push(lam); L.push(lineAffPoly(Pa.x, Pa.y, lam, F2.sub(F2.mul(lam, aff.x), aff.y)));
      const x3 = F2.sub(F2.sqr(lam), F2.add(aff.x, aff.x)); aff = {x: x3, y: F2.sub(F2.mul(lam, F2.sub(aff.x, x3)), aff.y)};
      if (BITS[e]) { assert.ok(!F2.eql(aff.x, Ba.x), 'x != xB at an addition'); const l2 = slopeAdd(aff, Ba); slopes.push(l2);
        L.push(lineAffPoly(Pa.x, Pa.y, l2, F2.sub(F2.mul(l2, aff.x), aff.y))); const x3b = F2.sub(F2.sub(F2.sqr(l2), aff.x), Ba.x); aff = {x: x3b, y: F2.sub(F2.mul(l2, F2.sub(aff.x, x3b)), aff.y)}; }
    } else {
      if (!proj) proj = {X: aff.x, Y: aff.y, Z: F2.ONE};
      const d = projDbl(proj); proj = d.T; L.push(lineGenPoly(Pa.x, Pa.y, ...d.l));
      if (BITS[e]) { const a = projAdd(proj, Ba); proj = a.T; L.push(lineGenPoly(Pa.x, Pa.y, ...a.l)); }
    }
    ev.push(L);
  }
  const end = proj ? (F2.is0(proj.Z) ? null : toAff(proj)) : aff;
  return {ev, slopes, end};
}
// delta walk (fixed): baked slopes, affine lines at P1 = C
export function walkDelta(P1, delta) {
  const Pa = P1.toAffine(); const da = delta.toAffine(); let T = {x: da.x, y: da.y}; const ev = []; const lams = [];
  for (let e = 0; e < NE; e++) {
    const L = []; const lam = slopeDbl(T); lams.push(lam); L.push(lineAffPoly(Pa.x, Pa.y, lam, F2.sub(F2.mul(lam, T.x), T.y)));
    const x3 = F2.sub(F2.sqr(lam), F2.add(T.x, T.x)); T = {x: x3, y: F2.sub(F2.mul(lam, F2.sub(T.x, x3)), T.y)};
    if (BITS[e]) { const l2 = slopeAdd(T, da); lams.push(l2); L.push(lineAffPoly(Pa.x, Pa.y, l2, F2.sub(F2.mul(l2, T.x), T.y))); const x3b = F2.sub(F2.sub(F2.sqr(l2), T.x), da.x); T = {x: x3b, y: F2.sub(F2.mul(l2, F2.sub(T.x, x3b)), T.y)}; }
    ev.push(L);
  }
  return {ev, lams, end: T};
}

// ---------------- VK constants ----------------
export const VKC = (() => {
  const mIC = VK.ic.map((P) => miller(P, VK.gamma));
  const R = [1, 2].map((k) => [monicRep(mIC[k]), monicRep(F12.frobeniusMap(mIC[k], 1))]);
  // factor (k, i) is a representative of Frob^i(m_k)^((-1)^i)
  R.forEach((Rk, k) => [0, 1, 2, 3].forEach((i) => { let t = F12.frobeniusMap(mIC[k + 1], i); if (i % 2) t = F12.conjugate(t); assert.ok(sameClass(fromPoly(glsFactorPoly(Rk, i)), t), 'GLS factor ' + k + i); }));
  const Rconst = monicRep(F12.mul(miller(VK.alpha, VK.beta), mIC[0]));
  return {mIC, R, Rconst};
})();

// ---------------- prover ----------------
export function prove(fix, {eaff = 0, layout = LAYOUTS.a2, seed = 'rho'} = {}) {
  const {inputs, proof} = fix; const P0 = proof.a.negate(), P1 = proof.c;
  const Bw = walkB(P0, proof.b, eaff), Dw = walkDelta(P1, VK.delta);
  // B endpoint: [|x|]B == -psi(B)
  { const Ba = proof.b.toAffine(); const [px, py] = psiAff(Ba.x, Ba.y); assert.ok(Bw.end && F2.eql(Bw.end.x, px) && F2.eql(Bw.end.y, F2.neg(py)), 'endpoint [|x|]B = -psi(B)'); }
  // GLS digits and nibble strings: byte j = bit (63 - j) of a_{k,0..3}; byte 0 at init, byte e+1 at event e
  const digits = inputs.map(glsDigits);
  const nib = digits.map((a) => Array.from({length: 64}, (_, j) => a.reduce((s, ai, i) => s | (Number((ai >> BigInt(63 - j)) & 1n) << i), 0)));
  const G = (k, n) => { let g = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) g = pmul(g, glsFactorPoly(VKC.R[k], i)); return g; };
  const Gpair = (j) => pmul(G(0, nib[0][j]), G(1, nib[1][j]));
  // event factor polynomial (without the c multiplier)
  const evFac = (e) => { let f = [1n]; for (const l of [...Bw.ev[e], ...Dw.ev[e]]) f = pmul(f, l); return pmul(f, Gpair(e + 1)); };
  // f' (no c): F_loop = G_init, then per event square and multiply; times Rconst
  let fl = fromPoly(Gpair(0)); for (let e = 0; e < NE; e++) fl = F12.mul(F12.sqr(fl), fromPoly(evFac(e)));
  const fprime = F12.mul(fl, fromPoly(VKC.Rconst));
  assert.ok(F12.eql(FE(fprime), F12.ONE), 'Groth16 equation (FE(f\') = 1)');
  // residue root: [f'] = [c]^lambda; u = f'^(p^6 - 1) has order | N6R; t = u^(lambda^-1 mod N6R); c = 1 + conj(t)
  const u = F12.div(F12.conjugate(fprime), fprime); // f'^(p^6-1)
  const t = F12.pow(u, Fr.ORDER && (() => { const egcd = (a, m) => { let [o, nn] = [a % m, m], [x0, x1] = [1n, 0n]; while (nn) { const q = o / nn; [o, nn] = [nn, o - q * nn]; [x0, x1] = [x1, x0 - q * x1]; } return mod(x0, m); }; return egcd(LAMBDA % N6R, N6R); })());
  const c = F12.add(F12.ONE, F12.conjugate(t));
  assert.ok(sameClass(F12.pow(c, LAMBDA), fprime), '[c]^lambda = [f\']');
  const Sc = monicRep(c); const ScNeg = pneg(Sc); const W = frob1Monic(Sc.slice(0, 6));
  // chain with states
  const K = layout.length; assert.equal(layout.reduce((a, b) => a + b, 0), NE);
  const evC = (e) => (BITS[e] ? pmul(evFac(e), ScNeg) : evFac(e));
  let start = pmul(ScNeg, Gpair(0)); // S_0 (not monic: c^-1 times the bit-63 GLS factors)
  const states = [], Qs = [], degP = [], degD = []; let e = 0;
  for (let k = 0; k < K; k++) {
    let P = start; for (let j = 0; j < layout[k]; j++, e++) P = pmul(pmul(P, P), evC(e));
    const last = k === K - 1; if (last) P = pmul(P, VKC.Rconst);
    const Snext = last ? W : monicRep(fromPoly(P));
    const D = psub(pmul(P, pneg(Snext)), pmul(pneg(P), Snext));
    const {q, r: rem} = pdivM(D); assert.ok(isZero(rem), `identity ${k} divisible by M`);
    degP.push(deg(P)); degD.push(deg(D)); Qs.push(q);
    if (!last) { states.push(Snext); start = Snext; }
  }
  // aggregate (rho from a hash; the script derives it from h0)
  const rho = BigInt('0x' + createHash('sha256').update(seed).digest('hex'));
  let Q = [0n]; for (let k = 0; k < K; k++) Q = padd(pmul(Q, [rho]), Qs[k]);
  Q = trim(Q); assert.ok(Q.every((x, i) => i % 2 === 1 || x === 0n), 'Q is odd');
  const nq = (Q.length) / 2; // odd coefficients q_1, q_3, ..., q_{2nq-1}
  // value-level check at a random z: sum rho^(K-1-k) D_k(z) == Q(z) M(z), via the +-z chains
  const z = BigInt('0x' + createHash('sha256').update(seed + 'z').digest('hex'));
  let R = 0n; e = 0; start = pmul(ScNeg, Gpair(0)); let Fp_ = peval(start, z), Fm_ = peval(start, mod(-z));
  for (let k = 0; k < K; k++) {
    for (let j = 0; j < layout[k]; j++, e++) { const f = evC(e); Fp_ = mod(Fp_ * Fp_ * peval(f, z)); Fm_ = mod(Fm_ * Fm_ * peval(f, mod(-z))); }
    const last = k === K - 1; if (last) { Fp_ = mod(Fp_ * peval(VKC.Rconst, z)); Fm_ = mod(Fm_ * peval(VKC.Rconst, mod(-z))); }
    const S = last ? W : states[k]; R = mod(R * rho + Fp_ * peval(S, mod(-z)) - Fm_ * peval(S, z));
    if (!last) { Fp_ = peval(S, z); Fm_ = peval(S, mod(-z)); }
  }
  assert.equal(R, mod(peval(Q, z) * peval(M, z)), 'batched identity at z');
  return {nq, K, states: states.length, degP, degD, maxDegD: Math.max(...degD), slopes: Bw.slopes.length, nib, digits, deltaLines: Dw.lams.length};
}

// ---------------- worst-case degree bound for a layout (every GLS bit set) ----------------
export function worstBound(layout, eaff) {
  const lB = (e) => (e < eaff ? 8 : 9);
  const f = (e, bits) => lB(e) + 8 + (BITS[e] ? lB(e) + 8 + 6 : 0) + 6 * bits;
  let e = 0, worst = 0; const per = [];
  layout.forEach((len, k) => {
    let d = k === 0 ? 6 + 48 : 6; for (let j = 0; j < len; j++, e++) d = 2 * d + f(e, 8);
    if (k === layout.length - 1) d += 6; const dD = d + (k === layout.length - 1 ? 11 : 6);
    per.push(dD); worst = Math.max(worst, dD);
  });
  const odd = worst % 2 ? worst : worst - 1; // D is odd
  return {maxDegD: odd, nqMax: (odd - 11) / 2, per};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const eaff = Number(arg('eaff', '0')), lname = arg('layout', 'a2'), layout = LAYOUTS[lname];
  const fixes = arg('fix', 'all') === 'all' ? Object.keys(FIXTURES) : [arg('fix')];
  const wb = worstBound(layout, eaff);
  console.log(`layout ${lname}: ${layout.length} chunks, ${layout.length - 1} states; eaff ${eaff}; worst deg D ${wb.maxDegD} -> NQ_MAX ${wb.nqMax}`);
  const out = {layout: lname, eaff, worst: wb, fixtures: {}};
  for (const name of fixes) {
    const t0 = Date.now(); const res = prove(FIXTURES[name], {eaff, layout});
    console.log(`${name.padEnd(13)} nq ${res.nq}  maxDegD ${res.maxDegD}  states ${res.states}  B slopes ${res.slopes}  delta lines ${res.deltaLines}  (${Date.now() - t0} ms)`);
    out.fixtures[name] = {nq: res.nq, maxDegD: res.maxDegD, degD: res.degD};
  }
  if (flag('json')) writeFileSync(new URL(`./proto-${lname}-eaff${eaff}.json`, import.meta.url), JSON.stringify(out, null, 1));
}
