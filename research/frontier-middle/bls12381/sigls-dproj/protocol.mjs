// BLS12-381 SI-GLS protocol: witness layout, transcript, the honest prover (exact polynomial identities,
// divisibility asserted) and a value-level reference verifier that mirrors the script step by step (used to
// test the protocol and to debug the script). See README.md for the protocol and the soundness argument.
//
// Schedule: T = |x| = 0xd201000000010000, binary, 63 events e = 0..62 (bit 62 - e), additions at events
// 0, 2, 5, 14, 46. The loop's initial value carries the top bit of T (c^-1), Rconst' and GLS nibble 0; event e
// squares, adds the B and delta doubling lines, [the B and delta addition lines and c^-1], and GLS nibble e + 1.
// Events 0..E_A-1 walk B affinely with witnessed slopes (each fixed by an exact equation), events E_A..62
// projectively from (x : y : 1).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {p, r, mod, F2, F12, Fr, f2, AX, AXPOW, BITS, NE, ADD_EVENTS, LAMBDA, N6R, B_TWIST, B3, GAMMA2, GAMMA3, conj2, VKC, VK, VK_ENCODING,
  glsFactor, glsDigits, lineAffPoly, lineGenPoly, frob1Monic, fromPoly, monicRep, pmul, psub, pneg, peval, pdivM, isZero, trim, M} from './math.mjs';

export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
// ---------------- fixed layout ----------------
export const E_A = Number(process.env.SIGLS_EA ?? 0);     // affine B events: 0 in this research variant (the whole B walk is projective from (x : y : 1))
assert.ok(E_A >= 0 && E_A <= NE);
export const TAG = Buffer.concat([Buffer.from('SIGLS-BLS/P'), sha(VK_ENCODING)]); // 43 B, fixed width
assert.equal(TAG.length, 43);
// chunks: [0] [1,2] [3] [4,5] [6] [7,8] ... [61,62]: every addition (0, 2, 5, 14, 46) is a chunk's only or second event
export const LAYOUT = [1, 2, 1, 2, 1, ...Array.from({length: 28}, () => 2)];
assert.equal(LAYOUT.reduce((a, b) => a + b, 0), NE);
export const CHUNK_END = LAYOUT.map((_, k) => LAYOUT.slice(0, k + 1).reduce((a, b) => a + b, 0) - 1); // last event of chunk k
export const BOUNDS = CHUNK_END.slice(0, -1);              // a state is committed after these events (32); the last chunk closes against W
export const NSTATES = BOUNDS.length, K_IDS = NSTATES + 1;
assert.equal(NSTATES, 32);
export const isBoundary = (e) => BOUNDS.includes(e);
export const isAdd = (e) => BITS[e] === 1;
export const NSLOPES = E_A + ADD_EVENTS.filter((e) => e < E_A).length; // 13 at E_A = 10
export const W = 48;                                        // field word (LE)
export const WS_LAYOUT = {stmt: 0, n0: 384, n1: 416, N0: 448, N1: 512, sc: 576, states: 864, slopes: 864 + 288 * NSTATES};
export const WS_SIZE = WS_LAYOUT.slopes + 96 * NSLOPES;      // 11,328 at E_A = 10
// ---------------- degree bookkeeping (structural, adversarial: up to 8 GLS bits per event) ----------------
// B line: affine 8, projective 9; delta line 9 (projective, dproj); c factor 6; GLS factor 6 per set bit. Start: c^-1 (6), Rconst' (6), GLS nibble 0.
export const lineDegB = (e) => (e < E_A ? 8 : 9);
export const LINE_DEG_D = 9;
export const eventDeg = (e, bits) => lineDegB(e) + LINE_DEG_D + (isAdd(e) ? lineDegB(e) + LINE_DEG_D + 6 : 0) + 6 * bits;
export const chunkDegP = (k, bitsOf) => { let d = k === 0 ? 12 + 6 * bitsOf(-1) : 6; for (let e = k ? CHUNK_END[k - 1] + 1 : 0; e <= CHUNK_END[k]; e++) d = 2 * d + eventDeg(e, bitsOf(e)); return d; };
const nqOfDegD = (dD) => { const odd = dD % 2 ? dD : dD - 1; return (odd - 12 + 1) / 2; };
export const degDBound = (k, bitsOf) => chunkDegP(k, bitsOf) + (k === K_IDS - 1 ? 11 : 6);
export const nqFor = (bitsOf) => Math.max(...Array.from({length: K_IDS}, (_, k) => nqOfDegD(degDBound(k, bitsOf))));
export const NQ_MAX = nqFor(() => 8);
assert.equal(NQ_MAX, E_A === 0 ? 120 : NQ_MAX); // re-derived for the projective delta lines (deg 9): worst chunk 2(12 + 66) + 90 = 246, deg D 252 -> 251, (251 - 11) / 2 = 120

// ---------------- encodings ----------------
export const leN = (x, n) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n), 'leN range'); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const W48 = (x) => leN(mod(x), 48);
export const rdle = (b, o = 0, n = 48) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = v * 256n + BigInt(b[o + i]); return v; };
export const toCh = (h) => rdle(h, 0, 32);                // BIN2NUM(h || 0x00): unsigned, < 2^256 < p, no reduction

// ---------------- on-chain B formulas (homogeneous projective over Fp2, a = 0) ----------------
// doubling: B = Y^2, C = Z^2, E = 3b'C, F = 3E, H = 2YZ; X3 = 2XY(B - F), Y3 = (B + F)^2 - 12E^2, Z3 = 4BH = 8Y^3 Z;
// line (B - E, -3X^2, H) = 2YZ * (affine tangent line). Z = 0 is absorbing.
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  const X3 = F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv));
  const Y3 = F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n)));
  return {T: [X3, Y3, F2.mul(F2.mul(B, H), f2(4n, 0n))], line: [F2.sub(B, E), F2.neg(F2.mul(F2.sqr(X), f2(3n, 0n))), H]};
};
// mixed addition with affine Q: th = Y - yq Z, la = X - xq Z, D = la^2, E = la D, F = Z th^2, G = X D, H = E + F - 2G;
// X3 = la H, Y3 = th (G - H) - Y E, Z3 = Z E = Z la^3; line (th xq - la yq, -th, la) = la * (affine chord line).
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = F2.sub(Y, F2.mul(yq, Z)), la = F2.sub(X, F2.mul(xq, Z));
  const D = F2.sqr(la), E = F2.mul(la, D), Fv = F2.mul(Z, F2.sqr(th)), G = F2.mul(X, D), H = F2.sub(F2.add(E, Fv), F2.add(G, G));
  return {T: [F2.mul(la, H), F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), F2.mul(Z, E)], line: [F2.sub(F2.mul(th, xq), F2.mul(la, yq)), F2.neg(th), la]};
};
const three = f2(3n, 0n);

// ---------------- delta walk, projective on-chain (dproj) ----------------
// The script walks delta from (x_d : y_d : 1) with the same homogeneous kernels as B (P = C). The 68 lines are
// deterministic; at load time they are asserted against noble: the walk point equals noble's [k]delta, Z != 0 and
// l3 != 0 at every step, and each projective line is l3 * (c_j, -lambda_j, 1), the baked affine line of the reviewed
// design (lambda_j = VKC.lams[j], asserted there against noble's millerTrace), so the classes are unchanged.
export const DPROJ = (() => {
  const d = VKC.deltaAff; let T = [d.x, d.y, F2.ONE], Tn = VK.delta; const lines = [], points = [], kinds = []; let j = 0;
  const check = (line, Ta) => { const [l0, l2, l3] = line; assert.ok(!F2.is0(l3), 'delta l3 != 0 at step ' + j);
    const lam = VKC.lams[j], c = F2.sub(F2.mul(lam, Ta.x), Ta.y);
    assert.ok(F2.eql(l0, F2.mul(l3, c)) && F2.eql(l2, F2.neg(F2.mul(l3, lam))), 'delta projective line = l3 * affine line, step ' + j); lines.push(line); j++; };
  const same = (T, P) => { const a = P.toAffine(); assert.ok(!F2.is0(T[2]), 'delta Z != 0'); const zi = F2.inv(T[2]); return F2.eql(F2.mul(T[0], zi), a.x) && F2.eql(F2.mul(T[1], zi), a.y); };
  for (let e = 0; e < NE; e++) {
    assert.ok(same(T, Tn)); { points.push(T); kinds.push('dbl'); const r1 = projDbl(T); check(r1.line, Tn.toAffine()); T = r1.T; Tn = Tn.double(); assert.ok(same(T, Tn), 'delta walk = noble after dbl ' + e); }
    if (BITS[e]) { points.push(T); kinds.push('add'); const r2 = projAdd(T, [d.x, d.y]); check(r2.line, Tn.toAffine()); T = r2.T; Tn = Tn.add(VK.delta); assert.ok(same(T, Tn), 'delta walk = noble after add ' + e); }
  }
  assert.equal(j, 68); assert.ok(Tn.equals(VK.delta.multiply(AX)));
  // points[j] is the projective walk point before step j (kinds[j] = dbl | add); end is the point after the last step
  return {lines, points, kinds, end: T};
})();

// ---------------- the schedule as polynomials (shared by prover and reference verifier) ----------------
// st: {xA, yA, xB, yB, xC, yC, N}; N[k][j] (j = 0..63) = nibble j: bit i = bit (63 - j) of digit a_{k,i}.
// slopes: the witnessed affine slopes (verifier) or null (prover: computed). Returns per-event factor lists
// (without c), the start factors, the slopes used, and the endpoint verdict; fail(why) on a violated exact check.
export function factorSchedule(st, slopes = null, {eaff = E_A, lenient = false} = {}) {
  const {xA, yA, xB, yB, xC, yC, N} = st;
  const xP = xA, yP = mod(-yA);                           // P0 = -A
  const out = {events: [], slopes: [], ok: true};
  const fail = (why) => (lenient ? null : {ok: false, why}); // lenient (forge mode only): keep going past a violated check
  const div = (a, b) => (F2.is0(b) ? F2.ZERO : F2.div(a, b));
  const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactor(k, i)); return poly; };
  const gls = (j) => pmul(tbl(0, N[0][j]), tbl(1, N[1][j]));
  // delta (fixed): the projective walk (P = C), its deterministic lines asserted in DPROJ
  let j = 0; const lam = DPROJ.lines;
  const dstep = () => { const line = lineGenPoly(xC, yC, ...lam[j]); j++; return line; };
  let aff = {x: xB, y: yB}, proj = null, si = 0;
  const nextSlope = (honest) => { if (slopes === null) { out.slopes.push(honest()); return out.slopes.at(-1); } const l = slopes[si++]; out.slopes.push(l); return l; };
  for (let e = 0; e < NE; e++) {
    const fs = [];
    if (e < eaff) {
      const l = nextSlope(() => div(F2.mul(three, F2.sqr(aff.x)), F2.add(aff.y, aff.y)));
      if (!F2.is0(F2.sub(F2.mul(F2.add(aff.y, aff.y), l), F2.mul(three, F2.sqr(aff.x)))) && fail()) return fail('affine doubling slope');
      fs.push(lineAffPoly(xP, yP, l, F2.sub(F2.mul(l, aff.x), aff.y)));
      const x3 = F2.sub(F2.sqr(l), F2.add(aff.x, aff.x)); aff = {x: x3, y: F2.sub(F2.mul(l, F2.sub(aff.x, x3)), aff.y)};
    } else {
      if (!proj) proj = [aff.x, aff.y, F2.ONE];
      const d = projDbl(proj); proj = d.T; fs.push(lineGenPoly(xP, yP, ...d.line));
    }
    fs.push(dstep());
    if (isAdd(e)) {
      if (e < eaff) {
        if (F2.eql(aff.x, xB) && fail()) return fail('affine addition x = xB');
        const l = nextSlope(() => div(F2.sub(yB, aff.y), F2.sub(xB, aff.x)));
        if (!F2.is0(F2.sub(F2.mul(l, F2.sub(xB, aff.x)), F2.sub(yB, aff.y))) && fail()) return fail('affine addition slope');
        fs.push(lineAffPoly(xP, yP, l, F2.sub(F2.mul(l, aff.x), aff.y)));
        const x3 = F2.sub(F2.sub(F2.sqr(l), aff.x), xB); aff = {x: x3, y: F2.sub(F2.mul(l, F2.sub(aff.x, x3)), aff.y)};
      } else { const a = projAdd(proj, [xB, yB]); proj = a.T; fs.push(lineGenPoly(xP, yP, ...a.line)); }
      fs.push(dstep());
    }
    fs.push(gls(e + 1));
    out.events.push({fs, c: isAdd(e)});
  }
  assert.equal(j, lam.length);
  if (slopes !== null && si !== slopes.length && fail()) return fail('slope count');
  out.start = [VKC.Rconst, gls(0)];
  // endpoint [T]B = -psi(B): X gamma1^2 = conj(xB) Z, Y gamma1^3 = -conj(yB) Z, Z != 0 (all-affine: Z = 1)
  const [X, Y, Z] = proj ?? [aff.x, aff.y, F2.ONE];
  out.endpoint = !F2.is0(Z) && F2.eql(F2.mul(X, GAMMA2), F2.mul(conj2(xB), Z)) && F2.eql(F2.mul(Y, GAMMA3), F2.neg(F2.mul(conj2(yB), Z)));
  return out;
}

// ---------------- prover ----------------
// digits: override of the base-|x| digits (any a_{k,i} < 2^64 with sum_i a_{k,i} T^i = n_k is valid).
// forge (red-team / rejection tests only): skip the Groth16, endpoint and divisibility assertions and use floor
// quotients, to build the most consistent witness for an INVALID input so that a specific script guard is exercised.
export function prove(fx, {digits = null, forge = false, eaff = E_A, slopeOverride = null} = {}) {
  const {inputs, proof} = fx; const A = proof.a, B = proof.b, C = proof.c;
  if (!forge) { A.assertValidity(); B.assertValidity(); C.assertValidity(); }
  assert.ok(!A.is0() && !B.is0() && !C.is0(), 'the encoding has no point at infinity');
  const ns = inputs.map(BigInt); if (!forge) ns.forEach((n) => assert.ok(n >= 0n && n < r));
  const dg = digits ?? ns.map((n) => glsDigits(n));
  dg.forEach((a, k) => { a.forEach((v) => assert.ok(v >= 0n && v < 1n << 64n, 'digit range')); if (!forge) assert.equal(a.reduce((s, v, i) => s + v * AXPOW[i], 0n), ns[k], 'digits bind n'); });
  const N = dg.map((a) => Array.from({length: 64}, (_, j) => a.reduce((s, ai, i) => s | (Number((ai >> BigInt(63 - j)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st, slopeOverride, {eaff, lenient: forge});
  assert.ok(sched.ok, 'schedule: ' + sched.why);
  if (!forge) assert.ok(sched.endpoint, 'B endpoint');
  // f' (no c): the full Miller product with Rconst' and the GLS factors; FE(f') = 1 for a valid proof
  let fprime = F12.ONE; for (const f of sched.start) fprime = F12.mul(fprime, fromPoly(f));
  for (const ev of sched.events) { fprime = F12.sqr(fprime); for (const f of ev.fs) fprime = F12.mul(fprime, fromPoly(f)); }
  if (!forge) assert.ok(F12.eql(F12.finalExponentiate(fprime), F12.ONE), 'Groth16 equation fails (FE(f\') != 1)');
  // residue root: [c]^lambda = [f'];  u = f'^(p^6-1) (order | N6R), t = u^(lambda^-1 mod N6R), c = 1 + conj(t)
  const minv = (a, m) => { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); };
  // forge only: a degenerate B walk (a projective addition at T = B, e.g. a small-order B) makes a line, and so f', zero
  // (Z = 0 is absorbing and every later B line is 0); f' has no residue root then, so commit S_c = X^6 (the trivial class)
  const degenerate = forge && F12.is0(fprime);
  const u = degenerate ? F12.ONE : F12.mul(F12.conjugate(fprime), F12.inv(fprime)), t = F12.pow(u, minv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(t));
  const Sc = degenerate ? [0n, 0n, 0n, 0n, 0n, 0n, 1n] : monicRep(c); const ScNeg = pneg(Sc);       // [S_c(-X)] = [c^-1]
  // chain: start = c^-1 * Rconst' * GLS_0; per chunk P = start^(2^len) * prod(events), states at boundaries, W = Frob(S_c) at the end
  let start = pmul(pmul(ScNeg, sched.start[0]), sched.start[1]);
  const evPoly = (e) => { let f = [1n]; for (const x of sched.events[e].fs) f = pmul(f, x); return sched.events[e].c ? pmul(f, ScNeg) : f; };
  const Wp = frob1Monic(Sc.slice(0, 6));
  const states = [], ids = []; let e = 0;
  for (let k = 0; k < K_IDS; k++) {
    let P = start; for (; e <= CHUNK_END[k]; e++) P = pmul(pmul(P, P), evPoly(e));
    // forge only: P = 0 mod M (degenerate walk) has no monic representative; commit X^6 (every chunk identity then holds
    // as 0 = 0, so only the endpoint guard Z_T != 0 can reject: the redteam's projective-degeneracy run)
    const last = k === K_IDS - 1; const S = last ? Wp : (forge && isZero(pdivM(P).r) ? [0n, 0n, 0n, 0n, 0n, 0n, 1n] : monicRep(fromPoly(P)));
    const D = psub(pmul(P, pneg(S)), pmul(pneg(P), S)); const {q, r: rem} = pdivM(D);
    if (!forge) { assert.ok(isZero(rem), `identity ${k} not divisible by M`); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd'); }
    ids.push({P, S, D, Q: q}); if (!last) { states.push(S); start = S; }
  }
  // transcript part 1
  const stmt = Buffer.concat([Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y].map(W48));
  const nsb = ns.map((n) => leN(mod(n, 1n << 256n), 32));
  const WS = Buffer.concat([stmt, ...nsb, Buffer.from(N[0]), Buffer.from(N[1]), ...Sc.slice(0, 6).map(W48), ...states.flatMap((s) => s.slice(0, 6).map(W48)),
    ...sched.slopes.flatMap((l) => [W48(l.c0), W48(l.c1)])]);
  assert.equal(WS.length, WS_LAYOUT.slopes + 96 * (eaff === E_A ? NSLOPES : sched.slopes.length));
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')), rho = toCh(rhoRaw);
  // aggregated quotient Q = sum_k rho^(K-1-k) Q_k (odd), trimmed: the leading odd word nonzero
  const Qagg = []; ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(K_IDS - 1 - k)); id.Q.forEach((x, i) => { Qagg[i] = mod((Qagg[i] ?? 0n) + wgt * x); }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1); while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  if (!forge) { assert.ok(qOdd.at(-1) !== 0n); assert.ok(qOdd.length <= nqFor((ev) => [0, 1].reduce((s, k) => s + popc(N[k][ev + 1]), 0)), 'n_q within the structural bound'); assert.ok(qOdd.length <= NQ_MAX); }
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W48)); // highest coefficient first
  return {WS, WQ, nq: qOdd.length, ns, digits: dg, N, Sc, states, c, debug: {sched, ids, rho, h0}};
}
const popc = (n) => [0, 1, 2, 3].filter((i) => (n >> i) & 1).length;

// ---------------- value-level reference verifier (mirrors the script) ----------------
export function verifyValues(WS, WQ, {eaff = E_A} = {}) {
  const fail = (why) => ({ok: false, why});
  const nsl = eaff + ADD_EVENTS.filter((e) => e < eaff).length;
  if (WS.length !== WS_LAYOUT.slopes + 96 * nsl) return fail('WS size');
  if (WQ.length % 48 || WQ.length === 0 || WQ.length > 48 * NQ_MAX) return fail('WQ size');
  const word = (o) => { const v = rdle(WS, o); return v < p ? v : null; };
  const words = (o, n) => Array.from({length: n}, (_, i) => word(o + 48 * i));
  const qw = Array.from({length: WQ.length / 48}, (_, i) => rdle(WQ, 48 * i));
  if (qw[0] === 0n) return fail('Q leading word zero');
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')), rho = toCh(rhoRaw), z = toCh(sha(h0, rhoRaw, WQ));
  if (z === 0n) return fail('z = 0');
  const st = words(0, 8); if (st.some((v) => v === null)) return fail('coordinate not canonical');
  const ns = [rdle(WS, 384, 32), rdle(WS, 416, 32)]; if (ns.some((v) => v >= r)) return fail('public input not canonical');
  const nibs = [0, 1].map((k) => [...WS.subarray(448 + 64 * k, 512 + 64 * k)]); if (nibs.flat().some((b) => b > 15)) return fail('nibble range');
  const sc = words(576, 6), stts = Array.from({length: NSTATES}, (_, k) => words(864 + 288 * k, 6));
  if ([...sc, ...stts.flat()].some((v) => v === null)) return fail('state word not canonical');
  const slw = words(WS_LAYOUT.slopes, 2 * nsl); if (slw.some((v) => v === null)) return fail('slope not canonical');
  if (qw.some((v) => v >= p)) return fail('Q word not canonical');
  const [xA, yA, xB0, xB1, yB0, yB1, xC, yC] = st; const xB = f2(xB0, xB1), yB = f2(yB0, yB1);
  if (mod(yA * yA - xA ** 3n - 4n) !== 0n || mod(yC * yC - xC ** 3n - 4n) !== 0n) return fail('G1 curve');
  if (!F2.eql(F2.sqr(yB), F2.add(F2.mul(F2.sqr(xB), xB), B_TWIST))) return fail('twist curve');
  const slopes = Array.from({length: nsl}, (_, i) => f2(slw[2 * i], slw[2 * i + 1]));
  const sched = factorSchedule({xA, yA, xB, yB, xC, yC, N: nibs}, slopes, {eaff});
  if (!sched.ok) return fail(sched.why);
  const mono = (s) => [...s, 1n]; const scP = mono(sc), zm = mod(-z);
  const ev2 = (f, F) => [mod(F[0] * peval(f, z)), mod(F[1] * peval(f, zm))];
  let F = [peval(pneg(scP), z), peval(pneg(scP), zm)]; for (const f of sched.start) F = ev2(f, F);
  let R = 0n, k = 0;
  sched.events.forEach((ev, e) => {
    F = [mod(F[0] * F[0]), mod(F[1] * F[1])]; for (const f of ev.fs) F = ev2(f, F); if (ev.c) F = ev2(pneg(scP), F);
    if (isBoundary(e)) { const S = mono(stts[k]); const Sp = peval(S, z), Sm = peval(S, zm); R = mod(R * rho + F[0] * Sm - F[1] * Sp); F = [Sp, Sm]; k++; }
  });
  const Wp = frob1Monic(sc); R = mod(R * rho + F[0] * peval(Wp, zm) - F[1] * peval(Wp, z));
  if (!sched.endpoint) return fail('B endpoint');
  for (const kk of [0, 1]) { let acc = 0n; for (let j = 0; j < 64; j++) { acc = 2n * acc; for (let i = 0; i < 4; i++) if ((nibs[kk][j] >> i) & 1) acc += AXPOW[i]; } if (acc !== ns[kk]) return fail('GLS binding ' + kk); }
  let acc = 0n; const z2 = mod(z * z); for (const q of qw) acc = mod(acc * z2 + q);
  return mod(R - z * acc * peval(M, z)) === 0n ? {ok: true, z, rho, R} : fail('final identity');
}
