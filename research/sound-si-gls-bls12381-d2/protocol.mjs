// BLS12-381 SI-GLS protocol reference: chunking, degree bounds, witness layout, transcript, the honest
// prover (exact polynomial identities, divisibility asserted), and a value-level reference verifier that
// evaluates everything at +-z exactly as the script would.
//
// Schedule: T = |x| = 0xd201000000010000. The initial step ("event -1") handles the top bit of T and
// bit 63 of the GLS digits (no squaring); events e = 0..62 handle bit 62 - e (square, B doubling,
// delta doubling, [B addition, delta addition, c^-1], GLS nibble). Additions at events 0, 2, 5, 14, 46.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {p, r, mod, F2, F12, f2, T, BITS, NE, NADD, LAMBDA, N6R, TPOW, glsDigits, glsFactorPoly, VKC, B_TWIST, psiAff, ETA,
  frob1Monic, linePoly, projDbl, projAdd, fromPoly, monicRep, pmul, psub, pneg, peval, pdivM, pdeg, M, modInv} from './math.mjs';

// ---------------- chunking ----------------
// BOUNDS: events after which a state is committed; the last chunk (ending at event 62) is closed by the
// terminal identity against W = Frob(S_c) instead of a committed state. Default: pairs, with the addition
// events placed second in their chunk where possible (chosen by search.mjs).
export const DEFAULT_BOUNDS = (process.env.BOUNDS ?? '').length ? process.env.BOUNDS.split(',').map(Number) : null;
export function layoutFor(BOUNDS) {
  assert.ok(BOUNDS.every((b, i) => b >= -1 && b < NE - 1 && (i === 0 || b > BOUNDS[i - 1])));
  const NSTATES = BOUNDS.length;
  const chunks = []; let a = -1; for (const b of [...BOUNDS, NE - 1]) { chunks.push([a, b]); a = b + 1; } // inclusive event ranges; chunk 0 starts at -1
  const WS = {stmt: 0, n0: 384, n1: 416, N0: 448, N1: 512, sc: 576, states: 864};
  return {BOUNDS, NSTATES, K_IDS: NSTATES + 1, chunks, WS, WS_SIZE: 864 + NSTATES * 288};
}
// per-event factor degree (adversarial: up to 8 GLS bits). B line 9, delta line 8, c 6, GLS 6 per bit
export const eventDeg = (e, bits) => (e < 0 ? 6 : 17 + (BITS[e] ? 23 : 0)) + 6 * bits;
export function chunkDegP(L, k, bitsOf) {
  const [a, b] = L.chunks[k]; let d = a < 0 ? 0 : 6;
  for (let e = a; e <= b; e++) d = (e < 0 ? d : 2 * d) + eventDeg(e, bitsOf(e));
  if (k === L.NSTATES) d += 6; // Rconst
  return d;
}
const nqOfDegD = (dD) => { const dq = (dD % 2 ? dD : dD - 1) - 12; return (dq + 1) / 2; };
// deg D_k <= deg P_k + deg S' (6 for a state, 11 for W = Frob(S_c))
export const nqFor = (L, bitsOf) => Math.max(...L.chunks.map((_, k) => nqOfDegD(chunkDegP(L, k, bitsOf) + (k === L.NSTATES ? 11 : 6))));
export const nqMax = (L) => nqFor(L, () => 8);

// ---------------- encodings ----------------
export const leN = (x, n) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n)); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const W48 = (x) => leN(mod(x), 48);
export const rdle = (b, o = 0, n = 48) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = v * 256n + BigInt(b[o + i]); return v; };
export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
export const toCh = (h) => rdle(h, 0, 32); // unsigned LE (BIN2NUM(h || 0x00)) < 2^256 < p: no reduction
export const TAG = Buffer.from('SIGLS-BLS/1');

// ---------------- the schedule as polynomials ----------------
// st: {xA, yA, xB, yB, xC, yC, N}; N[k][e+1] = nibble of event e (e = -1..62): bit i = bit (62 - e) of d_{k,i}
export function factorSchedule(st) {
  const {xA, yA, xB, yB, xC, yC, N} = st;
  const yP0 = mod(-yA); // P0 = -A
  let Tb = [xB, yB, F2.ONE];
  let dx = VKC.deltaStart.x, dc = VKC.deltaStart.c, j = 0; const lam = VKC.lams; const dAff = VKC.deltaAff;
  const dline = () => linePoly(xC, yC, dc, F2.neg(lam[j]), F2.ONE);
  const dstep = (isAdd) => { const s = isAdd ? dAff.x : dx; const nx = F2.sub(F2.sub(F2.sqr(lam[j]), dx), s); if (j + 1 < lam.length) dc = F2.sub(F2.mul(F2.add(lam[j], lam[j + 1]), nx), dc); dx = nx; j++; };
  const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactorPoly(k, i)); return poly; };
  const events = [{fs: [tbl(0, N[0][0]), tbl(1, N[1][0])], c: true, init: true}]; // event -1: c^-1 (top bit of T) and GLS bit 63
  for (let e = 0; e < NE; e++) {
    const fs = [];
    let o = projDbl(Tb); fs.push(linePoly(xA, yP0, ...o.line)); Tb = o.T;
    fs.push(dline()); dstep(false);
    if (BITS[e]) { o = projAdd(Tb, [xB, yB]); fs.push(linePoly(xA, yP0, ...o.line)); Tb = o.T; fs.push(dline()); dstep(true); }
    fs.push(tbl(0, N[0][e + 1]), tbl(1, N[1][e + 1]));
    events.push({fs, c: !!BITS[e]});
  }
  assert.equal(j, NE + NADD);
  // endpoint: T_B == -psi(B), Z != 0
  const [px, py] = psiAff(xB, yB); const [X, Y, Z] = Tb;
  const endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(px, Z)) && F2.eql(Y, F2.mul(F2.neg(py), Z));
  return {events, endpoint, Tend: Tb}; // events[e + 1] is event e
}

// ---------------- prover ----------------
export function prove(proof, L, {forge = false} = {}) {
  const {A, B, C, ns} = proof;
  if (!forge) { A.assertValidity(); B.assertValidity(); C.assertValidity(); ns.forEach((n) => assert.ok(n >= 0n && n < r)); }
  const ds = ns.map((n) => glsDigits(n));
  const N = ds.map((d) => Array.from({length: 64}, (_, e1) => d.reduce((s, v, i) => s | (Number((v >> BigInt(63 - e1)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st);
  if (!forge) assert.ok(sched.endpoint, 'B endpoint');
  // f' (no c): FE(f') = 1 for a valid proof
  let raw = F12.ONE; sched.events.forEach((ev, i) => { if (i) raw = F12.sqr(raw); for (const f of ev.fs) raw = F12.mul(raw, fromPoly(f)); });
  raw = F12.mul(raw, fromPoly(VKC.Rconst));
  if (!forge) assert.ok(F12.eql(F12.finalExponentiate(raw), F12.ONE), 'Groth16 equation fails (FE(f\') != 1)');
  // residue root: [c]^lambda = [f'], via u = f'^(p^6 - 1) (in the order-(p^6+1) subgroup), c = 1 + conj(u^(lambda^-1 mod (p^6+1)/r))
  const u = F12.mul(F12.conjugate(raw), F12.inv(raw)), v = F12.pow(u, modInv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(v));
  const Sc = monicRep(c); const ScNeg = pneg(Sc);
  // classes along the loop, states at the bounds
  let Fc = F12.ONE; const states = [];
  sched.events.forEach((ev, i) => { const e = i - 1; if (i) Fc = F12.sqr(Fc); for (const f of ev.fs) Fc = F12.mul(Fc, fromPoly(f)); if (ev.c) Fc = F12.mul(Fc, fromPoly(ScNeg)); if (L.BOUNDS.includes(e)) states.push(monicRep(Fc)); });
  assert.equal(states.length, L.NSTATES);
  // identities
  const Fr1 = frob1Monic(Sc); const ids = [];
  for (let k = 0; k <= L.NSTATES; k++) {
    const [a, b] = L.chunks[k]; let P = k ? states[k - 1] : [1n];
    for (let e = a; e <= b; e++) { const ev = sched.events[e + 1]; if (e >= 0) P = pmul(P, P); for (const f of ev.fs) P = pmul(P, f); if (ev.c) P = pmul(P, ScNeg); }
    if (k === L.NSTATES) P = pmul(P, VKC.Rconst);
    const Wn = k < L.NSTATES ? states[k] : Fr1;
    const Nn = pmul(P, pneg(Wn)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D);
    if (!forge) { assert.ok(rem.every((x) => x === 0n), 'identity ' + k + ' not divisible by M'); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd'); }
    ids.push({P, W: Wn, Q: q, degD: pdeg(D)});
  }
  // transcript, part 1
  const stmt = Buffer.concat([...[Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y].map(W48), ...ns.map((n) => leN(n, 32))]);
  const WS = Buffer.concat([stmt, Buffer.from(N[0]), Buffer.from(N[1]), ...Sc.slice(0, 6).map(W48), ...states.flatMap((s) => s.slice(0, 6).map(W48))]);
  assert.equal(WS.length, L.WS_SIZE);
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')), rho = toCh(rhoRaw);
  const bitsOf = (e) => [0, 1].reduce((s, k) => s + [0, 1, 2, 3].filter((i) => (N[k][e + 1] >> i) & 1).length, 0);
  const nq = nqFor(L, bitsOf);
  const Qagg = Array(2 * nq).fill(0n);
  ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(L.K_IDS - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * nq, 'Q exceeds structural bound'); Qagg[i] = mod(Qagg[i] + wgt * x); } }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1);
  while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W48)); // highest coefficient first
  return {WS, WQ, nq: qOdd.length, nqBound: nq, ds, ns, Sc, states, c, debug: {sched, ids, rho, bitsOf}};
}

// ---------------- value-level reference verifier (mirrors the intended script) ----------------
export function verifyValues(WS, WQ, L) {
  const fail = (why) => ({ok: false, why});
  const NQ_MAX = nqMax(L);
  if (WS.length !== L.WS_SIZE) return fail('WS size');
  if (WQ.length % 48 || WQ.length === 0 || WQ.length > 48 * NQ_MAX) return fail('WQ size');
  const word = (o) => { const v = rdle(WS, o); return v < p ? v : null; };
  const st = Array.from({length: 8}, (_, i) => word(48 * i)); if (st.some((v) => v === null)) return fail('coordinate not canonical');
  const ns = [rdle(WS, 384, 32), rdle(WS, 416, 32)]; if (ns.some((v) => v >= r)) return fail('public input not canonical');
  const [xA, yA, xB0, xB1, yB0, yB1, xC, yC] = st; const xB = f2(xB0, xB1), yB = f2(yB0, yB1);
  if (mod(yA * yA - xA ** 3n - 4n) !== 0n || mod(yC * yC - xC ** 3n - 4n) !== 0n) return fail('G1 curve');
  if (!F2.eql(F2.sqr(yB), F2.add(F2.mul(F2.sqr(xB), xB), B_TWIST))) return fail('twist curve');
  const N = [0, 1].map((k) => [...WS.subarray(448 + 64 * k, 512 + 64 * k)]); if (N.flat().some((b) => b > 15)) return fail('nibble range');
  const words = (o, n) => Array.from({length: n}, (_, i) => word(o + 48 * i));
  const sc = words(576, 6), stts = Array.from({length: L.NSTATES}, (_, k) => words(864 + 288 * k, 6));
  if ([...sc, ...stts.flat()].some((v) => v === null)) return fail('state word not canonical');
  const qw = Array.from({length: WQ.length / 48}, (_, i) => rdle(WQ, 48 * i)); if (qw.some((v) => v >= p)) return fail('Q word not canonical');
  if (qw[0] === 0n) return fail('Q leading word zero');
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')), rho = toCh(rhoRaw), z = toCh(sha(h0, rhoRaw, WQ));
  if (z === 0n) return fail('z = 0');
  // GLS binding (exact integers): acc_k = sum_bits 2^(63-e1) TB[N_k[e1]], TB[n] = sum_{i in n} T^i; acc_k == n_k
  for (const k of [0, 1]) { let acc = 0n; for (let e1 = 0; e1 < 64; e1++) { acc = 2n * acc; for (let i = 0; i < 4; i++) if ((N[k][e1] >> i) & 1) acc += TPOW[i]; } if (acc !== ns[k]) return fail('GLS binding ' + k); }
  const sched = factorSchedule({xA, yA, xB, yB, xC, yC, N});
  if (!sched.endpoint) return fail('B endpoint');
  const scP = [...sc, 1n], zm = mod(-z);
  let Fp_ = 1n, Fm_ = 1n, R = 0n, k = 0;
  sched.events.forEach((ev, i) => { const e = i - 1;
    if (i) { Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_); }
    for (const f of ev.fs) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
    if (ev.c) { Fp_ = mod(Fp_ * peval(scP, zm)); Fm_ = mod(Fm_ * peval(scP, z)); }
    if (L.BOUNDS.includes(e)) { const Wn = [...stts[k], 1n]; const Wp = peval(Wn, z), Wm = peval(Wn, zm); R = mod(R * rho + Fp_ * Wm - Fm_ * Wp); Fp_ = Wp; Fm_ = Wm; k++; }
  });
  Fp_ = mod(Fp_ * peval(VKC.Rconst, z)); Fm_ = mod(Fm_ * peval(VKC.Rconst, zm));
  const Fr1 = frob1Monic(sc); R = mod(R * rho + Fp_ * peval(Fr1, zm) - Fm_ * peval(Fr1, z));
  let acc = 0n; const z2 = mod(z * z); for (const q of qw) acc = mod(acc * z2 + q);
  return R === mod(z * acc * peval(M, z)) ? {ok: true, z, rho, R} : fail('final identity');
}
