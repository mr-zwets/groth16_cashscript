// SI pairing check for the KZG product Miller(P*, [1]_2) * Miller(P_right, [x]_2) (fork of
// chunked/bn254/sound-si-gls/protocol.mjs, reviewed): both G2 arguments are fixed, so both chains are SI "delta
// chains" with baked slopes; there is no G2 walk and no GT-GLS fold. One residue root c and one set of 33 states
// serve the 2-pairing product: [f'] = [c]^lambda with f' = Miller(P*, [1]_2) Miller(P_right, [x]_2).
import assert from 'node:assert/strict';
import {p, mod, inv, F2, F12, DIGITS, NE, NADD, LAMBDA, N6R, ETA, chainConsts, linePoly, fromPoly, monicRep, pmul, psub, pneg, psubst, peval, pdivM, M, frob1Monic} from './math.mjs';
import {sha, le32, le} from './plonk.mjs';

export const TAG = Buffer.from('PLONKKZG-SI/1');
export const CHUNK = 2;
export const BOUNDS = (() => { const b = []; for (let e = CHUNK; e < NE; e += CHUNK) b.push(e); b.push(NE); return b; })();
export const NSTATES = BOUNDS.length; // 33
export const K_IDS = NSTATES + 1;
export const isBoundary = (e) => BOUNDS.includes(e + 1);
export const WS_SIZE = 192 * (1 + NSTATES); // s^c and the 33 states, 6 LE words each
// degrees: an event multiplies two lines (9 each); an addition event two more lines and the c factor (6)
export const eventDeg = (e) => 18 + (DIGITS[e] ? 24 : 0);
export const chunkDegP = (k) => { let d = 6; for (let e = k ? BOUNDS[k - 1] : 0; e < BOUNDS[k]; e++) d = 2 * d + eventDeg(e); return d; };
const nqOfDegD = (dD) => { const dq = (dD % 2 ? dD : dD - 1) - 12; return (dq + 1) / 2; };
export const TERM_DEG_P = 6 + 4 * 9 + 6; // S_33, four Frobenius lines, S_c(eta X)
export const NQ_MAX = Math.max(...Array.from({length: NSTATES}, (_, k) => nqOfDegD(chunkDegP(k) + 6)), nqOfDegD(TERM_DEG_P + 22));

const chainCache = new Map();
export const chains = (vk) => { const key = vk.g2x.toHex(); if (!chainCache.has(key)) chainCache.set(key, {a: chainConsts(vk.g2), b: chainConsts(vk.g2x)}); return chainCache.get(key); };

// per-event line polynomials of both chains at the affine points Pa = P*, Pb = P_right
export function factorSchedule(CH, Pa, Pb) {
  const mk = (C, [xP, yP]) => { let x = C.aff.x, c = F2.sub(F2.mul(C.lams[0], C.aff.x), C.aff.y), j = 0;
    return (s) => { const line = linePoly(xP, yP, F2.ONE, F2.neg(C.lams[j]), c); const sx = s === 'dbl' ? x : s;
      const nx = F2.sub(F2.sub(F2.sqr(C.lams[j]), x), sx); if (j + 1 < 88) c = F2.sub(F2.mul(F2.add(C.lams[j], C.lams[j + 1]), nx), c); x = nx; j++; return line; }; };
  const A = mk(CH.a, Pa), B = mk(CH.b, Pb);
  const events = [];
  for (let e = 0; e < NE; e++) { const fs = [A('dbl'), B('dbl')]; if (DIGITS[e]) fs.push(A(CH.a.aff.x), B(CH.b.aff.x)); events.push({fs, cSign: DIGITS[e]}); }
  const term = [A(CH.a.psi1x), B(CH.b.psi1x), A(F2.ZERO), B(F2.ZERO)];
  return {events, term};
}

export function proveSI(CH, Pa, Pb, uRaw) {
  const sched = factorSchedule(CH, Pa, Pb);
  let raw = F12.ONE;
  for (const ev of sched.events) { raw = F12.sqr(raw); for (const f of ev.fs) raw = F12.mul(raw, fromPoly(f)); }
  for (const f of sched.term) raw = F12.mul(raw, fromPoly(f));
  const accept = F12.eql(F12.finalExponentiate(raw), F12.ONE);
  const minv = (a, m) => inv(a, m);
  const uu = F12.mul(F12.conjugate(raw), F12.inv(raw)), vv = F12.pow(uu, minv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(vv));
  const Sc = monicRep(c);
  const cPoly = (sign) => (sign > 0 ? pneg(Sc) : Sc);
  let Fc = fromPoly(pneg(Sc)); const states = [];
  sched.events.forEach((ev, e) => { Fc = F12.sqr(Fc); for (const f of ev.fs) Fc = F12.mul(Fc, fromPoly(f)); if (ev.cSign) Fc = F12.mul(Fc, fromPoly(cPoly(ev.cSign))); if (isBoundary(e)) states.push(monicRep(Fc)); });
  const Sp = [pneg(Sc), ...states]; const ids = [];
  for (let k = 0; k < NSTATES; k++) {
    let P = Sp[k];
    for (let e = k ? BOUNDS[k - 1] : 0; e < BOUNDS[k]; e++) { P = pmul(P, P); for (const f of sched.events[e].fs) P = pmul(P, f); if (sched.events[e].cSign) P = pmul(P, cPoly(sched.events[e].cSign)); }
    ids.push({P, W: Sp[k + 1]});
  }
  let Pfin = Sp[NSTATES]; for (const f of sched.term) Pfin = pmul(Pfin, f); Pfin = pmul(Pfin, psubst(Sc, ETA));
  const Fr1 = frob1Monic(Sc); ids.push({P: Pfin, W: pmul(Fr1, psubst(Fr1, ETA))});
  let divisible = true;
  for (const id of ids) { const Nn = pmul(id.P, pneg(id.W)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D); if (!rem.every((x) => x === 0n)) divisible = false; id.Q = q; }
  if (accept) assert.ok(divisible, 'identity not divisible by M');
  const W32 = (x) => le32(mod(x));
  const WS = Buffer.concat([...Sc.slice(0, 6).map(W32), ...states.flatMap((s) => s.slice(0, 6).map(W32))]);
  assert.equal(WS.length, WS_SIZE);
  const h0 = sha(TAG, uRaw, WS), rhoRaw = sha(h0, Buffer.from('rho'));
  const rho = le(rhoRaw) % p;
  const Qagg = Array(2 * NQ_MAX).fill(0n);
  ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(K_IDS - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * NQ_MAX, 'Q exceeds structural bound'); Qagg[i] = mod(Qagg[i] + wgt * x); } }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1);
  while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W32));
  return {accept, WS, WQ, nq: qOdd.length, Sc, states, sched};
}
export {NE, NADD};
