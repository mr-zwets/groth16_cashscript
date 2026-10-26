// BLS12-381 SI-GLS on current BCH (bch-2026), split over 4 P2SH32 inputs: the witness layout, the role table
// (which input holds which bytes, at which offset), the transcript, the honest prover (exact polynomial
// identities, divisibility asserted) and a value-level reference of the split computation (the partial sums
// R_i and the B-walk handoffs T_i that each input claims). See README.md for the protocol and the soundness argument.
//
// Schedule: T = |x| = 0xd201000000010000, binary, 63 events e = 0..62 (bit 62 - e), additions at events
// 0, 2, 5, 14, 46. The loop's initial value carries the top bit of T (c^-1), Rconst' and GLS nibble 0; event e
// squares, adds the B and delta doubling lines, [the B and delta addition lines and c^-1], and GLS nibble e + 1.
// The B walk is affine for every event, with witnessed slopes, each fixed by an exact field equation.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {p, r, mod, F2, F12, f2, AXPOW, BITS, NE, ADD_EVENTS, LAMBDA, N6R, B_TWIST, GAMMA2, GAMMA3, conj2, VKC, VK_ENCODING,
  glsFactor, glsDigits, lineAffPoly, frob1Monic, fromPoly, monicRep, pmul, psub, pneg, peval, pdivM, isZero, M} from './math.mjs';

export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
// ---------------- schedule and chunks ----------------
export const TAG = Buffer.concat([Buffer.from('SIGLS-BLS-NATIVE/1'), sha(VK_ENCODING)]); // 50 B, fixed width
assert.equal(TAG.length, 50);
// chunks: [0] [1,2] [3] [4,5] [6] [7,8] ... [61,62]: every addition (0, 2, 5, 14, 46) is a chunk's only or second event
export const LAYOUT = [1, 2, 1, 2, 1, ...Array.from({length: 28}, () => 2)];
assert.equal(LAYOUT.reduce((a, b) => a + b, 0), NE);
export const CHUNK_END = LAYOUT.map((_, k) => LAYOUT.slice(0, k + 1).reduce((a, b) => a + b, 0) - 1); // last event of chunk k
export const CHUNK_START = CHUNK_END.map((e, k) => e - LAYOUT[k] + 1);
export const BOUNDS = CHUNK_END.slice(0, -1);              // a state is committed after these events (32); the last chunk closes against W
export const NSTATES = BOUNDS.length, K_IDS = NSTATES + 1;
assert.equal(NSTATES, 32);
export const isBoundary = (e) => BOUNDS.includes(e);
export const isAdd = (e) => BITS[e] === 1;
export const W = 48;                                        // field word (LE)
// ---------------- degree bookkeeping (structural, adversarial: up to 8 GLS bits per event) ----------------
// B line (affine) 8, delta line 8, c factor 6, GLS factor 6 per set bit. Start: c^-1 (6), Rconst' (6), GLS nibble 0.
export const eventDeg = (e, bits) => 8 + 8 + (isAdd(e) ? 8 + 8 + 6 : 0) + 6 * bits;
export const chunkDegP = (k, bitsOf) => { let d = k === 0 ? 12 + 6 * bitsOf(-1) : 6; for (let e = CHUNK_START[k]; e <= CHUNK_END[k]; e++) d = 2 * d + eventDeg(e, bitsOf(e)); return d; };
const nqOfDegD = (dD) => { const odd = dD % 2 ? dD : dD - 1; return (odd - 12 + 1) / 2; };
export const degDBound = (k, bitsOf) => chunkDegP(k, bitsOf) + (k === K_IDS - 1 ? 11 : 6);
export const nqFor = (bitsOf) => Math.max(...Array.from({length: K_IDS}, (_, k) => nqOfDegD(degDBound(k, bitsOf))));
export const NQ_MAX = nqFor(() => 8);                      // structural cap (every nibble 15)
export const N_MIN = nqFor(() => 0);                       // canonical floor: the structural length of the all-zero-nibble statement
assert.equal(NQ_MAX, 116); assert.equal(N_MIN, 44);

// statement block (head, at the start of region 0): 8 coordinates, n0, n1 (32 B each), N0, N1 (64 nibbles each), s^c (6 words)
export const STMT = {xA: 0, n0: 384, n1: 416, N0: 448, N1: 512, sc: 576};
export const STMT_SIZE = 864;

// ---------------- the 4 inputs: chunk ownership ----------------
export const NIN = 4;
// the layout (layout.json, checked in; NATIVE_CUTS / NATIVE_PLACE override it for layout search and measurement)
export const LAYOUT_FILE = JSON.parse(readFileSync(new URL('./layout.json', import.meta.url), 'utf8'));
export const CUTS = process.env.NATIVE_CUTS ? process.env.NATIVE_CUTS.split(',').map(Number) : LAYOUT_FILE.cuts; // input i owns chunks [CUTS[i], CUTS[i+1])
assert.equal(CUTS.length, NIN + 1); assert.equal(CUTS[0], 0); assert.equal(CUTS[NIN], K_IDS);
export const ROLES = Array.from({length: NIN}, (_, i) => {
  const c0 = CUTS[i], c1 = CUTS[i + 1]; const e0 = CHUNK_START[c0], e1 = CHUNK_END[c1 - 1];
  const events = Array.from({length: e1 - e0 + 1}, (_, k) => e0 + k);
  const states = []; for (let k = c0; k < c1; k++) if (k < NSTATES) states.push(k); // states[k] = S_{k+1}, after chunk k
  const nslopes = events.reduce((s, e) => s + 1 + (isAdd(e) ? 1 : 0), 0);
  const dstep0 = Array.from({length: e0}, (_, e) => 1 + (isAdd(e) ? 1 : 0)).reduce((a, b) => a + b, 0); // first delta step index
  return {i, c0, c1, e0, e1, events, states, nslopes, dstep0, last: i === NIN - 1,
    regionSize: (i === 0 ? STMT_SIZE : 0) + 288 * states.length + 96 * nslopes,
    claimSize: i === NIN - 1 ? W : W + 4 * W,
    kSize: (i === 0 ? 0 : 192) + 96 * nslopes};                // delta block: start point (x, y) (input 0: delta itself, in the program) + one slope per step
});

// ---------------- placement of the movable bytes (constant blocks, program blob) ----------------
// Each role's delta block K_i is a constant (SHA256 baked in the program) and may sit in any input's unlocking as
// one or more fixed-size pushes ("pieces"); the program blob is split into parts, each the last push before the redeem
// of its carrier input (PLACE.blob = [carrier, ...], PLACE.blobLens = lengths of all parts but the last).
// PLACE.K[i] = [[host, len], ...] (in order, lengths sum to kSize). Overridable for layout search (NATIVE_PLACE json).
export const PLACE = (() => {
  const dflt = {blob: 3, K: ROLES.map((ro) => [[ro.i, ro.kSize]])};
  const pl = process.env.NATIVE_PLACE ? JSON.parse(process.env.NATIVE_PLACE) : process.env.NATIVE_CUTS ? dflt : structuredClone(LAYOUT_FILE.place);
  if (!pl.K) pl.K = dflt.K;
  pl.K = pl.K.map((pcs, i) => { const tot = pcs.reduce((s, [, l]) => s + l, 0); const fixed = pcs.map(([h, l]) => [h, l]);
    if (tot !== ROLES[i].kSize) { const lastLen = fixed.at(-1)[1] + ROLES[i].kSize - tot; assert.ok(lastLen >= 48, 'K piece'); fixed.at(-1)[1] = lastLen; } return fixed; });
  if (!Array.isArray(pl.blob)) pl.blob = [pl.blob]; pl.blobLens = pl.blobLens ?? [];
  assert.equal(pl.blobLens.length, pl.blob.length - 1); assert.equal(new Set(pl.blob).size, pl.blob.length);
  pl.blob.forEach((c) => assert.ok(c > 0 && c < NIN, 'a carrier is not input 0 (its WQ has a variable length)'));
  pl.K.forEach((pcs) => pcs.forEach(([h, l]) => assert.ok(h >= 0 && h < NIN && l >= 48)));
  return pl;
})();
export const hdrLen = (n) => (n < 76 ? 1 : n < 256 ? 2 : 3);
// pushes of input h in unlocking order (the redeem follows); sizes, with WQ (input 0) and BLOB variable
export const pushesOf = (h) => {
  const out = [];
  if (h === 0) out.push({name: 'ZR', size: 2 * W});
  out.push({name: 'G', size: ROLES[h].regionSize});
  out.push({name: 'CL', size: ROLES[h].claimSize});                              // right after G: one slice reads both
  PLACE.K.forEach((pcs, i) => pcs.forEach(([host, len], j) => { if (host === h) out.push({name: `K${i}_${j}`, size: len, role: i, piece: j}); }));
  if (PLACE.fill?.[h]) out.push({name: 'PAD', size: PLACE.fill[h]});           // budget filler (zero bytes), only if a layout needs it
  if (h === 0) out.push({name: 'WQ', size: null});
  if (PLACE.blob.includes(h)) out.push({name: 'BLOB', size: null, part: PLACE.blob.indexOf(h)});
  return out;
};
// byte offset of the data of push `name` in input h's unlocking (only for pushes before any variable-size push)
export const offsetOf = (h, name) => {
  let o = 0;
  for (const ps of pushesOf(h)) { if (ps.name === name) return o + hdrLen(ps.size); assert.ok(ps.size !== null, 'offset after a variable push'); o += hdrLen(ps.size) + ps.size; }
  throw new Error(`no push ${name} in input ${h}`);
};
export const fixedPrefixSize = (h) => pushesOf(h).filter((x) => x.size !== null).reduce((s, x) => s + hdrLen(x.size) + x.size, 0);

// ---------------- encodings ----------------
export const leN = (x, n) => { assert.ok(x >= 0n && x < 1n << BigInt(8 * n), 'leN range'); const b = Buffer.alloc(n); let v = x; for (let i = 0; i < n; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const W48 = (x) => leN(mod(x), 48);
export const rdle = (b, o = 0, n = 48) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = v * 256n + BigInt(b[o + i]); return v; };
export const toCh = (h) => rdle(h, 0, 32);                // BIN2NUM(h || 0x00): unsigned, < 2^256 < p, no reduction
const three = f2(3n, 0n);

// ---------------- the delta constant blocks ----------------
// delta walk state before step j: (x_j, c_{j-1}, l_{j-1}), start (x_delta, y_delta, 0); baked slope l_j per step
export const DELTA = (() => {
  const d = VKC.deltaAff; let x = d.x, c = d.y, l = F2.ZERO; const states = [];
  for (let e = 0, j = 0; e < NE; e++) for (const add of isAdd(e) ? [false, true] : [false]) {
    states[j] = {x, c, l}; const lj = VKC.lams[j]; const cj = F2.sub(F2.mul(F2.add(l, lj), x), c);
    x = F2.sub(F2.sub(F2.sqr(lj), x), add ? d.x : x); c = cj; l = lj; j++;
  }
  return {states};
})();
// the start point (x_j, y_j) of role i's first delta step (y_j = c_{j-1} - l_{j-1} x_j); the script resumes the recursion
// with l_{j-1} := 0 and c_{j-1} := y_j, which gives the same c_j = l_j x_j - y_j
export const kBlock = (i) => { const ro = ROLES[i]; const s = DELTA.states[ro.dstep0]; const y = F2.sub(s.c, F2.mul(s.l, s.x));
  const b = Buffer.concat([...(i === 0 ? [] : [s.x.c0, s.x.c1, y.c0, y.c1].map(W48)), ...VKC.lams.slice(ro.dstep0, ro.dstep0 + ro.nslopes).flatMap((l) => [W48(l.c0), W48(l.c1)])]);
  assert.equal(b.length, ro.kSize); return b; };
export const K_BLOCKS = ROLES.map((_, i) => kBlock(i));
export const K_HASH = K_BLOCKS.map((b) => sha(b));

// ---------------- the schedule as polynomials (shared by prover and reference verifier) ----------------
// st: {xA, yA, xB, yB, xC, yC, N}; N[k][j] (j = 0..63) = nibble j: bit i = bit (63 - j) of digit a_{k,i}.
// slopes: the witnessed affine slopes (verifier) or null (prover: computed). Returns per-event factor lists
// (without c), the start factors, the slopes used, the B points after each event, and the endpoint verdict.
export function factorSchedule(st, slopes = null) {
  const {xA, yA, xB, yB, xC, yC, N} = st;
  const xP = xA, yP = mod(-yA);                           // P0 = -A
  const out = {events: [], slopes: [], pts: [], ok: true};
  const fail = (why) => ({ok: false, why});
  const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactor(k, i)); return poly; };
  const gls = (j) => pmul(tbl(0, N[0][j]), tbl(1, N[1][j]));
  // delta (fixed): baked slopes, the on-chain recursion
  let dx = VKC.deltaAff.x, dc = VKC.deltaAff.y, dl = F2.ZERO, j = 0; const lam = VKC.lams;
  const dstep = (add) => { const cj = F2.sub(F2.mul(F2.add(dl, lam[j]), dx), dc); const line = lineAffPoly(xC, yC, lam[j], cj);
    const s = add ? VKC.deltaAff.x : dx; dx = F2.sub(F2.sub(F2.sqr(lam[j]), dx), s); dc = cj; dl = lam[j]; j++; return line; };
  let aff = {x: xB, y: yB}, si = 0;
  const nextSlope = (honest) => { if (slopes === null) { out.slopes.push(honest()); return out.slopes.at(-1); } const l = slopes[si++]; out.slopes.push(l); return l; };
  for (let e = 0; e < NE; e++) {
    const fs = [];
    { const l = nextSlope(() => F2.div(F2.mul(three, F2.sqr(aff.x)), F2.add(aff.y, aff.y)));
      if (!F2.is0(F2.sub(F2.mul(F2.add(aff.y, aff.y), l), F2.mul(three, F2.sqr(aff.x))))) return fail('affine doubling slope');
      fs.push(lineAffPoly(xP, yP, l, F2.sub(F2.mul(l, aff.x), aff.y)));
      const x3 = F2.sub(F2.sqr(l), F2.add(aff.x, aff.x)); aff = {x: x3, y: F2.sub(F2.mul(l, F2.sub(aff.x, x3)), aff.y)}; }
    fs.push(dstep(false));
    if (isAdd(e)) {
      if (F2.eql(aff.x, xB)) return fail('affine addition x = xB');
      const l = nextSlope(() => F2.div(F2.sub(yB, aff.y), F2.sub(xB, aff.x)));
      if (!F2.is0(F2.sub(F2.mul(l, F2.sub(xB, aff.x)), F2.sub(yB, aff.y)))) return fail('affine addition slope');
      fs.push(lineAffPoly(xP, yP, l, F2.sub(F2.mul(l, aff.x), aff.y)));
      const x3 = F2.sub(F2.sub(F2.sqr(l), aff.x), xB); aff = {x: x3, y: F2.sub(F2.mul(l, F2.sub(aff.x, x3)), aff.y)};
      fs.push(dstep(true));
    }
    fs.push(gls(e + 1));
    out.events.push({fs, c: isAdd(e)}); out.pts.push(aff);
  }
  assert.equal(j, lam.length);
  if (slopes !== null && si !== slopes.length) return fail('slope count');
  out.start = [VKC.Rconst, gls(0)];
  // endpoint [T]B = -psi(B): x gamma1^2 = conj(xB), y gamma1^3 = -conj(yB)
  out.endpoint = F2.eql(F2.mul(aff.x, GAMMA2), conj2(xB)) && F2.eql(F2.mul(aff.y, GAMMA3), F2.neg(conj2(yB)));
  return out;
}
const popc = (n) => [0, 1, 2, 3].filter((i) => (n >> i) & 1).length;

// ---------------- prover ----------------
// digits: override of the base-|x| digits (any a_{k,i} < 2^64 with sum_i a_{k,i} T^i = n_k is valid).
// forge (rejection tests only): skip the Groth16, endpoint and divisibility assertions and use floor quotients, to
// build the most consistent witness for an INVALID input so that a specific script guard is exercised.
export function prove(fx, {digits = null, forge = false, slopeOverride = null} = {}) {
  const {inputs, proof} = fx; const A = proof.a, B = proof.b, C = proof.c;
  if (!forge) { A.assertValidity(); B.assertValidity(); C.assertValidity(); }
  assert.ok(!A.is0() && !B.is0() && !C.is0(), 'the encoding has no point at infinity');
  const ns = inputs.map(BigInt); if (!forge) ns.forEach((n) => assert.ok(n >= 0n && n < r));
  const dg = digits ?? ns.map((n) => glsDigits(n));
  dg.forEach((a, k) => { a.forEach((v) => assert.ok(v >= 0n && v < 1n << 64n, 'digit range')); if (!forge) assert.equal(a.reduce((s, v, i) => s + v * AXPOW[i], 0n), ns[k], 'digits bind n'); });
  const N = dg.map((a) => Array.from({length: 64}, (_, j) => a.reduce((s, ai, i) => s | (Number((ai >> BigInt(63 - j)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st, slopeOverride);
  assert.ok(sched.ok, 'schedule: ' + sched.why);
  if (!forge) assert.ok(sched.endpoint, 'B endpoint');
  // f' (no c): the full Miller product with Rconst' and the GLS factors; FE(f') = 1 for a valid proof
  let fprime = F12.ONE; for (const f of sched.start) fprime = F12.mul(fprime, fromPoly(f));
  for (const ev of sched.events) { fprime = F12.sqr(fprime); for (const f of ev.fs) fprime = F12.mul(fprime, fromPoly(f)); }
  if (!forge) assert.ok(F12.eql(F12.finalExponentiate(fprime), F12.ONE), 'Groth16 equation fails (FE(f\') != 1)');
  // residue root: [c]^lambda = [f'];  u = f'^(p^6-1) (order | N6R), t = u^(lambda^-1 mod N6R), c = 1 + conj(t)
  const minv = (a, m) => { let [x, y] = [mod(a, m), m], [s0, s1] = [1n, 0n]; while (y) { const q = x / y; [x, y] = [y, x - q * y]; [s0, s1] = [s1, s0 - q * s1]; } assert.equal(x, 1n); return mod(s0, m); };
  const u = F12.mul(F12.conjugate(fprime), F12.inv(fprime)), t = F12.pow(u, minv(LAMBDA, N6R)), c = F12.add(F12.ONE, F12.conjugate(t));
  const Sc = monicRep(c); const ScNeg = pneg(Sc);       // [S_c(-X)] = [c^-1]
  let start = pmul(pmul(ScNeg, sched.start[0]), sched.start[1]);
  const evPoly = (e) => { let f = [1n]; for (const x of sched.events[e].fs) f = pmul(f, x); return sched.events[e].c ? pmul(f, ScNeg) : f; };
  const Wp = frob1Monic(Sc.slice(0, 6));
  const states = [], ids = []; let e = 0;
  for (let k = 0; k < K_IDS; k++) {
    let P = start; for (; e <= CHUNK_END[k]; e++) P = pmul(pmul(P, P), evPoly(e));
    const last = k === K_IDS - 1; const S = last ? Wp : monicRep(fromPoly(P));
    const D = psub(pmul(P, pneg(S)), pmul(pneg(P), S)); const {q, r: rem} = pdivM(D);
    if (!forge) { assert.ok(isZero(rem), `identity ${k} not divisible by M`); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd'); }
    ids.push({P, S, D, Q: q}); if (!last) { states.push(S); start = S; }
  }
  // regions (committed bytes): region 0 = statement block | own states | own slopes; region i = states | slopes
  const stmt = Buffer.concat([...[Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y].map(W48), ...ns.map((n) => leN(mod(n, 1n << 256n), 32)),
    Buffer.from(N[0]), Buffer.from(N[1]), ...Sc.slice(0, 6).map(W48)]);
  assert.equal(stmt.length, STMT_SIZE);
  const slopeBytes = sched.slopes.map((l) => Buffer.concat([W48(l.c0), W48(l.c1)]));
  let si = 0;
  const regions = ROLES.map((ro) => { const parts = ro.i === 0 ? [stmt] : [];
    for (const k of ro.states) parts.push(...states[k].slice(0, 6).map(W48));
    for (let n = 0; n < ro.nslopes; n++) parts.push(slopeBytes[si++]);
    const g = Buffer.concat(parts); if (!forge || slopeOverride === null) assert.equal(g.length, ro.regionSize); return g; });
  const w = {regions, ns, digits: dg, N, Sc, states, c, stmt, slopes: sched.slopes, debug: {sched, ids, forge, popBound: nqFor((ev) => [0, 1].reduce((s, k) => s + popc(N[k][ev + 1]), 0))}};
  return finishWitness(w, regions);
}
// transcript, challenges, aggregated quotient and claims for given region bytes (the honest prover; also used by the rejection
// suite to re-derive a consistent transcript for a re-encoded region, e.g. a +p alias, which must then fail its range check)
export function finishWitness(w0, regions) {
  const {ids, forge, popBound, sched} = w0.debug;
  const {h0, rhoRaw} = transcript(regions); const rho = toCh(rhoRaw);
  // aggregated quotient Q = sum_k rho^(K-1-k) Q_k (odd), trimmed; canonical length >= N_MIN (zero-padded below)
  const Qagg = []; ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(K_IDS - 1 - k)); id.Q.forEach((x, i) => { Qagg[i] = mod((Qagg[i] ?? 0n) + wgt * x); }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1); while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  const nqTrue = qOdd.length; while (qOdd.length < N_MIN) qOdd.push(0n);
  if (!forge) { assert.ok(nqTrue <= popBound, 'n_q within the structural bound'); assert.ok(qOdd.length <= NQ_MAX); }
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W48)); // highest coefficient first
  const z = toCh(sha(h0, rhoRaw, WQ));
  const w = {...w0, regions, WQ, nq: qOdd.length, nqTrue, z, rho, h0};
  w.claims = splitClaims(w, null, sched);
  return w;
}
export function transcript(regions) {
  const h0 = sha(TAG, ...regions.map((g) => sha(g))); const rhoRaw = sha(h0, Buffer.from('rho'));
  return {h0, rhoRaw};
}

// ---------------- value-level split computation (the reference of each input's work) ----------------
// For input i: F+- start at S_{c0}(+-z) (input 0: S_c(-+z) Rconst'(+-z) G_0(+-z)); per event the factors; at each
// chunk end R <- R rho + F+ S(-z) - F- S(z); the last input closes against W = Frob(S_c). R continues across the inputs:
// input i > 0 starts from the predecessor's claim R_{i-1}, so R_3 = sum_k rho^(K-1-k) D_k(z). Claims: R_i, T_i (B point).
export function splitClaims(w, st, sched) {
  const {z, rho} = w; const zm = mod(-z); const mono = (s) => [...s.slice(0, 6), 1n];
  const scP = mono(w.Sc); const ev2 = (f, F) => [mod(F[0] * peval(f, z)), mod(F[1] * peval(f, zm))];
  const Rs = [], Ts = [];
  for (const ro of ROLES) {
    let F;
    if (ro.i === 0) { F = [peval(pneg(scP), z), peval(pneg(scP), zm)]; for (const f of sched.start) F = ev2(f, F); }
    else { const S = mono(w.states[ro.c0 - 1]); F = [peval(S, z), peval(S, zm)]; }
    let R = ro.i === 0 ? 0n : Rs[ro.i - 1];
    for (const e of ro.events) {
      const ev = sched.events[e];
      F = [mod(F[0] * F[0]), mod(F[1] * F[1])]; for (const f of ev.fs) F = ev2(f, F); if (ev.c) F = ev2(pneg(scP), F);
      const k = BOUNDS.indexOf(e);
      if (k >= 0) { const S = mono(w.states[k]); const Sp = peval(S, z), Sm = peval(S, zm); R = mod(R * rho + F[0] * Sm - F[1] * Sp); F = [Sp, Sm]; }
    }
    if (ro.last) { const Wp = frob1Monic(w.Sc.slice(0, 6)); R = mod(R * rho + F[0] * peval(Wp, zm) - F[1] * peval(Wp, z)); }
    Rs.push(R); Ts.push(sched.pts[ro.e1]);
  }
  // the head's final identity: R_3 == z q(z^2) M(z)
  let acc = 0n; const z2 = mod(z * z); for (let i = 0; i < w.WQ.length; i += 48) acc = mod(acc * z2 + rdle(w.WQ, i));
  const fin = mod(Rs[NIN - 1] - z * acc * peval(M, z));
  return {R: Rs, T: Ts, final: fin, bytes: ROLES.map((ro, i) => Buffer.concat([W48(Rs[i]), ...(ro.last ? [] : [Ts[i].x.c0, Ts[i].x.c1, Ts[i].y.c0, Ts[i].y.c1].map(W48))]))};
}

// ---------------- the transaction's unlocking pushes (before the redeem) ----------------
export const blobParts = (blob) => { const out = []; let o = 0; PLACE.blob.forEach((h, j) => { const n = j < PLACE.blobLens.length ? PLACE.blobLens[j] : blob.length - o; out.push(blob.subarray(o, o + n)); o += n; }); return out; };
export function txPushes(w, blob) {
  const parts = blobParts(blob);
  const ZR = Buffer.concat([W48(w.z), W48(w.rho)]);
  return Array.from({length: NIN}, (_, h) => pushesOf(h).map((ps) => {
    if (ps.name === 'ZR') return ZR;
    if (ps.name === 'G') return w.regions[h];
    if (ps.name === 'CL') return w.claims.bytes[h];
    if (ps.name === 'WQ') return w.WQ;
    if (ps.name === 'BLOB') return Buffer.from(parts[ps.part]);
    if (ps.name === 'PAD') return Buffer.alloc(ps.size);
    const pcs = PLACE.K[ps.role]; const off = pcs.slice(0, ps.piece).reduce((s, [, l]) => s + l, 0);
    return K_BLOCKS[ps.role].subarray(off, off + ps.size);
  }));
}

// ---------------- value-level reference verifier (single computation, mirrors the scripts' checks) ----------------
export function verifyValues(w) {
  const fail = (why) => ({ok: false, why});
  const {WQ} = w; const g0 = w.regions[0];
  if (WQ.length % 48 || WQ.length < 48 * N_MIN || WQ.length > 48 * NQ_MAX) return fail('WQ size');
  const qw = Array.from({length: WQ.length / 48}, (_, i) => rdle(WQ, 48 * i));
  if (WQ.length > 48 * N_MIN && qw[0] === 0n) return fail('Q leading word zero');
  if (w.regions.some((g, i) => g.length !== ROLES[i].regionSize)) return fail('region size');
  const {h0, rhoRaw} = transcript(w.regions); const rho = toCh(rhoRaw), z = toCh(sha(h0, rhoRaw, WQ));
  if (z === 0n) return fail('z = 0');
  const word = (b, o) => { const v = rdle(b, o); return v < p ? v : null; };
  const st = Array.from({length: 8}, (_, i) => word(g0, 48 * i)); if (st.some((v) => v === null)) return fail('coordinate not canonical');
  const ns = [rdle(g0, STMT.n0, 32), rdle(g0, STMT.n1, 32)]; if (ns.some((v) => v >= r)) return fail('public input not canonical');
  const nibs = [0, 1].map((k) => [...g0.subarray(STMT.N0 + 64 * k, STMT.N0 + 64 + 64 * k)]); if (nibs.flat().some((b) => b > 15)) return fail('nibble range');
  const sc = Array.from({length: 6}, (_, j) => word(g0, STMT.sc + 48 * j)); if (sc.some((v) => v === null)) return fail('s^c not canonical');
  const stts = [], sl = [];
  for (const ro of ROLES) { const g = w.regions[ro.i]; let o = ro.i === 0 ? STMT_SIZE : 0;
    for (const k of ro.states) { const s = Array.from({length: 6}, (_, j) => word(g, o + 48 * j)); if (s.some((v) => v === null)) return fail('state not canonical'); stts[k] = s; o += 288; }
    for (let n = 0; n < ro.nslopes; n++) { const a = word(g, o), b = word(g, o + 48); if (a === null || b === null) return fail('slope not canonical'); sl.push(f2(a, b)); o += 96; } }
  if (qw.some((v) => v >= p)) return fail('Q word not canonical');
  const [xA, yA, xB0, xB1, yB0, yB1, xC, yC] = st; const xB = f2(xB0, xB1), yB = f2(yB0, yB1);
  if (mod(yA * yA - xA ** 3n - 4n) !== 0n || mod(yC * yC - xC ** 3n - 4n) !== 0n) return fail('G1 curve');
  if (!F2.eql(F2.sqr(yB), F2.add(F2.mul(F2.sqr(xB), xB), B_TWIST))) return fail('twist curve');
  const sched = factorSchedule({xA, yA, xB, yB, xC, yC, N: nibs}, sl);
  if (!sched.ok) return fail(sched.why);
  if (!sched.endpoint) return fail('B endpoint');
  for (const kk of [0, 1]) { let acc = 0n; for (let j = 0; j < 64; j++) { acc = 2n * acc; for (let i = 0; i < 4; i++) if ((nibs[kk][j] >> i) & 1) acc += AXPOW[i]; } if (acc !== ns[kk]) return fail('GLS binding ' + kk); }
  const cl = splitClaims({z, rho, Sc: sc, states: stts, WQ}, null, sched);
  return cl.final === 0n ? {ok: true, z, rho, claims: cl} : fail('final identity');
}
