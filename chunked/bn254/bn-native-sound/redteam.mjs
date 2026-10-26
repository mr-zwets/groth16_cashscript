// Rejection suite for bn-native-sound (ordinary, constructive rejection tests only: malformed or mismatched inputs
// that a sound verifier must reject; no witness is ever searched or rebuilt to satisfy a false statement).
// Every run below must be REJECTED (some input of the 3-input transaction fails) in consensus AND standard mode.
//
// Two levels of tamper:
//   raw         - bytes changed, nothing else: tests the commitment / handover / layout checks;
//   recommitted - a committed item (STMT, S_i, WQ) is changed and the digest list DG, the challenges and the
//                 handovers are recomputed for the changed bytes (handovers = what the honest roles compute), so
//                 that the specific guard (range, curve, nibble mask, inverse-norm equation, binding, final identity,
//                 quotient rules) is what has to reject.
// Graph tests (2 or 4 inputs, a foreign locking) change the transaction shape; they are run here but cannot be
// expressed in the bench red-team file (which only patches unlockings of the fixed 3-input run).
//   node redteam.mjs vectors.json redteam.json [report.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {encodeDataPush, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
import {FIXTURES, p, r, PI, GLS_OFFSET, LATTICE, mod, F2, f2, Fp} from '../sound-si-gls/math.mjs';
import {BOUNDS, proveCore, factorSchedule, runRange, startState, encodeHand, zOf, zTail, sha, le32, rdle, STMT_LAYOUT, CUTS, ROLES, NQ_MAX, TAG, toFp} from './protocol.mjs';
import {buildProgram} from './script.mjs';
import {transactionFor, unlockingsFor} from './transaction.mjs';
import {encodeUnlocking, spendAll, programOf, VMS, p2sh32} from './vm.mjs';

const [vecPath, outPath, reportPath] = process.argv.slice(2);
assert.ok(vecPath && outPath, 'usage: node redteam.mjs vectors.json redteam.json [report.json]');
const prog = buildProgram();
const built = JSON.parse(readFileSync(new URL('./build.json', import.meta.url), 'utf8'));
assert.equal(createHash('sha256').update(prog.code).digest('hex'), built.codeSha256, 'build.json is stale: run build.mjs');
const vectors = JSON.parse(readFileSync(vecPath, 'utf8'));
const fx0 = FIXTURES.fixtures[0], fx1 = FIXTURES.fixtures[1];
const T0 = transactionFor(fx0, prog), T1 = transactionFor(fx1, prog);
const lock = T0.locking; const LOCKS = [lock, lock, lock];
vectors.steps.forEach((s, i) => { assert.equal(s.locking, lock.toString('hex')); assert.equal(s.unlocking, T0.unlockings[i].toString('hex'), 'vectors are from another build'); });
const fills = T0.fills;
const PUSH = {S0: [0, 0], DS0: [0, 1], C0: [0, 2], F0: [0, 3], R0: [0, 4], S1: [1, 0], H1: [1, 1], DS1: [1, 2], C1: [1, 3], F1: [1, 4], R1: [1, 5],
  DG: [2, 0], STMT: [2, 1], S2: [2, 2], H2: [2, 3], DS2: [2, 4], F2: [2, 5], WQ: [2, 6], R2: [2, 7]};

const runs = [];
// expect (optional): the exact first rejecting guard per input, as guardOf reports it ('accept' = that input must accept)
const add = (label, kind, unlockings, {locks = LOCKS, bench = true, expect = null} = {}) => runs.push({label, kind, unlockings: unlockings.map((u) => Buffer.from(u)), locks, bench, expect});
const clonePushes = (T) => T.pushes.map((ps) => ps.map((b) => Buffer.from(b)));
const enc = (P) => P.map((ps) => Buffer.from(encodeUnlocking(ps)));
const setWord = (b, off, v) => { const c = Buffer.from(b); le32(v).copy(c, off); return c; };
const flipAt = (b, i, m = 1) => { const c = Buffer.from(b); c[i] ^= m; return c; };
const raw = (label, kind, f, T = T0) => { const P = clonePushes(T); f(P); add(label, kind, enc(P)); };
const at = (P, k) => P[PUSH[k][0]][PUSH[k][1]];
const put = (P, k, v) => { P[PUSH[k][0]][PUSH[k][1]] = Buffer.from(v); };
// recommitted: change committed items (STMT, S, WQ), recompute DG, rho, z and the handovers the honest roles compute
function recommitted(label, kind, {STMT, S, WQ, fill2, core, expect} = {}, base = T0) {
  const c = {...(core ?? base.core), STMT: STMT ?? base.core.STMT, S: S ?? base.core.S, WQ: WQ ?? base.core.WQ};
  c.D = Buffer.concat([sha(c.S[0]), sha(c.S[1]), sha(c.STMT, c.S[2])]);
  c.h0 = sha(TAG, c.D); c.rhoRaw = sha(c.h0, Buffer.from('rho')); c.rho = toFp(c.rhoRaw);
  const f = [...fills]; if (fill2 !== undefined) f[2] = fill2;
  const z = zOf(c, zTail(f[2], c.WQ)); let s = startState(c, z); const H = [null];
  for (let i = 0; i < 2; i++) { s = runRange(c, z, CUTS[i], CUTS[i + 1], s); H.push(encodeHand(s)); }
  const P = clonePushes(base); put(P, 'DG', c.D); put(P, 'STMT', c.STMT); put(P, 'S0', c.S[0]); put(P, 'S1', c.S[1]); put(P, 'S2', c.S[2]); put(P, 'WQ', c.WQ);
  put(P, 'H1', H[1]); put(P, 'H2', H[2]); put(P, 'F2', Buffer.alloc(f[2]));
  add(label, kind, enc(P), {expect});
}
const W = T0.core; const word = (b, o) => rdle(b, o);
const stmtWith = (off, v) => setWord(W.STMT, off, v);

// ---------------- 0. sanity: the recommit path reproduces the valid transaction ----------------
{ const before = runs.length; recommitted('(control)', 'control'); const u = runs.pop().unlockings; assert.equal(runs.length, before);
  u.forEach((x, i) => assert.ok(x.equals(T0.unlockings[i]), 'recommit path reproduces the valid run')); }

// ---------------- 1. statement: public inputs ----------------
{ const n0 = BigInt(fx0.publicInputs[0]), n1 = BigInt(fx0.publicInputs[1]);
  for (const [label, a, b] of [['n0 + 1', n0 + 1n, n1], ['n0 - 1', n0 - 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0, n1 swapped', n1, n0], ['n0 := fixture 1 n0', BigInt(fx1.publicInputs[0]), n1]])
    recommitted(`claim ${label} (honest witness otherwise; DG recommitted)`, 'public-input-binding', {STMT: setWord(stmtWith(STMT_LAYOUT.n0, a), STMT_LAYOUT.n1, b)});
  recommitted('n0 + r (non-canonical alias of n0)', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n0, n0 + r)});
  recommitted('n1 + r (non-canonical alias of n1)', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n1, n1 + r)});
  recommitted('n0 with the top bit set', 'public-input-encoding', {STMT: flipAt(W.STMT, STMT_LAYOUT.n0 + 31, 0x80)});
  recommitted('n0 = 2^256 - 1', 'public-input-encoding', {STMT: stmtWith(STMT_LAYOUT.n0, (1n << 256n) - 1n)});
  raw('n0 + 1 without recommitting DG', 'public-input-binding', (P) => put(P, 'STMT', stmtWith(STMT_LAYOUT.n0, n0 + 1n)));
}
// ---------------- 2. statement: proof points ----------------
{ for (const [label, off] of [['A.x + 1 (off curve)', 0], ['A.y + 1', 32], ['B.x.c0 + 1 (off twist)', 64], ['B.y.c1 + 1', 160], ['C.x + 1', 192], ['C.y + 1', 224]])
    recommitted(label, 'invalid-proof-point', {STMT: stmtWith(off, word(W.STMT, off) + 1n)});
  for (const [label, off] of [['A.x + p', 0], ['A.y + p', 32], ['B.x.c1 + p', 96], ['B.y.c0 + p', 128], ['C.x + p', 192], ['C.y + p', 224]])
    recommitted(label + ' (non-canonical alias of the same point)', 'non-canonical-coordinate', {STMT: stmtWith(off, word(W.STMT, off) + p)});
  recommitted('A = (0, 0)', 'invalid-proof-point', {STMT: setWord(stmtWith(0, 0n), 32, 0n)});
  recommitted('C = (0, 0)', 'invalid-proof-point', {STMT: setWord(stmtWith(192, 0n), 224, 0n)});
  recommitted('B = (0, 0)', 'invalid-proof-point', {STMT: [64, 96, 128, 160].reduce((b, o) => setWord(b, o, 0n), W.STMT)});
  recommitted('-A (y negated, on the curve)', 'invalid-proof-point', {STMT: stmtWith(32, mod(-word(W.STMT, 32)))});
  recommitted('-C (y negated)', 'invalid-proof-point', {STMT: stmtWith(224, mod(-word(W.STMT, 224)))});
  recommitted('-B (y negated, on the twist)', 'invalid-proof-point', {STMT: setWord(stmtWith(128, mod(-word(W.STMT, 128))), 160, mod(-word(W.STMT, 160)))});
  recommitted('A from proof 1', 'invalid-proof-point', {STMT: Buffer.concat([T1.core.STMT.subarray(0, 64), W.STMT.subarray(64)])});
  recommitted('B from proof 1 (in G2; the inverse-norm witnesses no longer match)', 'invalid-proof-point', {STMT: Buffer.concat([W.STMT.subarray(0, 64), T1.core.STMT.subarray(64, 192), W.STMT.subarray(192)])});
}
// ---------------- 2b. B on the twist but outside G2 (the endpoint guard) ----------------
// B' = the first twist point with x = (k, 1), k = 1, 2, ... (a square right-hand side) that noble's G2 validity check
// rejects; deterministic, no search over verifier outcomes. The inverse-norm witnesses t of the B' walk, DG, rho, z
// and the handovers are recomputed (states, residue root and quotient stay the honest ones), so every guard before
// the end of the walk passes on inputs 0 and 1 and the endpoint check T == -psi^3(B) in role 2 is the first to fire.
{ const bT = F2.div(f2(3n, 0n), f2(9n, 1n)); let Bq = null;
  for (let k = 1n; !Bq; k++) { const x = f2(k, 1n); let y; try { y = F2.sqrt(F2.add(F2.mul(F2.sqr(x), x), bT)); } catch { continue; } if (!y) continue;
    let inG2 = true; try { bn254.G2.Point.fromAffine({x, y}).assertValidity(); } catch { inG2 = false; } if (!inG2) Bq = {x, y}; }
  const st2 = {...W.st, xB: Bq.x, yB: Bq.y}; const sched2 = factorSchedule(st2);
  assert.ok(!sched2.endpoint, 'non-G2 B: the walk must not end at -psi^3(B)');
  const S2 = ROLES.map(({chunks, i}) => { const out = [];
    for (const k of chunks) { for (let e = (k ? BOUNDS[k - 1] : 0); e < BOUNDS[k]; e++) out.push(...sched2.events[e].ts.map((t) => le32(mod(t)))); out.push(...W.states[k].slice(0, 6).map((v) => le32(mod(v)))); }
    if (i === ROLES.length - 1) out.push(...sched2.tts.map((t) => le32(mod(t))));
    const b = Buffer.concat(out); assert.equal(b.length, ROLES[i].streamSize); return b; });
  const STMT2 = [Bq.x.c0, Bq.x.c1, Bq.y.c0, Bq.y.c1].reduce((b, v, j) => setWord(b, 64 + 32 * j, v), W.STMT);
  recommitted('B on the twist but outside G2 (t, DG, rho, z, handovers recomputed; states, quotient honest)', 'g2-subgroup',
    {STMT: STMT2, S: S2, core: {...W, st: st2, sched: sched2}, expect: ['accept', 'accept', 'r2:t:endpoint']});
}
// ---------------- 3. statement: GT-GLS nibbles, residue root ----------------
{ const L = STMT_LAYOUT;
  recommitted('nibble N0[30] = 0x10 (out of range)', 'gls-digit', {STMT: ((b) => { b[L.N0 + 30] = 0x10; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N1[64] = 0x80 (negative zero)', 'gls-digit', {STMT: ((b) => { b[L.N1 + 64] = 0x80; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N0[0] = 0xff', 'gls-digit', {STMT: ((b) => { b[L.N0] = 0xff; return b; })(Buffer.from(W.STMT))});
  recommitted('nibble N1[10] bit flip (in range, binding broken)', 'gls-digit', {STMT: flipAt(W.STMT, L.N1 + 10)});
  recommitted('nibble N0[50] bit flip (role 2 range)', 'gls-digit', {STMT: flipAt(W.STMT, L.N0 + 50, 2)});
  // binding-consistent alternative digits (lattice shift, still binding n0 mod r) with the old states/quotient
  { const es = W.es.map((e) => e.slice()); let ok = false;
    for (const v of LATTICE) for (const sg of [1n, -1n]) { if (ok) continue; const e2 = es[0].map((x, i) => x + sg * v[i]); if (e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { es[0] = e2; ok = true; } }
    assert.ok(ok); assert.equal(mod(es[0].reduce((a, x, i) => a + x * PI[i], 0n), r), BigInt(fx0.publicInputs[0]));
    const alt = proveCore(fx0, {es}); // a valid alternative witness (positive control below)
    const b = Buffer.from(W.STMT); alt.STMT.copy(b, L.N0, L.N0, L.N0 + 130);
    recommitted('lattice-shifted GLS digits (binding holds) with stale states and quotient', 'gls-digit', {STMT: b});
    recommitted('lattice-shifted GLS digits and states with the old quotient', 'gls-digit', {STMT: alt.STMT, S: alt.S});
  }
  recommitted('residue root s^c word 0 + 1', 'tamper-residue', {STMT: stmtWith(L.sc, word(W.STMT, L.sc) + 1n)});
  recommitted('residue root s^c word 3 + p (alias)', 'non-canonical-state', {STMT: stmtWith(L.sc + 96, word(W.STMT, L.sc + 96) + p)});
  recommitted('residue root from proof 1', 'tamper-residue', {STMT: Buffer.concat([W.STMT.subarray(0, L.sc), T1.core.STMT.subarray(L.sc)])});
}
// ---------------- 4. streams: states and inverse-norm witnesses ----------------
{ const S = (i, f) => W.S.map((x, j) => (j === i ? f(Buffer.from(x)) : x));
  // record layout per role: per chunk, the t's of its B steps then 6 state words
  const recOff = (i, k) => ROLES[i].records.slice(0, k).reduce((a, b) => a + b, 0);
  const stateOff = (i, k) => recOff(i, k) + ROLES[i].records[k] - 192;
  for (const [i, k, j] of [[0, 0, 0], [0, 11, 5], [1, 0, 2], [1, 6, 0], [2, 0, 1], [2, 8, 5]]) {
    const o = stateOff(i, k) + 32 * j;
    recommitted(`role ${i} state ${k + 1} of its range, word ${j} + 1`, 'tamper-state', {S: S(i, (b) => setWord(b, o, word(b, o) + 1n))});
  }
  recommitted('role 1 state 3 word 2 + p (alias)', 'non-canonical-state', {S: S(1, (b) => { const o = stateOff(1, 2) + 64; return setWord(b, o, word(b, o) + p); })});
  recommitted('role 2 last state word 5 = p', 'non-canonical-state', {S: S(2, (b) => setWord(b, stateOff(2, 8) + 160, p))});
  recommitted('role 0 states 2 and 3 swapped', 'tamper-state', {S: S(0, (b) => { const x = Buffer.from(b.subarray(stateOff(0, 1), stateOff(0, 1) + 192)), y = Buffer.from(b.subarray(stateOff(0, 2), stateOff(0, 2) + 192)); y.copy(b, stateOff(0, 1)); x.copy(b, stateOff(0, 2)); return b; })});
  // inverse norms: t + p (alias), t = 0, t + 1 (wrong), for a doubling (first t of role 0), an addition, the terminal ones
  const tOffs = [['role 0 first doubling t', 0, 0], ['role 1 first t (doubling)', 1, 0], ['role 0 an addition t (event 1)', 0, 64], ['role 2 terminal t_psi', 2, ROLES[2].streamSize - 64], ['role 2 terminal t_{-psi^2}', 2, ROLES[2].streamSize - 32]];
  for (const [what, i, o] of tOffs) {
    recommitted(`${what} + p (non-canonical)`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, word(b, o) + p))});
    recommitted(`${what} = 0`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, 0n))});
    recommitted(`${what} + 1 (wrong inverse)`, 'inverse-norm', {S: S(i, (b) => setWord(b, o, mod(word(b, o) + 1n)))});
  }
  recommitted('role 0 stream from proof 1', 'staple', {S: [T1.core.S[0], W.S[1], W.S[2]]});
  recommitted('role 1 stream from proof 1', 'staple', {S: [W.S[0], T1.core.S[1], W.S[2]]});
  recommitted('role 2 stream from proof 1', 'staple', {S: [W.S[0], W.S[1], T1.core.S[2]]});
  raw('role 0 stream byte flipped (DG not recommitted)', 'tamper-transcript', (P) => put(P, 'S0', flipAt(at(P, 'S0'), 300)));
  raw('role 2 stream byte flipped (DG not recommitted)', 'tamper-transcript', (P) => put(P, 'S2', flipAt(at(P, 'S2'), 300)));
}
// ---------------- 5. quotient ----------------
{ const Q = W.WQ, n = Q.length / 32;
  for (const i of [0, 1, n >> 1, n - 1]) recommitted(`Q word ${i} + 1`, 'tamper-quotient', {WQ: setWord(Q, 32 * i, word(Q, 32 * i) + 1n)});
  recommitted('Q word 3 + p (alias)', 'non-canonical-quotient', {WQ: setWord(Q, 96, word(Q, 96) + p)});
  recommitted('Q word 7 top bit set', 'non-canonical-quotient', {WQ: flipAt(Q, 7 * 32 + 31, 0x80)});
  recommitted('Q with a leading zero word (non-canonical n_q)', 'non-canonical-quotient', {WQ: Buffer.concat([Buffer.alloc(32), Q])});
  recommitted('Q missing the leading word', 'tamper-quotient', {WQ: Q.subarray(32)});
  recommitted('Q missing the last word', 'tamper-quotient', {WQ: Q.subarray(0, -32)});
  recommitted('Q padded to 133 words (over the cap)', 'quotient-cap', {WQ: Buffer.concat([Buffer.alloc(32 * (NQ_MAX + 1 - n)).fill(1, 0, 1), Q])});
  recommitted('Q length not a multiple of 32', 'quotient-cap', {WQ: Q.subarray(1)});
  recommitted('Q all zero (same length)', 'tamper-quotient', {WQ: Buffer.alloc(Q.length).fill(1, 0, 1)});
  recommitted('Q from proof 1', 'tamper-quotient', {WQ: T1.core.WQ});
  raw('Q word flipped (z not recomputed: stale handovers)', 'tamper-quotient', (P) => put(P, 'WQ', flipAt(at(P, 'WQ'), 40)));
  raw('Q empty', 'quotient-cap', (P) => put(P, 'WQ', Buffer.alloc(0)));
}
// ---------------- 6. handovers ----------------
{ for (const [k, nm] of [['H1', 'HAND_1'], ['H2', 'HAND_2']]) {
    for (const [w, wn] of [[0, 'x_T.c0'], [3, 'y_T.c1'], [4, 'F+'], [6, 'R']]) {
      raw(`${nm} ${wn} + 1`, 'handover', (P) => put(P, k, setWord(at(P, k), 32 * w, word(at(P, k), 32 * w) + 1n)));
      raw(`${nm} ${wn} + p (alias)`, 'handover', (P) => put(P, k, setWord(at(P, k), 32 * w, word(at(P, k), 32 * w) + p)));
    }
    raw(`${nm} single bit flipped`, 'handover', (P) => put(P, k, flipAt(at(P, k), 100, 0x10)));
    raw(`${nm} words shifted by one (off-by-one word)`, 'handover', (P) => { const h = at(P, k); put(P, k, Buffer.concat([h.subarray(32), h.subarray(0, 32)])); });
    raw(`${nm} from proof 1`, 'staple', (P) => put(P, k, at(clonePushes(T1), k)));
  }
}
// ---------------- 7. staples: whole inputs from another proof ----------------
for (const [label, mix] of [['input 0 from proof 1', [1, 0, 0]], ['input 1 from proof 1', [0, 1, 0]], ['input 2 from proof 1', [0, 0, 1]], ['inputs 0, 1 from proof 1', [1, 1, 0]], ['inputs 1, 2 from proof 1', [0, 1, 1]]])
  add(label, 'staple', mix.map((m, i) => (m ? T1 : T0).unlockings[i]));
// ---------------- 8. layout ----------------
{ const U = (P) => enc(P);
  for (const i of [0, 1, 2]) {
    add(`input ${i}: extra push at the bottom`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? [Buffer.from([1]), ...ps] : ps))));
    add(`input ${i}: filler push missing`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? ps.filter((_, k) => k !== PUSH['F' + i][1]) : ps))));
    add(`input ${i}: first two pushes swapped`, 'layout', U(clonePushes(T0).map((ps, j) => (j === i ? [ps[1], ps[0], ...ps.slice(2)] : ps))));
    raw(`input ${i}: filler with a nonzero byte`, 'filler', (P) => { const f = at(P, 'F' + i); assert.ok(f.length > 0); put(P, 'F' + i, flipAt(f, f.length - 1)); });
    raw(`input ${i}: filler of 0x80 bytes (BIN2NUM zero)`, 'filler', (P) => put(P, 'F' + i, Buffer.alloc(at(P, 'F' + i).length).fill(0x80)));
    raw(`input ${i}: redeem byte flipped`, 'layout', (P) => put(P, 'R' + i, flipAt(at(P, 'R' + i), 20)));
  }
  raw('input 2: filler grown so the unlocking exceeds 10,000 B', 'filler', (P) => put(P, 'F2', Buffer.alloc(at(P, 'F2').length + 10000 - T0.unlockings[2].length + 1)));
  raw('input 0: code piece byte flipped (K_code)', 'code', (P) => put(P, 'C0', flipAt(at(P, 'C0'), 123)));
  raw('input 1: code piece byte flipped (K_code)', 'code', (P) => put(P, 'C1', flipAt(at(P, 'C1'), 1234)));
  raw('input 0: delta slice byte flipped (K_DS)', 'constants', (P) => put(P, 'DS0', flipAt(at(P, 'DS0'), 999)));
  raw('input 2: delta slice byte flipped (K_DS)', 'constants', (P) => put(P, 'DS2', flipAt(at(P, 'DS2'), 64)));
  raw('input 2: DG byte flipped', 'tamper-transcript', (P) => put(P, 'DG', flipAt(at(P, 'DG'), 70)));
  // non-minimal push headers: a remote reader's offset would shift (the owner's raw-size pin and the header check reject)
  const nonMinimal = (P, i, k, op) => { const pre = P[i].slice(0, k).map((b) => Buffer.from(encodeDataPush(b))); const x = P[i][k];
    const h = op === 0x4e ? Buffer.from([0x4e, ...(() => { const l = Buffer.alloc(4); l.writeUInt32LE(x.length); return l; })()]) : Buffer.from([0x4d, x.length & 255, x.length >> 8]);
    const post = P[i].slice(k + 1).map((b) => Buffer.from(encodeDataPush(b))); return Buffer.concat([...pre, h, x, ...post]); };
  { const P = clonePushes(T0); const u = enc(P); u[1] = nonMinimal(P, 1, 1, 0x4d); add('input 1: HAND_1 pushed with a non-minimal PUSHDATA2 (remote offset shift)', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[2] = nonMinimal(P, 2, 1, 0x4e); add('input 2: STMT pushed with a non-minimal PUSHDATA4 (remote offset shift)', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[2] = nonMinimal(P, 2, 6, 0x4e); add('input 2: WQ pushed with a non-minimal PUSHDATA4', 'layout', u); }
  { const P = clonePushes(T0); const u = enc(P); u[0] = Buffer.concat([Buffer.from(encodeDataPush(P[0][0])), Buffer.from([0x61]), ...P[0].slice(1).map((b) => Buffer.from(encodeDataPush(b)))]); add('input 0: OP_NOP in the unlocking', 'layout', u); }
  // a remote header changed: input 2's HAND_2 push header replaced by a PUSHDATA2 of the same length (bytes shift by one)
  add('inputs 0 and 1 swapped (unlockings)', 'graph', [T0.unlockings[1], T0.unlockings[0], T0.unlockings[2]]);
  add('inputs 1 and 2 swapped (unlockings)', 'graph', [T0.unlockings[0], T0.unlockings[2], T0.unlockings[1]]);
}
// ---------------- 9. graph (transaction shape; local runner only) ----------------
{ add('2 inputs (input 2 missing)', 'graph', T0.unlockings.slice(0, 2), {locks: [lock, lock], bench: false});
  add('4 inputs (input 2 duplicated)', 'graph', [...T0.unlockings, T0.unlockings[2]], {locks: [lock, lock, lock, lock], bench: false});
  const foreign = Buffer.from(p2sh32(Uint8Array.of(0x51))); // P2SH32(OP_TRUE)
  add('input 2 replaced by a foreign P2SH32(OP_TRUE) input', 'graph', [T0.unlockings[0], T0.unlockings[1], Buffer.from(encodeUnlocking([Uint8Array.of(0x51)]))], {locks: [lock, lock, foreign], bench: false});
  add('a foreign P2SH32(OP_TRUE) input appended', 'graph', [...T0.unlockings, Buffer.from(encodeUnlocking([Uint8Array.of(0x51)]))], {locks: [lock, lock, lock, foreign], bench: false});
  add('input 0 replaced by a foreign P2SH32(OP_TRUE) input', 'graph', [Buffer.from(encodeUnlocking([Uint8Array.of(0x51)])), T0.unlockings[1], T0.unlockings[2]], {locks: [foreign, lock, lock], bench: false});
  // a foreign P2SH32 input at index j that carries input j's honest pushes (only the redeem differs: it drops every item
  // and leaves TRUE), so the code pieces and every remote range sit where the sibling readers expect them: the
  // sibling-locking check UTXOBYTECODE(j) == own (GRAPH instruction 8 / 12 / 16 for j = 0 / 1 / 2) must fire in both
  // siblings, and the input-count check (GRAPH instruction 2) for an appended 4th input with the same locking
  for (const j of [0, 1, 2]) {
    const n = T0.pushes[j].length - 1; const fr = Uint8Array.from([...Array(n >> 1).fill(0x6d), ...(n & 1 ? [0x75] : []), 0x51]);
    const U = T0.unlockings.slice(); U[j] = Buffer.from(encodeUnlocking([...T0.pushes[j].slice(0, -1), fr]));
    const locks = LOCKS.slice(); locks[j] = Buffer.from(p2sh32(fr));
    add(`foreign P2SH32 input at index ${j} carrying the honest pushes`, 'graph', U, {locks, bench: false,
      expect: [0, 1, 2].map((i) => (i === j ? 'foreign' : `r${i}:graph > GRAPH@${[8, 12, 16][j]}`))});
  }
  runs.find((x) => x.label === '4 inputs (input 2 duplicated)').expect = ['r0:graph > GRAPH@2', 'r1:graph > GRAPH@2', 'r2:graph > GRAPH@2', 'unlocking/redeem'];  // input 3: no role 3 (dispatch fails before GRAPH)
}

// ---------------- locate the first rejecting guard ----------------
const roleIns = [0, 1, 2].map((i) => { const c = prog.funcCodes['role' + i]; const d = decodeAuthenticationInstructions(c); const o = []; let x = 0; for (const t of d) { o.push(x); x += encodeAuthenticationInstruction(t).length; } return {n: d.length, offs: o}; });
const fnOf = new Map(); for (const [n, c] of Object.entries(prog.funcCodes)) { if (n.startsWith('role')) continue; const L = decodeAuthenticationInstructions(c).length; fnOf.set(L, fnOf.has(L) ? fnOf.get(L) + '|' + n : n); }
const marks = prog.marks.slice().sort((a, b) => a.roff - b.roff);
const guardOf = (locks, unl, input) => {
  const tr = VMS.consensus.debug(programOf(locks, unl, input)); let sec = 'unlocking/redeem', fn = '';
  for (const s of tr) { const ri = roleIns.findIndex((x) => x.n === s.instructions?.length);
    if (ri >= 0) { fn = ''; let n = 'r' + ri + ':start'; for (const m of marks) if (m.role === ri && m.roff <= roleIns[ri].offs[Math.max(0, s.ip - 1)]) n = m.name; sec = n; }
    else if (fnOf.has(s.instructions?.length)) fn = fnOf.get(s.instructions.length) + '@' + (s.ip - 1); // index of the instruction just run
    if (s.error) break; }
  return sec + (fn ? ' > ' + fn : ''); };
// ---------------- evaluate ----------------
const report = []; let acceptedAny = 0;
for (const x of runs) {
  const c = spendAll(x.locks, x.unlockings, 'consensus'), s = spendAll(x.locks, x.unlockings, 'standard');
  const accC = c.every((y) => y.accepted), accS = s.every((y) => y.accepted);
  const first = c.findIndex((y) => !y.accepted);
  const rejecting = c.map((y, i) => (y.accepted ? null : i)).filter((i) => i !== null);
  if (x.expect) { const got = x.locks.map((l, i) => (!l.equals(lock) ? 'foreign' : c[i].accepted ? 'accept' : guardOf(x.locks, x.unlockings, i)));
    const gotS = x.locks.map((l, i) => (!l.equals(lock) ? 'foreign' : s[i].accepted ? 'accept' : 'rejected'));
    assert.deepEqual(got, x.expect, 'unexpected guard: ' + x.label);
    assert.deepEqual(gotS, x.expect.map((e) => (e === 'accept' || e === 'foreign' ? e : 'rejected')), 'standard mode differs: ' + x.label); }
  report.push({label: x.label, kind: x.kind, consensus: accC, standard: accS, rejectingInputs: rejecting, expect: x.expect ?? undefined,
    reason: first >= 0 ? String(c[first].error).replace(/^.*?: /, '').slice(0, 100) : null, at: first >= 0 && x.locks[first].equals(lock) ? `input ${first}: ${guardOf(x.locks, x.unlockings, first)}` : first >= 0 ? `input ${first} (foreign)` : null, bench: x.bench});
  if (accC || accS) { acceptedAny++; console.log('ACCEPTED:', x.label); }
}
// positive controls: the honest fixture and a valid alternative (lattice-shifted) GLS witness must be accepted
const controls = [['fixture 0 (vectors)', LOCKS, T0.unlockings]];
{ const es = W.es.map((e) => e.slice()); let done = false; for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = W.es[0].map((x, i) => x + sg * v[i]); if (!done && e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) { es[0] = e2; done = true; } }
  assert.ok(done);
  const t = transactionFor(fx0, prog, {es}); controls.push(['fixture 0, lattice-shifted GLS decomposition', LOCKS, t.unlockings]); }
for (const [label, locks, u] of controls) for (const m of ['consensus', 'standard']) assert.ok(spendAll(locks, u, m).every((y) => y.accepted), 'control rejected: ' + label + ' ' + m);
const kinds = [...new Set(runs.map((x) => x.kind))];
console.log(`runs ${runs.length} (${runs.filter((x) => x.bench).length} in the bench file), accepted ${acceptedAny}; kinds: ${kinds.join(', ')}; positive controls accepted: ${controls.map((c) => c[0]).join('; ')}`);
assert.equal(acceptedAny, 0);
writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-bn254-sound-native',
  description: 'Rejection tests (constructive): statement tampering with the digest list recommitted (public-input claims with an otherwise honest witness, n + r and top-bit encodings, off-curve/off-twist/identity/negated points, +p coordinate aliases, GT-GLS nibble range/negative zero/bit flips, lattice-shifted digits with stale identities, residue root), stream tampering (states, +p aliases, swapped states, inverse-norm witnesses t + p, t = 0, wrong t, terminal t), quotient words/aliases/length/cap/leading zero, handover words (+1, +p alias, bit flip, shifted, another proof), whole-input and per-item staples from a second valid proof, and layout (extra/missing/swapped pushes, nonzero or 0x80 filler, redeem/code/delta-slice bytes, non-minimal pushes that shift remote offsets, a non-push opcode, swapped inputs). Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bn254/bn-native-sound/redteam.mjs',
  lockingSha256: LOCKS.map((l) => createHash('sha256').update(l).digest('hex')),
  runs: runs.filter((x) => x.bench).map((x) => ({label: x.label, kind: x.kind, patches: x.unlockings.map((u, i) => (u.equals(T0.unlockings[i]) ? null : {input: i, unlocking: u.toString('hex')})).filter(Boolean)})),
}, null, 1) + '\n');
if (reportPath) writeFileSync(reportPath, JSON.stringify({runs: report, controls: controls.map((c) => c[0])}, null, 1) + '\n');
