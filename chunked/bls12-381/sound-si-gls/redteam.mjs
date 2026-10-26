// Rejection suite for the BLS12-381 SI-GLS verifier: every run below is a MALFORMED or INVALID input and must be
// REJECTED by the bch-spec VM in consensus AND standard mode. Constructive policy: no run is a forged statement or a
// search for an accepting invalid proof. Byte-level runs tamper one push class at a time (the transcript then no
// longer matches, and the named guard or the final identity rejects). Runs that must reach one specific guard
// (an off-G2 B, a wrong slope, x = xB at an addition) rebuild the transcript with the prover's forge mode, which
// only skips the prover's own assertions; the report names the guard that fired.
//   node redteam.mjs vectors.json redteam.json [report.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction, encodeDataPush} from '@bitauth/libauth';
import {FIXTURES, G2, p, r, F2, AX, AXPOW, smul, randomTwistPoint, FACTS, glsDigits, mint, nonCanonicalDigits} from './math.mjs';
import {prove, WS_LAYOUT, NSTATES, NSLOPES, NQ_MAX, leN, rdle, E_A} from './protocol.mjs';
import {redeem, locking} from './transaction.mjs';
import {encodeUnlocking, spend, programOf, VMS} from './vm.mjs';
import {buildRedeem} from './script.mjs';

const [vecPath, outPath, reportPath] = process.argv.slice(2);
assert.ok(vecPath && outPath, 'usage: node redteam.mjs vectors.json redteam.json [report.json]');
const vectors = JSON.parse(readFileSync(vecPath, 'utf8'));
assert.equal(vectors.steps[0].locking, locking.toString('hex'), 'vectors target a different locking');
const fx0 = FIXTURES.committed, fx1 = FIXTURES.proof1;
const W0 = prove(fx0), W1 = prove(fx1);
const runs = [];
const add = (label, kind, unlocking) => runs.push({label, kind, unlocking: Buffer.from(unlocking)});
const std = (WQ, WS, R = redeem) => encodeUnlocking([WQ, WS, R]);
const flipAt = (b, i, m = 1) => { const c = Buffer.from(b); c[i] ^= m; return c; };
const setW = (b, off, v, n = 48) => { const c = Buffer.from(b); leN(v, n).copy(c, off); return c; };
const word = (b, off, n = 48) => rdle(b, off, n);
const L = WS_LAYOUT, S0 = L.states, SL = L.slopes;
const forged = (fx, opts = {}) => { const w = prove(fx, {forge: true, ...opts}); return std(w.WQ, w.WS); };
const withB = (fx, B) => ({inputs: fx.inputs, proof: {a: fx.proof.a, b: B, c: fx.proof.c}});

// ---------------- 1. proof points: curve, twist, canonical coordinates, identity ----------------
for (const [label, off] of [['A.x + 1 (off curve)', 0], ['A.y + 1 (off curve)', 48], ['B.x.c0 + 1 (off twist)', 96], ['B.y.c1 + 1 (off twist)', 240], ['C.x + 1 (off curve)', 288], ['C.y + 1 (off curve)', 336]])
  add(label, 'invalid-proof-point', std(W0.WQ, setW(W0.WS, off, word(W0.WS, off) + 1n)));
for (const [label, off] of [['A.x + p', 0], ['A.y + p', 48], ['B.x.c0 + p', 96], ['B.x.c1 + p', 144], ['B.y.c0 + p', 192], ['B.y.c1 + p', 240], ['C.x + p', 288], ['C.y + p', 336]])
  add(label + ' (alias, same point mod p)', 'non-canonical-coordinate', std(W0.WQ, setW(W0.WS, off, word(W0.WS, off) + p)));
add('A.x + p (alias) with a rebuilt transcript', 'non-canonical-coordinate', (() => { const w = prove(fx0, {forge: true}); return std(w.WQ, setW(w.WS, 0, word(w.WS, 0) + p)); })());
add('A.y = 2^384 - 1', 'non-canonical-coordinate', std(W0.WQ, setW(W0.WS, 48, (1n << 384n) - 1n)));
// the point at infinity has no encoding: (0, 0) is off the curve (4 != 0) and off the twist
add('A = (0, 0) (identity encoding)', 'identity-point', std(W0.WQ, setW(setW(W0.WS, 0, 0n), 48, 0n)));
add('B = (0, 0) (identity encoding)', 'identity-point', std(W0.WQ, [96, 144, 192, 240].reduce((b, o) => setW(b, o, 0n), W0.WS)));
add('C = (0, 0) (identity encoding)', 'identity-point', std(W0.WQ, setW(setW(W0.WS, 288, 0n), 336, 0n)));
// B on the twist but not in G2: a random twist point, and G2 point + cofactor point (rebuilt transcripts; endpoint guard)
const twistPt = (seed) => { const t = randomTwistPoint(seed); return G2.fromAffine({x: t.x, y: t.y}); };
{ const P = twistPt(11); assert.ok(!smul(P, r).is0()); add('B on the twist, not in G2 (rebuilt)', 'subgroup', forged(withB(fx0, P))); }
{ const P = fx0.proof.b.add(smul(twistPt(12), r)); assert.ok(!smul(P, r).is0()); add('B + an r-torsion-free cofactor point (rebuilt)', 'subgroup', forged(withB(fx0, P))); }
// B of order 13 (13 | h2): at event 2 the affine walk reaches T = 12B = -B, so x = xB at the addition (rebuilt)
{ let h = BigInt(FACTS.h2); assert.equal(h % 13n, 0n); while (h % 13n === 0n) h /= 13n; // 13^2 || h2: strip the 13-part, then descend to order 13
  let P = null; for (let s = 20; !P && s < 60; s++) { let Q = smul(twistPt(s), r * h); if (Q.is0()) continue; while (!smul(Q, 13n).is0()) Q = smul(Q, 13n); P = Q; }
  assert.ok(smul(P, 13n).is0()); assert.ok(E_A > 2, 'event 2 is affine');
  add('B of order 13: x = xB at the event-2 affine addition (rebuilt)', 'subgroup', forged(withB(fx0, P))); }
// -A, -B, -C (valid points, wrong proof; rebuilt transcripts reach the final identity)
add('A negated (rebuilt)', 'invalid-proof', forged({inputs: fx0.inputs, proof: {...fx0.proof, a: fx0.proof.a.negate()}}));
add('B negated (rebuilt)', 'invalid-proof', forged(withB(fx0, fx0.proof.b.negate())));
add('C from proof 1 (rebuilt)', 'invalid-proof', forged({inputs: fx0.inputs, proof: {...fx0.proof, c: fx1.proof.c}}));

// ---------------- 2. public inputs: canonical encoding (byte level) ----------------
{ const n0 = fx0.inputs[0], n1 = fx0.inputs[1];
  add('n0 + r (non-canonical alias)', 'public-input-encoding', std(W0.WQ, setW(W0.WS, L.n0, n0 + r, 32)));
  add('n1 + r (non-canonical alias)', 'public-input-encoding', std(W0.WQ, setW(W0.WS, L.n1, n1 + r, 32)));
  add('n0 = 2^256 - 1', 'public-input-encoding', std(W0.WQ, setW(W0.WS, L.n0, (1n << 256n) - 1n, 32)));
  add('n0 with the top bit set', 'public-input-encoding', std(W0.WQ, flipAt(W0.WS, L.n0 + 31, 0x80)));
  add('n0 + 1 (byte level)', 'public-input-encoding', std(W0.WQ, setW(W0.WS, L.n0, n0 + 1n, 32)));
  add('n0, n1 swapped (byte level)', 'public-input-encoding', std(W0.WQ, setW(setW(W0.WS, L.n0, n1, 32), L.n1, n0, 32))); }

// ---------------- 3. GT-GLS nibbles ----------------
const setByte = (b, i, v) => { const c = Buffer.from(b); c[i] = v; return c; };
add('nibble N0[30] = 0x10 (> 15)', 'gls-digit', std(W0.WQ, setByte(W0.WS, L.N0 + 30, 0x10)));
add('nibble N1[63] = 0x80 (negative zero)', 'gls-digit', std(W0.WQ, setByte(W0.WS, L.N1 + 63, 0x80)));
add('nibble N0[0] = 0xff', 'gls-digit', std(W0.WQ, setByte(W0.WS, L.N0, 0xff)));
add('nibble N1[10] bit flip', 'gls-digit', std(W0.WQ, flipAt(W0.WS, L.N1 + 10)));
// a nibble change that keeps every byte <= 15, with a rebuilt transcript: the exact binding acc == n rejects
{ const dg = W0.digits.map((a) => a.slice()); dg[0][0] ^= 1n << 5n; add('digit a_{0,0} bit 5 flipped, binding off (rebuilt)', 'gls-binding', forged(fx0, {digits: dg})); }

// ---------------- 4. affine B slopes ----------------
add('slope 0 c0 + 1 (byte level)', 'slope', std(W0.WQ, setW(W0.WS, SL, word(W0.WS, SL) + 1n)));
add(`slope ${NSLOPES - 1} c1 + p (alias)`, 'non-canonical-slope', std(W0.WQ, setW(W0.WS, SL + 96 * (NSLOPES - 1) + 48, word(W0.WS, SL + 96 * (NSLOPES - 1) + 48) + p)));
{ const sl = W0.debug.sched.slopes.slice(); sl[1] = F2.add(sl[1], F2.ONE); add('slope 1 (the event-0 addition) + 1 (rebuilt)', 'slope', forged(fx0, {slopeOverride: sl})); }
{ const sl = W0.debug.sched.slopes.slice(); sl[3] = F2.neg(sl[3]); add('slope 3 negated (rebuilt)', 'slope', forged(fx0, {slopeOverride: sl})); }
{ const sl = W0.debug.sched.slopes.slice(); [sl[4], sl[5]] = [sl[5], sl[4]]; add('slopes 4 and 5 swapped (rebuilt)', 'slope', forged(fx0, {slopeOverride: sl})); }

// ---------------- 5. states, residue root, transcript encoding ----------------
for (const off of [5, 200, 400]) add(`statement byte ${off}`, 'tamper-transcript', std(W0.WQ, flipAt(W0.WS, off)));
for (const k of [0, 1, 15, NSTATES - 1]) for (const j of [0, 5]) add(`state ${k + 1} word ${j} + 1`, 'tamper-state', std(W0.WQ, setW(W0.WS, S0 + 288 * k + 48 * j, word(W0.WS, S0 + 288 * k + 48 * j) + 1n)));
add('state 9 word 2 + p (alias)', 'non-canonical-state', std(W0.WQ, setW(W0.WS, S0 + 288 * 8 + 96, word(W0.WS, S0 + 288 * 8 + 96) + p)));
add(`state ${NSTATES} word 5 = p`, 'non-canonical-state', std(W0.WQ, setW(W0.WS, S0 + 288 * (NSTATES - 1) + 240, p)));
add('state 2 word 0 top bit set', 'non-canonical-state', std(W0.WQ, flipAt(W0.WS, S0 + 288 + 47, 0x80)));
{ const b = Buffer.from(W0.WS); W0.WS.copy(b, S0 + 288 * 4, S0 + 288 * 5, S0 + 288 * 6); W0.WS.copy(b, S0 + 288 * 5, S0 + 288 * 4, S0 + 288 * 5); add('states 5 and 6 swapped', 'tamper-state', std(W0.WQ, b)); }
{ const b = Buffer.from(W0.WS); W1.WS.copy(b, S0, S0, S0 + 288 * NSTATES); add('all states from proof 1', 'tamper-state', std(W0.WQ, b)); }
add('residue root s^c word 0 + 1', 'tamper-residue', std(W0.WQ, setW(W0.WS, L.sc, word(W0.WS, L.sc) + 1n)));
add('residue root s^c word 3 + p (alias)', 'non-canonical-state', std(W0.WQ, setW(W0.WS, L.sc + 144, word(W0.WS, L.sc + 144) + p)));
{ const b = Buffer.concat([W0.WS.subarray(0, S0 + 287), Buffer.from([W0.WS[S0 + 288]]), Buffer.from([W0.WS[S0 + 287]]), W0.WS.subarray(S0 + 289)]); add('bytes swapped across the state 1 / state 2 boundary', 'transcript-encoding', std(W0.WQ, b)); }
{ const b = Buffer.concat([W0.WS.subarray(0, L.sc), W0.WS.subarray(L.sc + 1, L.sc + 288), Buffer.from([0]), W0.WS.subarray(L.sc + 288)]); add('residue root shifted by one byte (re-parse)', 'transcript-encoding', std(W0.WQ, b)); }
add('WS from proof 0 with WQ from proof 1', 'tamper-quotient', std(W1.WQ, W0.WS));

// ---------------- 6. quotient words ----------------
{ const n = W0.WQ.length / 48;
  for (const i of [0, 1, n >> 1, n - 1]) add(`Q word ${i} + 1`, 'tamper-quotient', std(setW(W0.WQ, 48 * i, word(W0.WQ, 48 * i) + 1n), W0.WS));
  add('Q word 3 + p (alias)', 'non-canonical-quotient', std(setW(W0.WQ, 144, word(W0.WQ, 144) + p), W0.WS));
  add('Q word 7 top bit set', 'non-canonical-quotient', std(flipAt(W0.WQ, 7 * 48 + 47, 0x80), W0.WS));
  add('Q with a leading zero word (non-canonical n_q)', 'non-canonical-quotient', std(Buffer.concat([Buffer.alloc(48), W0.WQ]), W0.WS));
  add('Q missing the leading word', 'tamper-quotient', std(W0.WQ.subarray(48), W0.WS));
  add('Q missing the last word', 'tamper-quotient', std(W0.WQ.subarray(0, -48), W0.WS));
  add(`Q padded to ${NQ_MAX + 1} words (over the cap)`, 'quotient-cap', std(Buffer.concat([Buffer.alloc(48 * (NQ_MAX + 1 - n)).fill(1, 0, 1), W0.WQ]), W0.WS));
  add('Q length not a multiple of 48', 'quotient-cap', std(W0.WQ.subarray(1), W0.WS));
  add('Q empty', 'quotient-cap', std(Buffer.alloc(0), W0.WS));
  add('Q all zero but a nonzero leading word', 'tamper-quotient', std(Buffer.alloc(W0.WQ.length).fill(1, 0, 1), W0.WS)); }

// ---------------- 7. layout ----------------
{ const U = (pushes) => encodeUnlocking(pushes);
  add('extra push at the bottom', 'layout', U([Buffer.from([1]), W0.WQ, W0.WS, redeem]));
  add('extra push between WQ and WS', 'layout', U([W0.WQ, Buffer.from([1]), W0.WS, redeem]));
  add('WQ missing', 'layout', U([W0.WS, redeem]));
  add('WQ and WS swapped', 'layout', U([W0.WS, W0.WQ, redeem]));
  add('WS one byte short', 'layout', std(W0.WQ, W0.WS.subarray(0, -1)));
  add('WS one byte long', 'layout', std(W0.WQ, Buffer.concat([W0.WS, Buffer.from([0])])));
  add('WS one slope short (96 B)', 'layout', std(W0.WQ, W0.WS.subarray(0, -96)));
  add('WS one slope long (96 B)', 'layout', std(W0.WQ, Buffer.concat([W0.WS, W0.WS.subarray(-96)])));
  add('WS + WQ as one push', 'layout', U([Buffer.concat([W0.WS, W0.WQ]), redeem]));
  add('redeem byte flipped', 'layout', std(W0.WQ, W0.WS, flipAt(redeem, 5000)));
  add('OP_NOP in the unlocking', 'layout', Buffer.concat([Buffer.from(encodeDataPush(W0.WQ)), Buffer.from([0x61]), Buffer.from(encodeDataPush(W0.WS)), Buffer.from(encodeDataPush(redeem))]));
  { const nm = Buffer.concat([Buffer.from([0x4e]), (() => { const l = Buffer.alloc(4); l.writeUInt32LE(W0.WQ.length); return l; })(), W0.WQ]); add('WQ pushed with a non-minimal PUSHDATA4', 'layout', Buffer.concat([nm, Buffer.from(encodeDataPush(W0.WS)), Buffer.from(encodeDataPush(redeem))])); } }

// ---------------- locate the failing guard (section of the redeem, or the function the VM was in) ----------------
const {info} = buildRedeem(); assert.ok(Buffer.from(buildRedeem().redeem).equals(redeem), 'redeem.hex is stale: run build.mjs');
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const marks = info.marks.slice().sort((a, b) => a.off - b.off);
const NEXT = {'end:init': 'transcript/size checks', 'end:transcript': 'parse + range/curve checks', 'end:parse+checks': 'powers', 'end:powers': 'GLS tables', 'end:gls-tables': 'loop setup', 'end:loop-setup': 'loop', 'end:loop': 'terminal (slope count, endpoint, binding)', 'end:terminal': 'quotient (Horner)', 'end:final': 'cleanup'};
const FN = Object.fromEntries(Object.entries(info.funcs).map(([n, len]) => [len, n]));
const bytesOf = (instrs) => instrs.reduce((a, x) => a + encodeAuthenticationInstruction(x).length, 0);
// the final evaluate state carries the call frames (controlStack): the main frame's ip names the section, the
// inner frames (and the current instruction list) name the functions the VM was in when the guard failed
const guardOf = (u) => {
  const st = VMS.consensus.evaluate(programOf(locking, u));
  const frames = [...(st.controlStack ?? []).filter((f) => typeof f === 'object' && f.instructions), {instructions: st.instructions, ip: st.ip}];
  const main = frames.findIndex((f) => f.instructions.length === ins.length); if (main < 0) return 'p2sh/unlocking';
  let n = 'prologue'; for (const m of marks) if (m.off <= offs[Math.max(0, frames[main].ip - 1)]) n = m.name;
  return [NEXT[n] ?? 'loop:' + n, ...frames.slice(main + 1).map((f) => FN[bytesOf(f.instructions)] ?? `function(${f.instructions.length} instr)`)].join(' > '); };
// ---------------- evaluate: every run must be rejected in both modes ----------------
const report = []; let acceptedAny = 0;
for (const x of runs) {
  const c = spend(locking, x.unlocking, 'consensus'), s = spend(locking, x.unlocking, 'standard');
  const why = (c.error ?? '').replace(/^.*?: /, '').slice(0, 110);
  report.push({label: x.label, kind: x.kind, consensus: c.accepted, standard: s.accepted, reason: why, at: why.includes('Unsuccessful') ? 'final identity (result false)' : why.includes('P2SH') || why.includes('push') ? 'transaction rules' : guardOf(x.unlocking)});
  if (c.accepted || s.accepted) { acceptedAny++; console.log('ACCEPTED:', x.label); }
}
// positive controls: the honest fixture, and a valid witness with NON-canonical digits (a_{0,0} + |x|, a_{0,1} - 1: the
// same n) for a statement whose digits allow it (n0 = 5 + 7|x| + 9|x|^2)
const controls = [['committed', std(W0.WQ, W0.WS)]];
{ const fx = mint([5n + 7n * AX + 9n * AX ** 2n, 456n]); const dg = nonCanonicalDigits(fx.inputs); assert.ok(dg);
  assert.equal(dg[0].reduce((s, v, i) => s + v * AXPOW[i], 0n), fx.inputs[0]); assert.notDeepEqual(dg[0], glsDigits(fx.inputs[0]));
  const w = prove(fx, {digits: dg}); controls.push(['n0 = 5 + 7|x| + 9|x|^2 with non-canonical GLS digits (a_0 + |x|, a_1 - 1)', std(w.WQ, w.WS)]); }
for (const [label, u] of controls) for (const m of ['consensus', 'standard']) assert.ok(spend(locking, u, m).accepted, 'control rejected: ' + label + ' ' + m);
const kinds = [...new Set(runs.map((x) => x.kind))];
console.log(`runs ${runs.length}, accepted ${acceptedAny}; kinds: ${kinds.join(', ')}; positive controls accepted: ${controls.map((c) => c[0]).join('; ')}`);
const byGuard = {}; for (const x of report) byGuard[x.at] = (byGuard[x.at] ?? 0) + 1; console.log(JSON.stringify(byGuard, null, 1));
assert.equal(acceptedAny, 0);
writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-bls12381-sound-si-gls-single',
  description: 'Rejection suite (malformed and invalid inputs only; no forged statements): off-curve / off-twist / identity-encoded proof points, non-canonical encodings (coordinate, slope, state, quotient +p aliases, n + r, top-bit words), B off G2 (random twist point, G2 + cofactor point, an order-13 point that makes x = xB at an affine addition), wrong / negated / swapped witnessed slopes, GT-GLS nibble range and binding, state / residue / quotient tampering, transcript re-parses, quotient length and cap, and layout mutations. Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bls12-381/sound-si-gls/redteam.mjs',
  lockingSha256: [createHash('sha256').update(locking).digest('hex')],
  runs: runs.map((x) => ({label: x.label, kind: x.kind, patches: [{input: 0, unlocking: x.unlocking.toString('hex')}]})),
}, null, 1) + '\n');
if (reportPath) writeFileSync(reportPath, JSON.stringify({runs: report, controls: controls.map((c) => c[0])}, null, 1) + '\n');
