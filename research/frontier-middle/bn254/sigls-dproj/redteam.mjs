// Red-team (rejection) suite for the SI-GLS verifier: every run below must be REJECTED by the bch-spec VM in
// consensus AND standard mode. Adaptive cases rebuild a fully consistent witness for the false statement with
// the prover's forge mode (fresh transcript, states, residue root and floor quotients), so a rejection cannot
// come from a stale hash; byte-level cases tamper one push class at a time.
//   node redteam.mjs vectors.json redteam.json [report.json]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {FIXTURES, p, r, mod, F2, f2, B_TWIST, PI, GLS_OFFSET, LATTICE, glsDecompose} from './math.mjs';
import {prove, WS_LAYOUT, WS_SIZE, NSTATES, NQ_MAX, le32, rdle, verifyValues} from './protocol.mjs';
import {redeem, locking} from './transaction.mjs';
import {encodeUnlocking, spend, programOf, VMS} from './vm.mjs';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildRedeem} from './script.mjs';
import {encodeDataPush} from '@bitauth/libauth';

const [vecPath, outPath, reportPath] = process.argv.slice(2);
// a lattice shift of e_0 that keeps every u in range (an alternative, equally valid GT-GLS decomposition)
const latticeShift = (e) => { for (const v of LATTICE) for (const sg of [1n, -1n]) { const e2 = e.map((x, i) => x + sg * v[i]); if (e2.every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) return e2; } throw new Error('no in-range lattice shift'); };
assert.ok(vecPath && outPath, 'usage: node redteam.mjs vectors.json redteam.json [report.json]');
const vectors = JSON.parse(readFileSync(vecPath, 'utf8'));
assert.equal(vectors.steps[0].locking, locking.toString('hex'), 'vectors target a different locking');
const fx0 = FIXTURES.fixtures[0], fx1 = FIXTURES.fixtures[1];
const W0 = prove(fx0), W1 = prove(fx1);
const runs = [];
const add = (label, kind, unlocking) => runs.push({label, kind, unlocking: Buffer.from(unlocking)});
const std = (WQ, WS, R = redeem) => encodeUnlocking([WQ, WS, R]);
const flipAt = (b, i, m = 1) => { const c = Buffer.from(b); c[i] ^= m; return c; };
const setWord = (b, off, v) => { const c = Buffer.from(b); le32(v).copy(c, off); return c; };
const word = (b, off) => rdle(b, off);
const L = WS_LAYOUT, S0 = L.states;
const proofOf = (fx) => ({proof: JSON.parse(JSON.stringify(fx.proof)), publicInputs: [...fx.publicInputs]});
const forged = (fx, opts = {}) => { const w = prove(fx, {forge: true, ...opts}); return std(w.WQ, w.WS); };

// ---------------- 1. forged statements with adaptively rebuilt witnesses ----------------
{ const n0 = BigInt(fx0.publicInputs[0]), n1 = BigInt(fx0.publicInputs[1]);
  for (const [label, pi] of [['n0 + 1', [n0 + 1n, n1]], ['n0 - 1', [n0 - 1n, n1]], ['n1 + 1', [n0, n1 + 1n]], ['n0 = 0', [0n, n1]], ['n0, n1 swapped', [n1, n0]], ['n0 := fixture 1 n0', [BigInt(fx1.publicInputs[0]), n1]]]) {
    const f = proofOf(fx0); f.publicInputs = pi.map(String); add(`forged ${label} (rebuilt witness)`, 'forged-public-inputs', forged(f));
  }
  // the honest witness for the claim n0 + r (non-canonical alias of n0): the GLS binding holds mod r, the range check rejects
  add('n0 + r (non-canonical alias, honest witness otherwise)', 'forged-public-inputs', std(W0.WQ, setWord(W0.WS, L.n0, n0 + r)));
  add('n1 + r (non-canonical alias)', 'forged-public-inputs', std(W0.WQ, setWord(W0.WS, L.n1, n1 + r)));
  add('n0 with the top bit set (negative under signed decoding)', 'public-input-encoding', std(W0.WQ, flipAt(W0.WS, L.n0 + 31, 0x80)));
  add('n0 = 2^256 - 1', 'public-input-encoding', std(W0.WQ, setWord(W0.WS, L.n0, (1n << 256n) - 1n)));
  // rebuilt witness for n0 + r: the binding and every identity are honest for n0, only the encoding is the alias
  { const w = prove(fx0, {forge: true}); add('n0 + r with a rebuilt transcript', 'forged-public-inputs', std(w.WQ, setWord(w.WS, L.n0, n0 + r))); }
  // proof of fixture 1 under the public inputs of fixture 0 (and vice versa), rebuilt
  { const f = proofOf(fx1); f.publicInputs = [...fx0.publicInputs]; add('proof 1 with public inputs 0 (rebuilt)', 'forged-public-inputs', forged(f)); }
}
// ---------------- 2. proof points ----------------
{ const a = proofOf(fx0);
  // -A (on-curve, in G1), rebuilt
  { const f = proofOf(fx0); f.proof.a.y = mod(-BigInt(f.proof.a.y)).toString(); add('A negated (rebuilt)', 'invalid-proof-point', forged(f)); }
  { const f = proofOf(fx0); f.proof.c.y = mod(-BigInt(f.proof.c.y)).toString(); add('C negated (rebuilt)', 'invalid-proof-point', forged(f)); }
  { const f = proofOf(fx0); f.proof.b.y = {c0: mod(-BigInt(f.proof.b.y.c0)).toString(), c1: mod(-BigInt(f.proof.b.y.c1)).toString()}; add('B negated (rebuilt)', 'invalid-proof-point', forged(f)); }
  { const f = proofOf(fx0); f.proof.a = JSON.parse(JSON.stringify(fx1.proof.a)); add('A from proof 1 (rebuilt)', 'invalid-proof-point', forged(f)); }
  // off-curve (byte level, honest transcript otherwise)
  for (const [label, off, d] of [['A.x + 1 (off curve)', 0, 1n], ['A.y + 1', 32, 1n], ['B.x.c0 + 1 (off twist)', 64, 1n], ['B.y.c1 + 1', 160, 1n], ['C.x + 1', 192, 1n], ['C.y + 1', 224, 1n]])
    add(label, 'invalid-proof-point', std(W0.WQ, setWord(W0.WS, off, word(W0.WS, off) + d)));
  // +p aliases (non-canonical, same point mod p)
  for (const [label, off] of [['A.x + p', 0], ['A.y + p', 32], ['B.x.c1 + p', 96], ['B.y.c0 + p', 128], ['C.x + p', 192], ['C.y + p', 224]])
    add(label + ' (alias)', 'non-canonical-coordinate', std(W0.WQ, setWord(W0.WS, off, word(W0.WS, off) + p)));
  add('A.x + p (alias) with a rebuilt transcript', 'non-canonical-coordinate', (() => { const w = prove(fx0, {forge: true}); return std(w.WQ, setWord(w.WS, 0, word(w.WS, 0) + p)); })());
  // identity encodings
  add('A = (0, 0)', 'invalid-proof-point', std(W0.WQ, setWord(setWord(W0.WS, 0, 0n), 32, 0n)));
  add('C = (0, 0)', 'invalid-proof-point', std(W0.WQ, setWord(setWord(W0.WS, 192, 0n), 224, 0n)));
  add('B = (0, 0)', 'invalid-proof-point', std(W0.WQ, [64, 96, 128, 160].reduce((b, o) => setWord(b, o, 0n), W0.WS)));
  // B on the twist but NOT in G2 (random cofactor point), and a point of small order 10069 (exceptional steps), rebuilt
  const twistPoint = (seed) => { for (let i = 0; ; i++) { const x = f2(BigInt('0x' + createHash('sha256').update(seed + i).digest('hex')), 7n); const y2 = F2.add(F2.mul(F2.sqr(x), x), B_TWIST); try { const y = F2.sqrt(y2); if (y) return bn254.G2.Point.fromAffine({x, y}); } catch {} } };
  const mulAny = (P, k) => { let R = bn254.G2.Point.ZERO, Q = P; while (k > 0n) { if (k & 1n) R = R.add(Q); Q = Q.double(); k >>= 1n; } return R; }; // any scalar, any twist point
  const asB = (P) => { const q = P.toAffine(); return {x: {c0: q.x.c0.toString(), c1: q.x.c1.toString()}, y: {c0: q.y.c0.toString(), c1: q.y.c1.toString()}}; };
  { const P = twistPoint('nonsub'); assert.ok(!mulAny(P, r).equals(bn254.G2.Point.ZERO)); const f = proofOf(fx0); f.proof.b = asB(P); add('B on the twist, not in G2 (rebuilt)', 'subgroup', forged(f)); }
  { const h2 = 2n * p - r; let P; for (let i = 0; ; i++) { P = mulAny(twistPoint('small' + i), r * (h2 / 10069n)); if (!P.equals(bn254.G2.Point.ZERO)) break; }
    assert.ok(mulAny(P, 10069n).equals(bn254.G2.Point.ZERO)); const f = proofOf(fx0); f.proof.b = asB(P); add('B of order 10069 (exceptional add/doubling; Z = 0 absorbing) (rebuilt)', 'subgroup', forged(f)); }
  { const P = twistPoint('nonsub2').add(bn254.G2.Point.fromAffine({x: f2(BigInt(fx0.proof.b.x.c0), BigInt(fx0.proof.b.x.c1)), y: f2(BigInt(fx0.proof.b.y.c0), BigInt(fx0.proof.b.y.c1))}));
    const f = proofOf(fx0); f.proof.b = asB(P); add('B + cofactor point (rebuilt)', 'subgroup', forged(f)); }
}
// ---------------- 3. transcript fields, states, residue root ----------------
{ for (const off of [0, 100, 255]) add(`statement byte ${off}`, 'tamper-transcript', std(W0.WQ, flipAt(W0.WS, off)));
  for (const k of [0, 1, 16, 31, 32]) for (const j of [0, 5]) add(`state ${k + 1} word ${j} + 1`, 'tamper-state', std(W0.WQ, setWord(W0.WS, S0 + 192 * k + 32 * j, word(W0.WS, S0 + 192 * k + 32 * j) + 1n)));
  add('state 9 word 2 + p (alias)', 'non-canonical-state', std(W0.WQ, setWord(W0.WS, S0 + 192 * 8 + 64, word(W0.WS, S0 + 192 * 8 + 64) + p)));
  add('state 33 word 5 = p', 'non-canonical-state', std(W0.WQ, setWord(W0.WS, S0 + 192 * 32 + 160, p)));
  add('state 2 word 0 top bit set', 'non-canonical-state', std(W0.WQ, flipAt(W0.WS, S0 + 192 + 31, 0x80)));
  { const b = Buffer.from(W0.WS); b.copy(b, S0 + 192 * 4, S0 + 192 * 5, S0 + 192 * 6); W0.WS.copy(b, S0 + 192 * 5, S0 + 192 * 4, S0 + 192 * 5); add('states 5 and 6 swapped', 'tamper-state', std(W0.WQ, b)); }
  { const b = Buffer.from(W0.WS); W1.WS.copy(b, S0, S0, S0 + 192 * NSTATES); add('all states from proof 1', 'tamper-state', std(W0.WQ, b)); }
  add('residue root s^c word 0 + 1', 'tamper-residue', std(W0.WQ, setWord(W0.WS, L.sc, word(W0.WS, L.sc) + 1n)));
  add('residue root s^c word 3 + p (alias)', 'non-canonical-state', std(W0.WQ, setWord(W0.WS, L.sc + 96, word(W0.WS, L.sc + 96) + p)));
  // injective encoding: move one byte across a field boundary (same total length)
  { const b = Buffer.concat([W0.WS.subarray(0, S0 + 191), Buffer.from([W0.WS[S0 + 192]]), Buffer.from([W0.WS[S0 + 191]]), W0.WS.subarray(S0 + 193)]); add('bytes swapped across the state 1 / state 2 boundary', 'transcript-encoding', std(W0.WQ, b)); }
  { const b = Buffer.concat([W0.WS.subarray(0, L.sc), W0.WS.subarray(L.sc + 1, L.sc + 192), Buffer.from([0]), W0.WS.subarray(L.sc + 192)]); add('residue root shifted by one byte (re-parse)', 'transcript-encoding', std(W0.WQ, b)); }
  add('WS from proof 0 with WQ from proof 1', 'tamper-quotient', std(W1.WQ, W0.WS));
}
// ---------------- 4. quotient words ----------------
{ const n = W0.WQ.length / 32;
  for (const i of [0, 1, n >> 1, n - 1]) add(`Q word ${i} + 1`, 'tamper-quotient', std(setWord(W0.WQ, 32 * i, word(W0.WQ, 32 * i) + 1n), W0.WS));
  add('Q word 3 + p (alias)', 'non-canonical-quotient', std(setWord(W0.WQ, 96, word(W0.WQ, 96) + p), W0.WS));
  add('Q word 7 top bit set', 'non-canonical-quotient', std(flipAt(W0.WQ, 7 * 32 + 31, 0x80), W0.WS));
  add('Q with a leading zero word (non-canonical n_q)', 'non-canonical-quotient', std(Buffer.concat([Buffer.alloc(32), W0.WQ]), W0.WS));
  add('Q missing the leading word', 'tamper-quotient', std(W0.WQ.subarray(32), W0.WS));
  add('Q missing the last word', 'tamper-quotient', std(W0.WQ.subarray(0, -32), W0.WS));
  add('Q padded to 133 words (over the cap)', 'quotient-cap', std(Buffer.concat([Buffer.alloc(32 * (NQ_MAX + 1 - n)).fill(1, 0, 1), W0.WQ]), W0.WS));
  add('Q length not a multiple of 32', 'quotient-cap', std(W0.WQ.subarray(1), W0.WS));
  add('Q empty', 'quotient-cap', std(Buffer.alloc(0), W0.WS));
  add('Q all zero', 'tamper-quotient', std(Buffer.alloc(W0.WQ.length).fill(1, 0, 1), W0.WS));
  // reviewer fix 4: a prover deriving rho with a signed SHA256 -> Fp conversion (wrong rho, wrong Q aggregate)
  { const h = createHash('sha256').update(Buffer.concat([createHash('sha256').update(Buffer.concat([Buffer.from('SIGLS/1'), W0.WS])).digest(), Buffer.from('rho')])).digest();
    const signedDiffers = (h[31] & 0x80) !== 0; const w = prove(fx0, {rhoSigned: true});
    if (signedDiffers) add('prover used a signed SHA256 -> Fp conversion for rho', 'challenge-derivation', std(w.WQ, w.WS));
    else { // search a valid statement whose rho digest has the top bit set (fixture 0's does not)
      for (let i = 0; i < 40; i++) { const f = proofOf(fx0); f.proof.a = JSON.parse(JSON.stringify(fx0.proof.a)); const pr = prove(FIXTURES.fixtures[1 + (i % 4)], {rhoSigned: true}); const pr2 = prove(FIXTURES.fixtures[1 + (i % 4)]); if (!pr.WQ.equals(pr2.WQ)) { add(`prover used a signed SHA256 -> Fp conversion for rho (fixture ${1 + (i % 4)})`, 'challenge-derivation', std(pr.WQ, pr.WS)); break; } } } }
}
// ---------------- 5. GT-GLS digits ----------------
{ add('nibble N0[30] = 0x10 (out of range)', 'gls-digit', std(W0.WQ, ((b) => { b[L.N0 + 30] = 0x10; return b; })(Buffer.from(W0.WS))));
  add('nibble N1[64] = 0x80 (negative zero)', 'gls-digit', std(W0.WQ, ((b) => { b[L.N1 + 64] = 0x80; return b; })(Buffer.from(W0.WS))));
  add('nibble N0[0] = 0xff', 'gls-digit', std(W0.WQ, ((b) => { b[L.N0] = 0xff; return b; })(Buffer.from(W0.WS))));
  add('nibble N1[10] bit flip', 'gls-digit', std(W0.WQ, flipAt(W0.WS, L.N1 + 10)));
  // reviewer fix 5: binding-consistent digits that the loop does not use. Shift e_0 by a lattice vector (binding still
  // holds mod r) but keep the old states/quotient: the identities are then for different factors -> rejected.
  { const es = W0.es.map((e) => e.slice()); es[0] = latticeShift(es[0]);
    assert.equal(mod(es[0].reduce((a, x, i) => a + x * PI[i], 0n), r), mod(BigInt(fx0.publicInputs[0]), r));
    if (es[0].every((x) => x >= -GLS_OFFSET && x < GLS_OFFSET)) {
      const alt = prove(fx0, {es}); // a VALID alternative witness (positive control, checked below)
      const b = Buffer.from(W0.WS); alt.WS.copy(b, L.N0, L.N0, L.N0 + 130);
      add('lattice-shifted GLS digits (binding holds) with stale states/quotient', 'gls-digit', std(W0.WQ, b));
      add('lattice-shifted GLS digits with the states of the alternative witness but the old quotient', 'gls-digit', std(W0.WQ, alt.WS));
    } }
  // digits for n0 + 1 (binding for the forged claim) with the honest transcript otherwise
  { const es = [glsDecompose(BigInt(fx0.publicInputs[0]) + 1n), W0.es[1]]; const w = prove({...fx0, publicInputs: [(BigInt(fx0.publicInputs[0]) + 1n).toString(), fx0.publicInputs[1]]}, {forge: true, es});
    add('digits and n0 for n0 + 1 (rebuilt)', 'gls-digit', std(w.WQ, w.WS)); }
  // binding off by one sub-scalar unit (e_{0,1} + 1) with a rebuilt witness
  { const es = W0.es.map((e) => e.slice()); es[0][1] += 1n; add('e_{0,1} + 1 (binding fails mod r) (rebuilt)', 'gls-digit', forged(fx0, {es})); }
}
// ---------------- 6. layout ----------------
{ const U = (pushes) => encodeUnlocking(pushes);
  add('extra push at the bottom', 'layout', U([Buffer.from([1]), W0.WQ, W0.WS, redeem]));
  add('extra push between WQ and WS', 'layout', U([W0.WQ, Buffer.from([1]), W0.WS, redeem]));
  add('WQ missing', 'layout', U([W0.WS, redeem]));
  add('WQ and WS swapped', 'layout', U([W0.WS, W0.WQ, redeem]));
  add('WS one byte short', 'layout', std(W0.WQ, W0.WS.subarray(0, -1)));
  add('WS one byte long', 'layout', std(W0.WQ, Buffer.concat([W0.WS, Buffer.from([0])])));
  add('WS + WQ as one push', 'layout', U([Buffer.concat([W0.WS, W0.WQ]), redeem]));
  add('redeem byte flipped', 'layout', std(W0.WQ, W0.WS, flipAt(redeem, 5000)));
  // non-push opcode and non-minimal push in the unlocking
  add('OP_NOP in the unlocking', 'layout', Buffer.concat([Buffer.from(encodeDataPush(W0.WQ)), Buffer.from([0x61]), Buffer.from(encodeDataPush(W0.WS)), Buffer.from(encodeDataPush(redeem))]));
  { const nm = Buffer.concat([Buffer.from([0x4e]), (() => { const l = Buffer.alloc(4); l.writeUInt32LE(W0.WQ.length); return l; })(), W0.WQ]); add('WQ pushed with a non-minimal PUSHDATA4', 'layout', Buffer.concat([nm, Buffer.from(encodeDataPush(W0.WS)), Buffer.from(encodeDataPush(redeem))])); }
}

// ---------------- locate the failing guard (section of the redeem, or the function the VM was in) ----------------
const {info} = buildRedeem(); assert.ok(Buffer.from(buildRedeem().redeem).equals(redeem), 'redeem.hex is stale: run build.mjs');
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const marks = info.marks.slice().sort((a, b) => a.off - b.off);
const NEXT = {'end:init': 'transcript/size checks', 'end:transcript': 'parse + range/curve checks', 'end:parse+checks': 'powers', 'end:powers': 'GLS tables', 'end:gls-tables': 'loop setup', 'end:loop-setup': 'loop', 'end:loop': 'terminal (endpoint, binding)', 'end:terminal': 'quotient (Horner)', 'end:final': 'cleanup', bnd: 'loop: state boundary'};
const guardOf = (u) => {
  const tr = VMS.consensus.debug(programOf(locking, u)); let last = 'p2sh/unlocking', lastMain = '';
  for (const st of tr) { if (st.instructions?.length === ins.length) { let n = 'prologue'; for (const m of marks) if (m.off <= offs[Math.max(0, st.ip - 1)]) n = m.name; lastMain = NEXT[n] ?? n; last = lastMain; } else if (lastMain) last = lastMain + ' > function(' + (st.instructions?.length ?? 0) + ' instr)'; if (st.error) break; }
  return last; };
// ---------------- evaluate: every run must be rejected in both modes ----------------
const report = []; let acceptedAny = 0;
for (const x of runs) {
  const c = spend(locking, x.unlocking, 'consensus'), s = spend(locking, x.unlocking, 'standard');
  const why = (c.error ?? '').replace(/^.*?: /, '').slice(0, 110);
  report.push({label: x.label, kind: x.kind, consensus: c.accepted, standard: s.accepted, reason: why, at: why.includes('Unsuccessful') ? 'final identity (result false)' : why.includes('P2SH') || why.includes('push') ? 'transaction rules' : guardOf(x.unlocking)});
  if (c.accepted || s.accepted) { acceptedAny++; console.log('ACCEPTED:', x.label); }
}
// positive controls: the honest fixture and a valid alternative (lattice-shifted) GLS witness must be accepted
const controls = [['fixture 0', std(W0.WQ, W0.WS)]];
{ const es = W0.es.map((e) => e.slice()); es[0] = latticeShift(es[0]); const w = prove(fx0, {es}); controls.push(['fixture 0, lattice-shifted GLS decomposition', std(w.WQ, w.WS)]); }
for (const [label, u] of controls) { for (const m of ['consensus', 'standard']) assert.ok(spend(locking, u, m).accepted, 'control rejected: ' + label + ' ' + m); }
const kinds = [...new Set(runs.map((x) => x.kind))];
console.log(`runs ${runs.length}, accepted ${acceptedAny}; kinds: ${kinds.join(', ')}; positive controls accepted: ${controls.map((c) => c[0]).join('; ')}`);
assert.equal(acceptedAny, 0);
writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-sound-si-gls-single',
  description: 'Forged statements with adaptively rebuilt witnesses (fresh transcript, states, residue root, floor quotients), non-canonical encodings (coordinate +p, n + r, top-bit words, state/quotient aliases), invalid and off-subgroup proof points (including a small-order B that makes the projective trajectory hit Z = 0), transcript re-parses, quotient length/cap, GT-GLS digit attacks (range, negative zero, lattice-shifted digits with stale identities, binding off by one), a signed challenge derivation, and layout mutations. Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bn254/sound-si-gls/redteam.mjs',
  lockingSha256: [createHash('sha256').update(locking).digest('hex')],
  runs: runs.map((x) => ({label: x.label, kind: x.kind, patches: [{input: 0, unlocking: x.unlocking.toString('hex')}]})),
}, null, 1) + '\n');
if (reportPath) writeFileSync(reportPath, JSON.stringify({runs: report, controls: controls.map((c) => c[0])}, null, 1) + '\n');
