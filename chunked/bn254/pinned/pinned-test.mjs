// Track 12: tests of the program-pinned covenant template. Plain rejection tests only (mismatched or malformed
// spends that a correct covenant must reject); nothing is searched to make a false statement pass.
//
//   node pinned-test.mjs test   [report.json]   both template systems (sp1, risc0) under the TEST key: every proof is
//                                               minted for its exact statement (mint.mjs, published trapdoor), so each
//                                               rejection below carries a VALID Groth16 proof of the statement in STMT
//                                               and only the template's binding can reject it.
//   node pinned-test.mjs sp1-v5 [report.json]   real keys (Track 11 fixtures): rejection runs only. No real proof of
//   node pinned-test.mjs risc0  [report.json]   the template statement exists (see README: proving was not possible).
//
// Every run records the verdict (libauth bch-2026, consensus and standard), the first failing input and its section
// (role 2's 'covenant' = this template), op cost per input, and the transaction (for the BCHN export).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {loadKey} from './keys.mjs';
import {openPinned} from './pinned.mjs';
import {encodePV, publicInputsFor, sha, normalizeOutputs} from './pv.mjs';
import {MASK253, splitDigest, claimDigest} from '../real-keys/claims.mjs';
import {INSTANCE, TEST_PROGRAM_VKEY, TEST_IMAGE_ID, P2PKH, OUTS} from './example-params.mjs';

const [key, outPath] = process.argv.slice(2);
const K = await loadKey(key);
const {math, proto, tx, vm, tpl, mint} = K;
const {r, g1, g2, FIXTURES} = math;
const hex = (b) => Buffer.from(b).toString('hex');
const H = (s) => sha(Buffer.from(s)).toString('hex');

// ---------------- the example application (fixed parameters, example-params.mjs) ----------------
// For the real keys the same INSTANCE is used; the pinned program is a placeholder (no guest was built).
const norm = (o) => normalizeOutputs(o);

// ---------------- runner ----------------
const runs = [];
const roleMap = (prog) => [0, 1, 2].map((i) => { const d = decodeAuthenticationInstructions(prog.funcCodes['role' + i]); const o = []; let x = 0; for (const t of d) { o.push(x); x += encodeAuthenticationInstruction(t).length; } return {n: d.length, offs: o}; });
function sectionOf(prog, locks, unl, input) {
  const roleIns = roleMap(prog); const marks = prog.marks.slice().sort((a, b) => a.roff - b.roff);
  const trace = vm.VMS.consensus.debug(vm.programOf(locks, unl, input)); let sec = 'unlocking/redeem';
  for (const s of trace) { const ri = roleIns.findIndex((x) => x.n === s.instructions?.length);
    if (ri >= 0) { let n = 'r' + ri + ':start'; for (const m of marks) if (m.role === ri && m.roff <= roleIns[ri].offs[Math.max(0, s.ip - 1)]) n = m.name; sec = n; }
    if (s.error) { const f = s.instructions?.[s.ip - 1]?.opcode; return {section: sec, failOp: f === undefined ? null : f.toString(16).padStart(2, '0')}; } }
  return {section: sec, failOp: null};
}
// outputs: normalized (+ optional token field, passed to the VM as is)
// sections: the expected rejecting inputs and their failing sections, 'input:section,...' (default for a rejection:
// '2:r2:covenant', i.e. only role 2 fails, inside the template). failOps: the expected failing opcode (hex) per rejecting
// input, 'input:op,...' (libauth names NUMEQUALVERIFY and VERIFY alike, so the opcode tells them apart); by default
// derived from `sections` with SECTION_OP; sections it does not cover (unlocking/redeem) need an explicit failOps.
// No rejection may come from a resource limit (op cost, stack item size): those are asserted absent on every run.
const RESOURCE = /operation cost|exceed|maximum|limit/i;
// observed failing opcodes per section: the statement checks in the template / graph (NUMEQUALVERIFY 9d), the public-
// input range checks (VERIFY 69), the reviewed core's transcript / handover checks (EQUALVERIFY 88)
const SECTION_OP = {covenant: '9d', graph: '9d', statement: '69', transcript: '88', post: '88'};
const opsOf = (sections) => (sections ? sections.split(',').map((x) => { const [i, , sec] = x.split(':'); assert.ok(sec in SECTION_OP, 'failOps needed for ' + x); return i + ':' + SECTION_OP[sec]; }).join(',') : '');
function run(label, kind, {prog, unlockings, outputs, expect = 'reject', system, bench = true, note, sections = expect === 'reject' ? '2:r2:covenant' : '', failOps = opsOf(sections)}) {
  const lock = tx.lockingOf(prog); const locks = unlockings.map(() => lock);
  vm.setOutputs(outputs);
  const res = Object.fromEntries(['consensus', 'standard'].map((m) => [m, vm.spendAll(locks, unlockings, m)]));
  const acc = (m) => res[m].every((x) => x.accepted);
  const rejecting = res.consensus.map((x, i) => (x.accepted ? null : {input: i, ...sectionOf(prog, locks, unlockings, i), error: String(x.error).replace(/^.*?: /, '').slice(0, 90)})).filter(Boolean);
  const r0 = {label, kind, system, expect, consensus: acc('consensus'), standard: acc('standard'), rejecting, note,
    opCost: res.standard.map((x) => x.opCost), budget: res.standard.map((x) => x.budget), unlocking: unlockings.map((u) => u.length), bench,
    tx: {lockingHex: hex(lock), unlockingsHex: unlockings.map(hex),
      outputs: outputs.map((o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: o.valueSatoshis.toString(), ...(o.token ? {token: {category: hex(o.token.category), amount: o.token.amount.toString()}} : {})}))}};
  runs.push(r0);
  const got = rejecting.map((y) => y.input + ':' + y.section).join(',');
  r0.sectionsExpected = sections; r0.sectionsOk = got === sections && rejecting.every((y) => !RESOURCE.test(y.error)) && rejecting.map((y) => y.input + ':' + y.failOp).join(',') === failOps;
  const ok = (expect === 'accept' ? r0.consensus && r0.standard : !r0.consensus && !r0.standard) && r0.sectionsOk;
  console.log(`${ok ? 'ok  ' : 'FAIL'}${r0.sectionsOk ? '' : ' (sections / ops: expected ' + sections + ' / ' + failOps + ')'} ${expect === 'accept' ? 'accept' : 'reject'} [${system}] ${label}${rejecting.length ? '  [' + rejecting.map((y) => 'input ' + y.input + ' ' + y.section + ': ' + y.error).join('; ') + ']' : ''}`);
  return r0;
}

// Groth16 re-randomization (public: needs only delta): A' = A/s, B' = s B + s t delta, C' = C + t A
const Fr = bn254.fields.Fr;
const aff1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const aff2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const scalar = (seed) => Fr.create(BigInt('0x' + createHash('sha256').update(seed).digest('hex')) % (r - 1n) + 1n);
function rerandomize(proof, seed) {
  const s = scalar(seed + ':s'), t = scalar(seed + ':t'); const A = g1(proof.a), B = g2(proof.b), C = g1(proof.c), D = g2(FIXTURES.vk.delta);
  return {a: aff1(A.multiply(Fr.inv(s))), b: aff2(B.multiply(s).add(D.multiply(Fr.mul(s, t)))), c: aff1(C.add(A.multiply(t)))};
}

// a spend of `prog` with proof `proof` whose STMT carries publicInputs (the honest prover: proveCore asserts that the
// Groth16 equation holds for exactly these inputs), fillers sized against `sizeOuts` (default: the outputs used)
function spend(prog, proof, publicInputs, sizeOuts, fills) {
  vm.setOutputs(sizeOuts);
  return tx.transactionFor({proof, publicInputs: publicInputs.map(String)}, prog, fills ? {fills} : {});
}

// STMT word patch with DG, challenges and handovers recomputed (as redteam-core.mjs's `recommitted`)
const {STMT_LAYOUT, TAG, CUTS, zOf, zTail, startState, runRange, encodeHand, toFp} = proto;
function recommitStmt(T, mutate) {
  const c = {...T.core, STMT: Buffer.from(T.core.STMT)}; mutate(c.STMT);
  c.D = Buffer.concat([proto.sha(c.S[0]), proto.sha(c.S[1]), proto.sha(c.STMT, c.S[2])]);
  c.h0 = proto.sha(TAG, c.D); c.rhoRaw = proto.sha(c.h0, Buffer.from('rho')); c.rho = toFp(c.rhoRaw);
  const z = zOf(c, zTail(T.fills[2], c.WQ)); let s = startState(c, z); const Hs = [null];
  for (let i = 0; i < 2; i++) { s = runRange(c, z, CUTS[i], CUTS[i + 1], s); Hs.push(encodeHand(s)); }
  const P = T.pushes.map((ps) => ps.map((b) => Buffer.from(b)));
  P[2][0] = c.D; P[2][1] = c.STMT; P[1][1] = Hs[1]; P[2][3] = Hs[2];
  return P.map((ps) => Buffer.from(vm.encodeUnlocking(ps)));
}
const le32 = (v) => { const b = Buffer.alloc(32); let x = v; for (let i = 0; i < 32; i++) { b[i] = Number(x & 255n); x >>= 8n; } assert.equal(x, 0n); return b; };

// ======================================================================================================================
const summary = {key, builds: {}};
const withVariants = (P) => (P.system === 'sp1' ? {programVKey: P.programVKey} : {imageId: P.imageId});
const mixes = [];
// observed with this build (recorded so that a change in WHERE mixing fails is caught): all script guards, no budget
// (the transcript / handover checks of the reviewed core: each input's commitments bind the other inputs' pieces)
const MIX_SECTIONS = {'A0 A1 B2, outputs of A': '0:r0:transcript,1:r1:transcript,2:r2:covenant', 'A0 A1 B2, outputs of B': '0:r0:transcript,1:r1:transcript',
  'B0 B1 A2, outputs of A': '0:r0:transcript,1:r1:transcript', 'A0 B1 A2, outputs of A': '0:r0:post,1:r1:transcript',
  "A0 A1 A'2 (A' = same statement, re-randomized proof)": '0:r0:transcript,1:r1:transcript', "A'0 A1 A2": '0:r0:transcript'};
const xorLast = (h) => h.slice(0, -2) + (parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, '0');

if (key === 'test') {
  for (const system of ['sp1', 'risc0']) {
    const P = system === 'sp1' ? {system, programVKey: TEST_PROGRAM_VKEY, instanceId: INSTANCE} : {system, imageId: TEST_IMAGE_ID, instanceId: INSTANCE};
    const prog = tpl.buildPinnedProgram(P); const prog2 = tpl.buildPinnedProgram(P);
    assert.deepEqual(Buffer.from(prog.code), Buffer.from(prog2.code), 'deterministic build');
    const O = norm(OUTS); const [n0, n1] = publicInputsFor(P, O);
    const rnd = mint.rng(`track12:${system}`); const M = (a, b) => mint.mint(a, b, rnd).proof;
    const pf = M(n0, n1); const T = spend(prog, pf, [n0, n1], O);
    const U = T.unlockings;
    recommitStmt(T, () => {}).forEach((u, i) => assert.ok(u.equals(U[i]), 'the recommit path reproduces the valid spend'));
    const go = (label, kind, extra) => run(label, kind, {prog, system, unlockings: U, outputs: O, ...extra});
    // with a proof minted for (a, b), outputs `outs` (fillers sized for them)
    const goProof = (label, kind, [a, b], outs = O, proof = M(a, b)) => run(label, kind, {prog, system, unlockings: spend(prog, proof, [a, b], outs).unlockings, outputs: outs});

    // ---- controls ----
    const c0 = go('control: proof of the exact statement (2 outputs: P2PKH payout 200,000 sat + OP_RETURN memo)', 'control', {expect: 'accept'});
    { const O1 = norm([OUTS[0]]); const s1 = publicInputsFor(P, O1); run('control: a 1-output statement (payout only), its own proof', 'control', {prog, system, expect: 'accept', unlockings: spend(prog, M(...s1), s1, O1).unlockings, outputs: O1}); }
    const pfR = rerandomize(pf, `rr:${system}`); assert.notDeepEqual(pfR, pf);
    run('control: the proof RE-RANDOMIZED (A, B, C all differ), same outputs', 'control', {prog, system, expect: 'accept', unlockings: spend(prog, pfR, [n0, n1], O).unlockings, outputs: O});
    // full-transaction validity (libauth verify, standard + consensus) of the control, as the builder would broadcast it
    { vm.setOutputs(O); const L = tx.lockingOf(prog);
      const t = {version: 2, locktime: 0, outputs: O, inputs: U.map((u, i) => ({outpointTransactionHash: Buffer.alloc(32, 0xab), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: u}))};
      const so = U.map(() => ({lockingBytecode: L, valueSatoshis: 100000n}));
      for (const m of ['consensus', 'standard']) { const v = vm.VMS[m].verify({sourceOutputs: so, transaction: t}); assert.equal(v, true, `control: full tx ${m}: ${v}`); }
      c0.fullTxVerify = 'libauth verify(): consensus true, standard true (3 × 100,000 sat inputs)'; }

    // ---- wrong program / image ----
    if (system === 'sp1') {
      const other = '0x00' + H('verifier.cash/track12/other-program').slice(2);
      goProof('valid proof of ANOTHER program (programVKey) committing the same PV', 'wrong-program', publicInputsFor({...P, programVKey: other}, O));
    } else {
      goProof('valid proof of ANOTHER image id with the same journal (PV)', 'wrong-program', publicInputsFor({...P, imageId: H('verifier.cash/track12/other-image')}, O));
    }
    { const Px = {...P, ...Object.fromEntries(Object.entries(withVariants(P)).map(([k, v]) => [k, xorLast(v)]))}; const progX = tpl.buildPinnedProgram(Px);
      assert.notDeepEqual(Buffer.from(progX.code), Buffer.from(prog.code));
      run(`covenant pinned to another ${system === 'sp1' ? 'programVKey' : 'image id'} (last byte xor 1), spent with the application's valid proof`, 'wrong-pinned-program',
        {prog: progX, system, unlockings: spend(progX, pf, [n0, n1], O).unlockings, outputs: O}); }

    // ---- wrong public values: a valid proof of another PV, the transaction keeps the outputs O ----
    const pvOf = (inst, outs) => encodePV(inst, outs);
    const inputsForPV = (pv) => (system === 'sp1' ? [BigInt(P.programVKey), BigInt('0x' + sha(pv).toString('hex')) & MASK253] : splitDigest(claimDigest(Buffer.from(P.imageId, 'hex'), pv)));
    const Ov = norm([{...OUTS[0], valueSatoshis: 200001n}, OUTS[1]]), Ol = norm([{...OUTS[0], lockingBytecode: P2PKH('22')}, OUTS[1]]);
    goProof('valid proof whose PV pays 200,001 sat (tx pays 200,000)', 'wrong-public-values', publicInputsFor(P, Ov));
    goProof('valid proof whose PV pays another locking (tx pays the original)', 'wrong-public-values', publicInputsFor(P, Ol));
    goProof('valid proof for the same outputs but ANOTHER instance id', 'wrong-public-values', publicInputsFor({...P, instanceId: H('verifier.cash/track12/other-instance')}, O));
    { const pv = pvOf(INSTANCE, O); const pvTag = Buffer.from(pv); pvTag.write('BCHPAYv2', 0, 'ascii');
      goProof('valid proof of the same PV with another tag ("BCHPAYv2")', 'wrong-public-values', inputsForPV(pvTag));
      goProof('valid proof of PV with one trailing byte appended', 'wrong-public-values', inputsForPV(Buffer.concat([pv, Buffer.from([0])])));
      // ---- pushed-digest / carrier substitution ----
      if (system === 'sp1') goProof('valid proof with n1 = sha256(PV) mod r (wrong reduction instead of the 253-bit mask)', 'digest-substitution',
        [BigInt(P.programVKey), BigInt('0x' + sha(pv).toString('hex')) % r]);
      else { const cd = claimDigest(Buffer.from(P.imageId, 'hex'), pv); const be = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
        goProof('valid proof with the claim-digest halves in big-endian order', 'digest-substitution', [be(cd.subarray(0, 16)), be(cd.subarray(16, 32))]);
        goProof('valid proof with n = splitDigest(sha256(PV)) (journal digest instead of the claim digest)', 'digest-substitution', splitDigest(sha(pv))); }
      // the application's valid proof; the transaction carries PV (or its digest) as data but pays elsewhere
      const Oalt = norm([{lockingBytecode: P2PKH('33'), valueSatoshis: 200000n}]);
      const opret = (b) => Buffer.concat([Buffer.from([0x6a]), Buffer.from(b.length <= 75 ? [b.length] : [0x4c, b.length]), b]);
      go('outputs = [OP_RETURN <PV of O>, payout to another locking] (PV as a pushed carrier)', 'digest-substitution', {outputs: norm([{lockingBytecode: opret(pv), valueSatoshis: 0n}, ...Oalt])});
      go('outputs = [OP_RETURN <sha256(PV of O)>, payout to another locking] (a pushed digest)', 'digest-substitution', {outputs: norm([{lockingBytecode: opret(sha(pv)), valueSatoshis: 0n}, ...Oalt])});
    }
    // ---- re-randomized proof with changed outputs ----
    run('re-randomized application proof, payout redirected to another locking', 're-randomized', {prog, system, unlockings: spend(prog, pfR, [n0, n1], O).unlockings, outputs: Ol});
    run('re-randomized application proof, payout value 199,999', 're-randomized', {prog, system, unlockings: spend(prog, pfR, [n0, n1], O).unlockings, outputs: norm([{...OUTS[0], valueSatoshis: 199999n}, OUTS[1]])});
    // ---- changed payout / outputs (the application's valid proof) ----
    go('payout value - 1', 'changed-outputs', {outputs: norm([{...OUTS[0], valueSatoshis: 199999n}, OUTS[1]])});
    go('payout value + 1', 'changed-outputs', {outputs: Ov});
    go('payout to another P2PKH', 'changed-outputs', {outputs: Ol});
    go('memo output data changed (last byte)', 'changed-outputs', {outputs: norm([OUTS[0], {...OUTS[1], lockingBytecode: OUTS[1].lockingBytecode.slice(0, -2) + '78'}])});
    go('memo output value 0 -> 546', 'changed-outputs', {outputs: norm([OUTS[0], {...OUTS[1], valueSatoshis: 546n}])});
    // ---- extra / missing / reordered outputs ----
    go('extra output appended (P2PKH 546 sat)', 'extra-missing-outputs', {outputs: norm([...OUTS, {lockingBytecode: P2PKH('44'), valueSatoshis: 546n}])});
    go('extra output appended (empty OP_RETURN)', 'extra-missing-outputs', {outputs: norm([...OUTS, {lockingBytecode: '6a', valueSatoshis: 0n}])});
    go('memo output missing (payout only)', 'extra-missing-outputs', {outputs: norm([OUTS[0]])});
    go('payout output missing (memo only)', 'extra-missing-outputs', {outputs: norm([OUTS[1]])});
    go('payout output duplicated', 'extra-missing-outputs', {outputs: norm([OUTS[0], OUTS[0], OUTS[1]])});
    // ---- input / output index games ----
    go('outputs swapped (memo first, payout second)', 'index-games', {outputs: norm([OUTS[1], OUTS[0]])});
    go('payout split into two outputs (100,000 + 100,000)', 'index-games', {outputs: norm([{...OUTS[0], valueSatoshis: 100000n}, {...OUTS[0], valueSatoshis: 100000n}, OUTS[1]])});
    go('inputs 0 and 2 swapped (unlockings permuted)', 'index-games', {unlockings: [U[2], U[1], U[0]], sections: '0:unlocking/redeem,1:unlocking/redeem,2:unlocking/redeem', failOps: '0:7f,1:7f,2:7f'}); // OP_SPLIT out of range
    go('inputs 0 and 1 swapped', 'index-games', {unlockings: [U[1], U[0], U[2]], sections: '0:unlocking/redeem,1:unlocking/redeem,2:unlocking/redeem', failOps: '0:88,1:88,2:88'});
    go('a 4th input (input 2 duplicated)', 'index-games', {unlockings: [U[0], U[1], U[2], U[2]], sections: '0:r0:graph,1:r1:graph,2:r2:graph,3:unlocking/redeem', failOps: '0:9d,1:9d,2:9d,3:8a'}); // input 3 fails at OP_INVOKE (8a), libauth error '0x19'
    go('only inputs 0 and 1 (2 inputs)', 'index-games', {unlockings: [U[0], U[1]], sections: '0:r0:graph,1:r1:graph'});
    go('payout output carries a fungible token (category = 32 x 0xab, amount 1)', 'index-games', {bench: false, failOps: '2:88', note: 'libauth only: on BCHN a token output with an unknown category fails the token rules before the script verdict matters',
      outputs: [{...O[0], token: {category: Buffer.alloc(32, 0xab), amount: 1n}}, O[1]]});
    // ---- change back to the covenant's own locking (a valid proof of exactly that statement): the on-chain
    //      self-payment guard (OP_VERIFY of NOT(b_k == UTXOBYTECODE(INPUTINDEX))) must reject it
    { const own = tx.lockingOf(prog);
      const Os = norm([{lockingBytecode: own, valueSatoshis: 150000n}, OUTS[1]]), Os2 = norm([OUTS[0], {lockingBytecode: own, valueSatoshis: 50000n}]);
      const sv = (l, outs) => run(l, 'self-payment', {prog, system, unlockings: spend(prog, M(...publicInputsFor(P, outs)), publicInputsFor(P, outs), outs).unlockings, outputs: outs, failOps: '2:69'}); // OP_VERIFY after EQUAL NOT: the guard, not a NUMEQUALVERIFY (9d) of the statement
      sv('valid proof whose outputs pay change back to THIS covenant (output 0)', Os);
      sv('valid proof whose outputs pay the payout + change back to THIS covenant (output 1)', Os2); }
    // ---- mixing inputs of two valid spends of this covenant ----
    { const O1 = norm([OUTS[0]]); const s1 = publicInputsFor(P, O1); const V = spend(prog, M(...s1), s1, O1).unlockings; const W = spend(prog, pfR, [n0, n1], O).unlockings;
      const mix = (label, unl, outs, sections) => run(label, 'mixing', {prog, system, unlockings: unl, outputs: outs, sections});
      mixes.push(['A0 A1 B2, outputs of A', [U[0], U[1], V[2]], O], ['A0 A1 B2, outputs of B', [U[0], U[1], V[2]], O1], ['B0 B1 A2, outputs of A', [V[0], V[1], U[2]], O],
        ['A0 B1 A2, outputs of A', [U[0], V[1], U[2]], O], ["A0 A1 A'2 (A' = same statement, re-randomized proof)", [U[0], U[1], W[2]], O], ["A'0 A1 A2", [W[0], U[1], U[2]], O]);
      for (const [l, unl, outs] of mixes.splice(0)) mix('mixed spends: ' + l, unl, outs, MIX_SECTIONS[l]); }
    // ---- spendability caps and builder preflight (unit checks, no transaction) ----
    { const many = (n, len) => Array.from({length: n}, () => ({lockingBytecode: Buffer.alloc(len, 0x51), valueSatoshis: 1000n}));
      assert.throws(() => encodePV(INSTANCE, many(97, 1)), /outputs/); encodePV(INSTANCE, many(96, 21));
      assert.throws(() => encodePV(INSTANCE, many(1, 9900)), /PV/); encodePV(INSTANCE, many(1, 9849));
      assert.throws(() => encodePV(INSTANCE, many(96, 60)), /x \|PV\|/); encodePV(INSTANCE, many(64, 60)); }
    // preflight (BEFORE proving) refuses outputs that libauth's standard verify() of the finished spend would refuse:
    // a non-OP_RETURN locking > 201 B, and OP_RETURN outputs over the 223-B data-carrier cap (sum of length + 1).
    // Each case is cross-checked against libauth verify() (standard) of the control transaction with those outputs.
    { const cov = await openPinned('test', {...P, allowTestKey: true}); const L = tx.lockingOf(prog);
      const so = U.map(() => ({lockingBytecode: L, valueSatoshis: 400000n}));
      const stdErr = (outs) => { vm.setOutputs(outs); const v = vm.VMS.standard.verify({sourceOutputs: so,
        transaction: {version: 2, locktime: 0, outputs: outs, inputs: U.map((u, i) => ({outpointTransactionHash: Buffer.alloc(32, 0xab), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: u}))}}); return String(v); };
      const opret = (n) => Buffer.concat([Buffer.from([0x6a, 0x4c, n]), Buffer.alloc(n, 0x61)]); // OP_RETURN PUSHDATA1 <n B>: n + 3 B locking
      const pre = (outs) => cov.preflight({outputs: outs, utxoTotal: 1200000n});
      const cases = [[norm([OUTS[0], {lockingBytecode: Buffer.alloc(202, 0x51), valueSatoshis: 10000n}]), /non-standard/, /non-standard/],
        [norm([OUTS[0], {lockingBytecode: opret(220), valueSatoshis: 0n}]), /data-carrier/, /arbitrary data/], // 223 + 1 B
        [norm([OUTS[0], {lockingBytecode: opret(110), valueSatoshis: 0n}, {lockingBytecode: opret(110), valueSatoshis: 0n}]), /data-carrier/, /arbitrary data/]]; // 2 x 114 B
      for (const [outs, mine, theirs] of cases) { assert.throws(() => pre(outs), mine); assert.match(stdErr(outs), theirs); }
      for (const outs of [norm([OUTS[0], {lockingBytecode: Buffer.alloc(201, 0x51), valueSatoshis: 10000n}]), norm([OUTS[0], {lockingBytecode: opret(219), valueSatoshis: 0n}])]) {
        pre(outs); assert.doesNotMatch(stdErr(outs), /non-standard|arbitrary data/); } // at the caps: standard (the script itself rejects these outputs)
      pre(O); vm.setOutputs(O); }
    // ---- public inputs >= r (honest witness, STMT word patched; DG, challenges and handovers recomputed) ----
    go('STMT n0 + r (alias)', 'public-input-range', {unlockings: recommitStmt(T, (s) => le32(n0 + r).copy(s, STMT_LAYOUT.n0)), sections: '0:r0:statement,1:r1:statement,2:r2:statement'});
    go('STMT n1 + r (alias)', 'public-input-range', {unlockings: recommitStmt(T, (s) => le32(n1 + r).copy(s, STMT_LAYOUT.n1)), sections: '0:r0:statement,1:r1:statement,2:r2:statement'});
    if (system === 'sp1') { const full = BigInt('0x' + sha(pvOf(INSTANCE, O)).toString('hex'));
      go(`STMT n1 = unmasked sha256(PV) (${full >= r ? '>= r' : '< r'})`, 'public-input-range', {unlockings: recommitStmt(T, (s) => le32(full).copy(s, STMT_LAYOUT.n1)), ...(full >= r ? {sections: '0:r0:statement,1:r1:statement,2:r2:statement'} : {})}); }
    go('STMT n1 = 2^256 - 1', 'public-input-range', {unlockings: recommitStmt(T, (s) => le32((1n << 256n) - 1n).copy(s, STMT_LAYOUT.n1)), sections: '0:r0:statement,1:r1:statement,2:r2:statement'});
    // ---- swapped inputs ----
    goProof('valid proof of the swapped statement (n1, n0)', 'swapped-inputs', [n1, n0]);
    go('application proof, STMT n0 and n1 swapped (DG recommitted)', 'swapped-inputs', {unlockings: recommitStmt(T, (s) => { le32(n1).copy(s, STMT_LAYOUT.n0); le32(n0).copy(s, STMT_LAYOUT.n1); })});

    summary.builds[system] = {params: P, codeBytes: prog.code.length, codeSha256: hex(createHash('sha256').update(prog.code).digest()), redeemBytes: prog.R.length, lockingHex: hex(tx.lockingOf(prog)),
      control: {unlocking: c0.unlocking, opCostStandard: c0.opCost, budget: c0.budget, marginStandard: c0.opCost.map((x, i) => +(100 * (1 - x / c0.budget[i])).toFixed(2)), fills: T.fills,
        txBytes: 4 + 1 + U.reduce((s, u) => s + 32 + 4 + (u.length < 253 ? 1 : 3) + u.length + 4, 0) + 1 + O.reduce((s, o) => s + 8 + 1 + o.lockingBytecode.length, 0) + 4}};
  }
} else {
  // ---------------- real keys: rejection runs only ----------------
  const system = key === 'sp1-v5' ? 'sp1' : 'risc0'; const O = norm(OUTS);
  const fxs = FIXTURES.fixtures; const app = system === 'sp1' ? {system, programVKey: TEST_PROGRAM_VKEY, instanceId: INSTANCE} : {system, imageId: TEST_IMAGE_ID, instanceId: INSTANCE};
  const progA = tpl.buildPinnedProgram(app);
  const pinOwn = (fx) => (system === 'sp1' ? {system, programVKey: fx.programVKey, instanceId: INSTANCE} : {system, imageId: fx.imageId, instanceId: INSTANCE});
  // each real proof with its OWN true statement in STMT (honest witness), under (a) the placeholder application
  // program, (b) a template pinned to that proof's own program: its PV is not of the template layout, so no
  // transaction's outputs can rebuild it (the PV tag 'BCHPAYv1' is absent), and the covenant must reject.
  for (const fx of fxs) {
    const ni = fx.publicInputs.map(BigInt);
    const pvHex = fx.publicValuesHex ?? fx.journalHex; assert.ok(!Buffer.from(pvHex, 'hex').subarray(0, 8).equals(Buffer.from('BCHPAYv1')), 'real PV is not of the template layout');
    run(`real proof ${fx.id} (true statement) under the template pinned to the placeholder application program`, 'real-wrong-program', {prog: progA, system, unlockings: spend(progA, fx.proof, ni, O).unlockings, outputs: O});
    const progO = tpl.buildPinnedProgram(pinOwn(fx));
    run(`real proof ${fx.id} under a template pinned to ITS OWN ${system === 'sp1' ? 'programVKey' : 'image id'} (its PV is not of the template layout)`, 'real-pv-layout', {prog: progO, system, unlockings: spend(progO, fx.proof, ni, O).unlockings, outputs: O});
    const rr = rerandomize(fx.proof, 'real:' + fx.id);
    run(`real proof ${fx.id} RE-RANDOMIZED, template pinned to its own program`, 'real-re-randomized', {prog: progO, system, unlockings: spend(progO, rr, ni, O).unlockings, outputs: O});
    // positive control for the re-randomization on the real key: the plain verifier core (no binding) accepts it
    if (fx === fxs[0]) { const plain = K.script.buildProgram(); vm.setOutputs([{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]);
      const Tp = tx.transactionFor({proof: rr, publicInputs: fx.publicInputs}, plain);
      run(`control: real proof ${fx.id} re-randomized, PLAIN verifier core (no application binding)`, 'real-control', {prog: plain, system, expect: 'accept', unlockings: Tp.unlockings, outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}); }
  }
  summary.builds[system] = {params: app, placeholder: 'the pinned program is a placeholder (no real guest could be built here)', codeBytes: progA.code.length,
    codeSha256: hex(createHash('sha256').update(progA.code).digest()), redeemBytes: progA.R.length, lockingHex: hex(tx.lockingOf(progA))};
}
vm.setOutputs([{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]);
const bad = runs.filter((x) => (x.expect === 'accept') !== (x.consensus && x.standard) || x.consensus !== x.standard || !x.sectionsOk);
const nA = runs.filter((x) => x.expect === 'accept').length;
console.log(`${key}: ${runs.length} runs: ${nA} accept controls accepted, ${runs.length - nA} rejections rejected${bad.length ? '; MISMATCH: ' + bad.map((x) => x.label).join(' | ') : ''}`);
for (const [s, b] of Object.entries(summary.builds)) console.log(`  ${s}: code ${b.codeBytes} B${b.control ? `, control unlocking ${b.control.unlocking.join(' / ')}, op std ${b.control.opCostStandard.join(' / ')}, margins ${b.control.marginStandard.join(' / ')}%, tx ${b.control.txBytes} B` : ''}`);
if (outPath) writeFileSync(outPath, JSON.stringify({...summary, runs}, null, 1) + '\n');
assert.equal(bad.length, 0, 'verdict mismatch');
