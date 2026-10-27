// TXv5-grading pad-slot variant of a reviewed SI-GLS bch-spec entry (BN254 or BLS12-381).
//
//   node derive.mjs <source dir> <reviewed bench vectors.json> <out prefix>
//     e.g. node derive.mjs ../bn254/sound-si-gls ../../../zk-verifier-bench/src/bch/groth16-sound-si-gls-single-vectors.json bn254
//
// Writes <out prefix>.redeem.hex, <out prefix>.json (hashes, offsets, checks) and <out prefix>-vectors.json
// (bench vector schema). The reviewed artifact (<source dir>/redeem.hex) is NOT changed; the variant is derived
// from it by exactly one instruction-level edit at the start of the code (right after the function prologue):
//
//   reviewed: DEPTH <2> NUMEQUALVERIFY          (74 52 9d)
//   variant:  DEPTH <3> NUMEQUALVERIFY DROP     (74 53 9d 75)
//
// and the unlocking gains one push, the pad, just before the redeem: <WQ> <WS> <pad> <redeem'>. The pad is the
// top stack item when the redeem starts; the variant checks the item count and DROPs it before any other
// instruction runs, so from the instruction after DROP the variant executes the reviewed program's remaining
// bytecode (byte-identical) on the same main stack [WQ, WS], the same (empty) altstack, the same function table
// (the prologue is byte-identical and runs before the edit) and the same control state. Nothing reads the pad: it
// is not hashed, picked, split or introspected (the program uses no transaction introspection and no
// ACTIVEBYTECODE). Its only effects are its own push and DROP op-cost and the unlocking length (the density
// budget), which can only turn an accept into a reject, never the reverse. The honest witnesses are exactly the
// reviewed vectors' WQ / WS pushes; only the pad and the redeem change.
//
// Checks (all asserted; the script fails otherwise):
//   - the reviewed bench vectors' locking is P2SH32 of <source dir>/redeem.hex (so the variant derives from the
//     graded artifact), and the entry pattern 74 52 9d occurs once, at build.json's prologue offset;
//   - instruction-level diff of reviewed vs variant: the decoded instruction lists are equal except that
//     [DEPTH, OP_2, NUMEQUALVERIFY] at the prologue's end becomes [DEPTH, OP_3, NUMEQUALVERIFY, DROP];
//   - no introspection opcode (0xc0..0xd3, incl. OP_ACTIVEBYTECODE) in the code or in any function body;
//   - every honest run (valid, extraValidProofs, worstCaseProof) with a 1-byte zero pad is accepted on the
//     bch-spec VM (consensus and standard);
//   - pad independence (fixture 0): pads of lengths 0, 1, 2, 75, 76, 520, 4,000 and 20,000 B, each as zeros and as
//     random bytes (and 0x01 / 0x81 single bytes, which encode as OP_1 / OP_1NEGATE), are all accepted in both
//     modes, and for each length the zero and random pads give the identical op-cost and hash-iteration count;
//   - rejection tests: no pad (two items), two pads, and the pad below WQ are rejected; every reviewed invalid
//     vector, carried over with the pad and redeem', is rejected (both modes).
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createVirtualMachineBchSpec, decodeAuthenticationInstructions, encodeDataPush, hash256} from '@bitauth/libauth';

assert.equal(process.argv.length, 5, 'usage: node derive.mjs <source dir> <reviewed vectors.json> <out prefix>');
const [srcDir, vecPath, outPrefix] = process.argv.slice(2);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const hex = (b) => Buffer.from(b).toString('hex');
const VMS = {consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true)};
const p2sh32 = (redeem) => Buffer.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
const encodeUnlocking = (pushes) => Buffer.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
const pushesOf = (unlocking) => decodeAuthenticationInstructions(unlocking).map((i) => { assert.ok('data' in i, 'unlocking is push-only'); return Buffer.from(i.data); });
const program = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
const spend = (locking, unlocking, mode) => { const vm = VMS[mode]; const p = program(locking, unlocking); const st = vm.evaluate(p);
  return {accepted: vm.verify(p) === true, opCost: st.metrics.operationCost, iters: st.metrics.hashDigestIterations}; };
const bothAccept = (locking, u) => ['consensus', 'standard'].map((m) => { const r = spend(locking, u, m); assert.ok(r.accepted, m + ' rejected'); return r; });
const bothReject = (locking, u, label) => { for (const m of ['consensus', 'standard']) assert.ok(!spend(locking, u, m).accepted, `${label}: accepted (${m})`); };

// ---- the reviewed artifact and the variant redeem ----
const R = Buffer.from(readFileSync(join(srcDir, 'redeem.hex'), 'utf8').trim(), 'hex');
const build = JSON.parse(readFileSync(join(srcDir, 'build.json'), 'utf8'));
assert.equal(R.length, build.redeemBytes); assert.equal(sha(R), build.redeemSha256, 'redeem.hex matches build.json');
const L = p2sh32(R);
const OLD = Buffer.from('74529d', 'hex'), NEW = Buffer.from('74539d75', 'hex');
const off = build.prologue;
assert.ok(R.subarray(off, off + 3).equals(OLD), 'entry check at the prologue offset');
assert.equal(R.indexOf(OLD), off); assert.equal(R.indexOf(OLD, off + 1), -1, 'entry pattern occurs once');
const RV = Buffer.concat([R.subarray(0, off), NEW, R.subarray(off + 3)]);
const LV = p2sh32(RV);
// instruction-level diff: equal except the entry check (so the edit is not inside push data)
let fnBodies = 0;
{
  const a = decodeAuthenticationInstructions(R), b = decodeAuthenticationInstructions(RV);
  const k = a.findIndex((_, i) => !(a[i].opcode === b[i].opcode && hex(a[i].data ?? []) === hex(b[i].data ?? []))) - 1; // the DEPTH before the first difference
  assert.deepEqual(a.slice(k, k + 3).map((i) => i.opcode), [0x74, 0x52, 0x9d]);
  assert.deepEqual(b.slice(k, k + 4).map((i) => i.opcode), [0x74, 0x53, 0x9d, 0x75]);
  assert.equal(b.length, a.length + 1);
  const same = (x, y) => x.length === y.length && x.every((i, j) => i.opcode === y[j].opcode && hex(i.data ?? []) === hex(y[j].data ?? []));
  assert.ok(same(a.slice(0, k), b.slice(0, k)) && same(a.slice(k + 3), b.slice(k + 4)), 'only the entry check differs');
  // no transaction introspection and no OP_ACTIVEBYTECODE (0xc0..0xd3: BCH introspection incl. token opcodes),
  // in the main code AND in every function body (the push before each <id> OP_DEFINE in the prologue)
  const scan = (ins, where) => {
    assert.ok(!ins.some((i) => i.opcode >= 0xc0 && i.opcode <= 0xd3), `introspection opcode in ${where}`);
    ins.forEach((i, j) => { if (i.opcode === 0x89) { const body = ins[j - 2]; assert.ok(body && 'data' in body, 'OP_DEFINE body is a push'); scan(decodeAuthenticationInstructions(body.data), `${where} > function ${j}`); bodies++; } });
  };
  let bodies = 0; scan(a, 'redeem'); assert.ok(bodies > 0, 'function bodies scanned');
  fnBodies = bodies;
}

// ---- carry the reviewed vectors over ----
const vec = JSON.parse(readFileSync(vecPath, 'utf8'));
const PAD = Buffer.from([0x00]);
const honestRun = (run) => run.map((s) => {
  assert.equal(s.locking, hex(L), 'reviewed vectors use the reviewed locking');
  const p = pushesOf(Buffer.from(s.unlocking, 'hex'));
  assert.equal(p.length, 3); assert.ok(p[2].equals(R));
  const u = encodeUnlocking([p[0], p[1], PAD, RV]);
  const [c, st] = bothAccept(LV, u);
  return {...s, locking: hex(LV), unlocking: hex(u), _op: [c.opCost, st.opCost]};
});
const strip = (run) => run.map(({_op, ...s}) => s);
const valid = honestRun(vec.steps);
const extra = (vec.extraValidProofs ?? []).map(honestRun);
const worst = vec.worstCaseProof ? honestRun(vec.worstCaseProof) : undefined;

// ---- pad independence (fixture 0) ----
const [WQ, WS] = pushesOf(Buffer.from(vec.steps[0].unlocking, 'hex'));
const padRows = [];
for (const n of [0, 1, 2, 75, 76, 520, 4000, 20000]) {
  const z = spend(LV, encodeUnlocking([WQ, WS, Buffer.alloc(n), RV]), 'standard');
  for (const pad of [Buffer.alloc(n), randomBytes(n)]) {
    const rs = bothAccept(LV, encodeUnlocking([WQ, WS, pad, RV]));
    assert.equal(rs[1].opCost, z.opCost, `pad content changed op-cost (len ${n})`); assert.equal(rs[1].iters, z.iters, 'pad content changed hash iterations');
  }
  padRows.push({padLen: n, opCostStandard: z.opCost, hashIters: z.iters});
}
for (const b of [0x01, 0x81, 0xff]) bothAccept(LV, encodeUnlocking([WQ, WS, Buffer.from([b]), RV]));

// ---- rejection tests ----
const step0 = vec.steps[0];
const mk = (label, pushes) => { const u = encodeUnlocking(pushes); bothReject(LV, u, label); return [{...step0, label: 'single: ' + label, locking: hex(LV), unlocking: hex(u)}]; };
const padInvalid = [mk('pad: missing (two items)', [WQ, WS, RV]), mk('pad: two pads', [WQ, WS, PAD, PAD, RV]), mk('pad: below WQ', [PAD, WQ, WS, RV])];
const carried = (vec.invalid ?? []).map((run) => run.map((s) => {
  const p = pushesOf(Buffer.from(s.unlocking, 'hex'));
  assert.equal(p.length, 3);
  let r = RV;
  if (!p[2].equals(R)) { // a tampered redeem: apply the same byte flip to redeem'
    const d = [...p[2]].map((x, i) => x ^ R[i]); const at = d.findIndex((x) => x !== 0);
    assert.equal(p[2].length, R.length); assert.equal(d.filter((x) => x !== 0).length, 1); assert.ok(at >= off + 3);
    r = Buffer.from(RV); r[at + 1] ^= d[at];
  }
  const u = encodeUnlocking([p[0], p[1], PAD, r]);
  bothReject(LV, u, s.label);
  return {...s, locking: hex(LV), unlocking: hex(u)};
}));

writeFileSync(`${outPrefix}.redeem.hex`, hex(RV) + '\n');
writeFileSync(`${outPrefix}-vectors.json`, JSON.stringify({steps: strip(valid), invalid: [...carried, ...padInvalid],
  extraValidProofs: extra.map(strip), ...(worst ? {worstCaseProof: strip(worst)} : {})}, null, 2) + '\n');
const out = {
  note: 'TXv5-grading pad-slot variant (derive.mjs); the reviewed artifact is unchanged',
  reviewed: {redeemBytes: R.length, redeemSha256: sha(R), lockingHex: hex(L), entryOffset: off, entryBytes: hex(OLD)},
  variant: {redeemBytes: RV.length, redeemSha256: sha(RV), lockingHex: hex(LV), entryBytes: hex(NEW), unlockingLayout: '<WQ> <WS> <pad> <redeem>'},
  honestRuns: {valid: valid[0]._op, extraValidProofs: extra.map((r) => r[0]._op), worstCaseProof: worst?.[0]._op, note: 'bch-spec op-cost [consensus, standard] with a 1-byte zero pad'},
  padIndependence: padRows,
  invalid: {carried: carried.length, pad: padInvalid.length},
  functionBodiesScanned: fnBodies,
  reviewedVectorsSha256: sha(readFileSync(vecPath)),
};
writeFileSync(`${outPrefix}.json`, JSON.stringify(out, null, 1) + '\n');
console.log(`${outPrefix}: redeem ${R.length} -> ${RV.length} B (${sha(RV).slice(0, 16)}), honest runs ${1 + extra.length + (worst ? 1 : 0)} accepted, invalid ${carried.length}+${padInvalid.length} rejected`);
