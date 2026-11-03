// Track 11: covenant-mode tests (plain rejection tests). The application is the key's fixture 0: its program
// (SP1 programVKey / RISC Zero image id) and its PV length are baked into role 2; PV travels in output 0.
//   node covenant-test.mjs sp1-v5|risc0 [<key>.cov.report.json]
// Every run but the control must be rejected in consensus and standard mode. Each rejected run records the input
// that fails and libauth's error.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {load} from './build-key.mjs';

const [key, outPath] = process.argv.slice(2);
const {math, tx, vm, cov} = await load(key, {covenant: true});
const {FIXTURES} = math;
const prog = cov.buildCovenantProgram(FIXTURES); const P = prog.covenant;
const lock = tx.lockingOf(prog); const LOCKS = [lock, lock, lock];
const fx0 = FIXTURES.fixtures[0], pv0 = cov.pvOf(fx0);
cov.useOutputsFor(pv0); const T0 = tx.transactionFor(fx0, prog);
// the section of role 2 where the first failing instruction sits (as in redteam-core.mjs's guardOf, role programs only)
const roleIns = [0, 1, 2].map((i) => { const d = decodeAuthenticationInstructions(prog.funcCodes['role' + i]); const o = []; let x = 0; for (const t of d) { o.push(x); x += encodeAuthenticationInstruction(t).length; } return {n: d.length, offs: o}; });
const marks = prog.marks.slice().sort((a, b) => a.roff - b.roff);
const sectionOf = (unl, input, locks = LOCKS) => { const tr = vm.VMS.consensus.debug(vm.programOf(locks, unl, input)); let sec = 'unlocking/redeem';
  for (const s of tr) { const ri = roleIns.findIndex((x) => x.n === s.instructions?.length);
    if (ri >= 0) { let n = 'r' + ri + ':start'; for (const m of marks) if (m.role === ri && m.roff <= roleIns[ri].offs[Math.max(0, s.ip - 1)]) n = m.name; sec = n; }
    if (s.error) break; }
  return sec; };
const runs = [];
const run = (label, kind, outputs, unlockings = T0.unlockings, locks = LOCKS) => {
  vm.setOutputs(outputs);
  const res = Object.fromEntries(['consensus', 'standard'].map((m) => [m, vm.spendAll(locks, unlockings, m)]));
  const acc = (m) => res[m].every((x) => x.accepted);
  runs.push({label, kind, consensus: acc('consensus'), standard: acc('standard'),
    rejecting: res.consensus.map((x, i) => (x.accepted ? null : {input: i, section: sectionOf(unlockings, i, locks), error: String(x.error).replace(/^.*?: /, '').slice(0, 90)})).filter(Boolean),
    opCost: res.standard.map((x) => x.opCost),
    tx: {lockingHex: Buffer.from(locks[0]).toString('hex'), unlockingsHex: unlockings.map((u) => Buffer.from(u).toString('hex')),
      outputs: outputs.map((o) => ({lockingHex: Buffer.from(o.lockingBytecode).toString('hex'), valueSatoshis: o.valueSatoshis.toString()}))}});
  return runs.at(-1);
};
const out = (pv) => [{lockingBytecode: cov.opReturnOf(pv), valueSatoshis: 0n}];
// ---- control ----
{ const c = run('control: application proof, output 0 = OP_RETURN <PV>', 'control', out(pv0)); assert.ok(c.consensus && c.standard, 'control rejected'); }
// ---- other real proofs: Groth16-valid under the same VK, but another program (full honest witness each) ----
for (const fx of FIXTURES.fixtures.slice(1)) {
  const pv = cov.pvOf(fx); cov.useOutputsFor(pv); const T = tx.transactionFor(fx, prog);
  if (pv.length + 3 <= 223) run(`valid proof of another program (${fx.id}, programVKey ${fx.programVKey.slice(0, 12)}…) with its own PV in output 0`, 'wrong-program', out(pv), T.unlockings);
  run(`valid proof of another program (${fx.id}) with the application's PV in output 0`, 'wrong-program', out(pv0), T.unlockings);
}
// ---- wrong public values (the application's valid proof; PV in the transaction differs) ----
{ const f = Buffer.from(pv0); f[0] ^= 1; run('PV first byte flipped (same length)', 'wrong-public-values', out(f)); }
{ const f = Buffer.from(pv0); f[f.length - 1] ^= 0x80; run('PV last byte flipped', 'wrong-public-values', out(f)); }
run('PV with one byte appended', 'wrong-public-values', out(Buffer.concat([pv0, Buffer.from([0])])));
run('PV truncated by one byte', 'wrong-public-values', out(pv0.subarray(0, -1)));
run('output 0 is a plain OP_RETURN (no PV)', 'wrong-public-values', [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]);
run('PV moved to output 1 (output 0 a plain OP_RETURN)', 'wrong-public-values', [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}, out(pv0)[0]]);
run('PV pushed with a non-minimal PUSHDATA1 header', 'wrong-public-values', [{lockingBytecode: Uint8Array.from([0x6a, 0x4c, pv0.length, ...pv0]), valueSatoshis: 0n}]);
run('output 0 = OP_RETURN <sha256(PV)> (a digest instead of the data)', 'wrong-public-values', out((await import('./claims.mjs')).sha(pv0)));
if (P.kind === 'risc0') {
  // the claim digest of an older receipt's journal under this image id (real other journals of the test receipts are
  // all the same string, so use a modified one)
  run('PV = journal with every byte xor 0x20', 'wrong-public-values', out(Buffer.from(pv0.map((b) => b ^ 0x20))));
}
// ---- a covenant pinned to another program (fix round): the application's PV length, but the pinned program
// (SP1 programVKey / RISC Zero image id) differs in its last byte; spent with the application's valid proof and PV.
// The role code (and so the locking script) differs, so the transaction is rebuilt for that program; the section map
// is the same (the covenant block has the same layout), so the failing section is read with this program's offsets.
{ const other = P.kind === 'sp1' ? {programVKey: ((h) => h.slice(0, -2) + ((parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, '0')))(P.programVKey)}
    : {imageId: ((h) => h.slice(0, -2) + ((parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, '0')))(P.imageId)};
  const progX = cov.buildCovenantProgram(FIXTURES, other); assert.notDeepEqual(Buffer.from(progX.code), Buffer.from(prog.code));
  const lockX = tx.lockingOf(progX); cov.useOutputsFor(pv0); const TX = tx.transactionFor(fx0, progX, {fills: T0.fills}); // the application's fillers (same code size)
  const r = run(`covenant pinned to another ${P.kind === 'sp1' ? 'programVKey' : 'image id'} (${Object.values(other)[0].slice(0, 12)}…, last byte xor 1), spent with the application's valid proof and PV`,
    'wrong-pinned-program', out(pv0), TX.unlockings, [lockX, lockX, lockX]);
  // sectionOf maps through prog's marks; the role-2 covenant block sits at the same offsets in progX (same instruction count)
  assert.equal(decodeAuthenticationInstructions(progX.funcCodes.role2).length, roleIns[2].n, 'same role-2 layout');
}
vm.setOutputs(out(pv0));
const bad = runs.filter((x) => x.kind !== 'control' && (x.consensus || x.standard));
for (const x of runs) console.log(`${x.consensus || x.standard ? 'ACCEPT' : 'reject'}  ${x.label}${x.rejecting.length ? '  [' + x.rejecting.map((y) => 'input ' + y.input + ' ' + y.section + ': ' + y.error).join('; ') + ']' : ''}`);
assert.equal(bad.length, 0, 'accepted: ' + bad.map((x) => x.label).join('; '));
console.log(`${key} covenant (${P.app}, |PV| ${P.pvLen}): ${runs.length - 1} rejection runs rejected, control accepted`);
if (outPath) writeFileSync(outPath, JSON.stringify({key, covenant: P, codeSha256: (await import('node:crypto')).createHash('sha256').update(prog.code).digest('hex'), runs}, null, 1) + '\n');
