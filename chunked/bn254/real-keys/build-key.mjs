// Track 11: build the reviewed bn-native-sound verifier (SI-MX3, 3 inputs) for a REAL BN254 verifying key and check
// every published fixture of that key. The verifier code is bn-native-sound's, unchanged; only the VK-derived
// constants differ (../sound-si-gls/math.mjs recomputes and asserts every one of them against noble at load).
//
//   node build-key.mjs sp1-v5|risc0 [--covenant]    -> writes <key>[.cov].build.json
//
// Checks (any failure aborts):
//   - the program is built twice and must be byte-identical; R hashes exactly the concatenated code pieces;
//   - every fixture: the 33 states and the residue root equal the reviewed single-input SI-GLS prover's, and the
//     role-split value-level run equals one uninterrupted run;
//   - every fixture is accepted by libauth bch-2026 in consensus and standard mode with prover-sized fillers
//     (libauth carries the bench's OP_DEFINE body-cost patch, so these op costs are BCHN's).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export const KEYS = {'sp1-v5': 'sp1-v5.fixtures.json', risc0: 'risc0.fixtures.json'};
export function selectKey(key) {
  assert.ok(KEYS[key], 'key: ' + Object.keys(KEYS).join(' | '));
  process.env.BN_VK_FIXTURES = fileURLToPath(new URL('./' + KEYS[key], import.meta.url));
}
export async function load(key, {covenant = false} = {}) {
  selectKey(key);
  const math = await import('../sound-si-gls/math.mjs');
  const proto = await import('../bn-native-sound/protocol.mjs');
  const script = await import('../bn-native-sound/script.mjs');
  const tx = await import('../bn-native-sound/transaction.mjs');
  const vm = await import('../bn-native-sound/vm.mjs');
  let cov = null; if (covenant) cov = await import('./covenant.mjs');
  return {math, proto, script, tx, vm, cov};
}
const hex = (b) => Buffer.from(b).toString('hex');
const sha = (b) => createHash('sha256').update(b).digest('hex');
export const scoreOf = (unlockings) => unlockings.reduce((a, u) => a + u.length, 0) + 3 * 35 + 8 + 2 + 10 + 3 * 43;

if (import.meta.url === `file://${process.argv[1]}`) {
  const key = process.argv[2]; const covenant = process.argv.includes('--covenant');
  const {math, proto, script, tx, vm} = await load(key, {covenant});
  const {FIXTURES, FACTS} = math; const {proveCore, runRange, startState, zOf, zTail, CUTS, TAG, VK_DIGEST} = proto;
  const {prove: proveSI} = await import('../sound-si-gls/protocol.mjs');
  const build = covenant ? (await import('./covenant.mjs')).buildCovenantProgram : script.buildProgram;
  const b1 = build(FIXTURES), b2 = build(FIXTURES);
  assert.deepEqual(Buffer.from(b1.code), Buffer.from(b2.code), 'deterministic build (code)');
  assert.deepEqual(Buffer.from(b1.R), Buffer.from(b2.R), 'deterministic build (R)');
  const prog = b1;
  assert.deepEqual(Buffer.concat(prog.pieces.map((x) => Buffer.from(x))), Buffer.from(prog.code));
  assert.equal(sha(prog.code), Buffer.from(prog.Kcode).toString('hex'));
  const lock = tx.lockingOf(prog);
  const fixtures = [];
  const cov = covenant ? await import('./covenant.mjs') : null;
  // covenant mode: the application is fixture 0 (its program and PV length are baked); the other fixtures are valid
  // Groth16 proofs of other programs and must be REJECTED (covenant-test.mjs)
  for (const fx of covenant ? FIXTURES.fixtures.slice(0, 1) : FIXTURES.fixtures) {
    if (cov) cov.useOutputsFor(cov.pvOf(fx));
    const core = proveCore(fx); const si = proveSI(fx);
    assert.deepEqual(core.states.map((s) => s.join()), si.states.map((s) => s.join()), `${fx.id}: states equal SI-GLS`);
    assert.deepEqual(core.Sc.join(), si.Sc.join(), `${fx.id}: residue root equals SI-GLS`);
    { const z = zOf(core, zTail(0, core.WQ)); const single = runRange(core, z, 0, 65, startState(core, z));
      let s = startState(core, z); for (let i = 0; i < 3; i++) s = runRange(core, z, CUTS[i], CUTS[i + 1], s);
      assert.equal(s.R, single.R); assert.equal(s.Fp, single.Fp); assert.equal(s.Fm, single.Fm); }
    const T = tx.transactionFor(fx, prog);
    const runs = Object.fromEntries(['consensus', 'standard'].map((m) => { const r = vm.spendAll(T.unlockings.map(() => lock), T.unlockings, m); r.forEach((x, i) => assert.ok(x.accepted, `${fx.id} ${m} input ${i}: ${x.error}`)); return [m, r]; }));
    fixtures.push({id: fx.id, nq: core.nq, fills: T.fills, unlocking: T.unlockings.map((u) => u.length), unlockingTotal: T.unlockings.reduce((a, u) => a + u.length, 0),
      score: scoreOf(T.unlockings), txBytes: null,
      inputs: [0, 1, 2].map((i) => ({consensus: runs.consensus[i].opCost, standard: runs.standard[i].opCost, budget: runs.standard[i].budget,
        marginStandard: +(100 * (1 - runs.standard[i].opCost / runs.standard[i].budget)).toFixed(2), marginConsensus: +(100 * (1 - runs.consensus[i].opCost / runs.consensus[i].budget)).toFixed(2)}))});
    console.log(`${fx.id}: n_q ${core.nq}, unlocking ${T.unlockings.map((u) => u.length).join(' / ')}, op std ${runs.standard.map((x) => x.opCost).join(' / ')} (margins ${fixtures.at(-1).inputs.map((x) => x.marginStandard).join(' / ')}%)`);
  }
  const out = {key, covenant, system: FIXTURES.system, vkJsonSha256: FIXTURES.vkJsonSha256, tag: hex(TAG), vkDigest: hex(VK_DIGEST),
    codeBytes: prog.code.length, codeSha256: sha(prog.code), redeemBytes: prog.R.length, redeemHex: hex(prog.R), lockingHex: hex(lock), lockingSha256: sha(lock),
    codePieces: prog.pieces.map((x) => x.length), codePiecesHex: prog.pieces.map(hex), covenantParams: prog.covenant ?? undefined,
    libauth: '@bitauth/libauth 3.1.0-next.8 + zk-verifier-bench patches/@bitauth__libauth@3.1.0-next.8.patch (OP_DEFINE body cost)',
    fixtures, facts: FACTS};
  const name = `${key}${covenant ? '.cov' : ''}.build.json`;
  writeFileSync(new URL('./' + name, import.meta.url), JSON.stringify(out, null, 1) + '\n');
  console.log(`${key}${covenant ? ' (covenant)' : ''}: code ${prog.code.length} B sha256 ${out.codeSha256.slice(0, 16)}…; R ${prog.R.length} B; ${fixtures.length} fixtures accepted (consensus + standard); wrote ${name}`);
}
