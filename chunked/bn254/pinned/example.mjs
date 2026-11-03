// Track 12: the example application end to end (CLI around pinned.mjs).
//
//   node example.mjs request <secretHex> <request.json>
//       the guest input for the example statement (INSTANCE, the example outputs); feed it to
//       guest/sp1/script (`prove`) or guest/risc0/host (`prove`), which write proof.json
//   node example.mjs pin <key> <proof.json>
//       the covenant pinned to proof.json's program (SP1 programVKey / RISC Zero image id) and INSTANCE:
//       locking bytecode and cashaddr to fund with 3 UTXOs
//   node example.mjs spend <key> <proof.json> <utxos.json> [tx.json]
//       the spending transaction. The outputs are DECODED from proof.json's public values (PV) and the covenant
//       rebuilds PV from them on chain; the builder refuses a PV for another instance or a proof for another program.
//       utxos.json: [{"txid": "<display hex>", "vout": 0, "valueSatoshis": "200000"}, x3]
//   node example.mjs test-proof <sp1|risc0> <proof.json>
//       TEST KEY ONLY: a proof.json of the example statement minted under the test key (published trapdoor), to
//       exercise `pin` / `spend` with key 'test' without a zkVM. Never deploy the test key.
//
// keys: 'sp1-v5' (SP1 v5), 'risc0-v3' (risc0-zkvm 3.0.x, released control root), 'risc0' (Track 11's pinned
// risc0-ethereum main control root), 'test'.
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {openPinned} from './pinned.mjs';
import {decodePV, encodePV} from './pv.mjs';
import {INSTANCE, TEST_PROGRAM_VKEY, TEST_IMAGE_ID, OUTS} from './example-params.mjs';

const [cmd, ...a] = process.argv.slice(2);
const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');
const paramsOf = (pf) => (pf.system === 'sp1' ? {system: 'sp1', programVKey: pf.programVKey, instanceId: INSTANCE} : {system: 'risc0', imageId: pf.imageId, instanceId: INSTANCE});
const proofOf = (pf) => pf.proof ?? (pf.system === 'sp1' ? pf.proofHex : pf.sealHex);
const pvOf = (pf) => Buffer.from(pf.publicValuesHex ?? pf.journalHex, 'hex');

if (cmd === 'request') {
  const [secretHex, out] = a; assert.ok(/^[0-9a-f]*$/i.test(secretHex ?? '') && out, 'request <secretHex> <request.json>');
  writeFileSync(out, JSON.stringify({secretHex, instanceId: INSTANCE, outputs: OUTS.map((o) => ({lockingHex: o.lockingBytecode, valueSatoshis: String(o.valueSatoshis)}))}, null, 1) + '\n');
  console.log(`wrote ${out}: instance ${INSTANCE.slice(0, 16)}…, ${OUTS.length} outputs; PV ${encodePV(INSTANCE, OUTS).length} B`);
} else if (cmd === 'pin') {
  const [key, pfPath] = a; const pf = readJson(pfPath); const cov = await openPinned(key, paramsOf(pf));
  console.log(JSON.stringify({key, params: cov.params, lockingHex: hex(cov.lockingBytecode), address: cov.address, codeBytes: cov.prog.code.length}, null, 1));
} else if (cmd === 'spend') {
  const [key, pfPath, utxoPath, out] = a; const pf = readJson(pfPath); const utxos = readJson(utxoPath);
  const pv = pvOf(pf); const {instanceId, outputs} = decodePV(pv);
  assert.equal(instanceId, INSTANCE, 'proof.json commits another instance id');
  const cov = await openPinned(key, paramsOf(pf));
  assert.ok(encodePV(INSTANCE, outputs).equals(pv), 'PV re-encodes exactly');
  const s = cov.buildSpend({proof: proofOf(pf), outputs, utxos});
  const res = {txid: s.txid, bytes: s.bytes, feeSatoshis: s.fee.toString(), unlocking: s.unlockings.map((u) => u.length), publicInputs: s.publicInputs, hex: s.hex};
  if (out) writeFileSync(out, JSON.stringify(res, null, 1) + '\n');
  // check the finished transaction with libauth (consensus + standard) before handing it out
  for (const m of ['consensus', 'standard']) { const v = cov.K.vm.VMS[m].verify({sourceOutputs: s.sourceOutputs, transaction: s.transaction}); assert.equal(v, true, `${m}: ${v}`); }
  console.log(`tx ${s.txid}: ${s.bytes} B, fee ${s.fee} sat, unlockings ${res.unlocking.join(' / ')} B; libauth verify: consensus + standard OK${out ? '; wrote ' + out : ''}`);
} else if (cmd === 'test-proof') {
  const [system, out] = a; assert.ok(['sp1', 'risc0'].includes(system) && out);
  const {loadKey} = await import('./keys.mjs'); const K = await loadKey('test');
  const pf = system === 'sp1' ? {system, programVKey: TEST_PROGRAM_VKEY} : {system, imageId: TEST_IMAGE_ID};
  const pv = encodePV(INSTANCE, OUTS); const {publicInputsFor} = await import('./pv.mjs');
  const [n0, n1] = publicInputsFor({...paramsOf(pf)}, OUTS);
  const minted = K.mint.mint(n0, n1, K.mint.rng('example.mjs:' + system));
  writeFileSync(out, JSON.stringify({...pf, [system === 'sp1' ? 'publicValuesHex' : 'journalHex']: hex(pv), proof: minted.proof,
    note: 'TEST KEY proof (minted with the published trapdoor of the densless fixture VK); valid only under key "test"'}, null, 1) + '\n');
  console.log(`wrote ${out} (test key, ${system})`);
} else {
  console.log('usage: request <secretHex> <request.json> | pin <key> <proof.json> | spend <key> <proof.json> <utxos.json> [tx.json] | test-proof <sp1|risc0> <proof.json>');
  process.exit(1);
}
