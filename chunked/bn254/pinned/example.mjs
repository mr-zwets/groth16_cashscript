// Track 12: the example application end to end (CLI around pinned.mjs).
//
// SAFETY: the program id and INSTANCE always come from YOUR arguments, never from a proof file: pin the programVKey /
// image id printed by your own guest build (`vkey` / `imageid`), and pick a fresh random 32-byte INSTANCE per funding.
// Addresses default to the test-network prefix ('bchtest'); `--mainnet` is required for a 'bitcoincash' address.
// The built-in example values (statement, INSTANCE, secret) are public and burn the payout: they are refused unless
// `--regtest` is given.
//
//   node example.mjs example-statement <statement.json>
//       writes the example statement (REGTEST / CHIPNET ONLY: payout to an unspendable P2PKH, public INSTANCE)
//   node example.mjs request <secretHex> <statement.json> <request.json> [--regtest]
//       the guest input: statement.json = {"instanceId": "<32 B hex>", "outputs": [{"lockingHex": "..",
//       "valueSatoshis": ".."}, ..]}; feed request.json to guest/sp1/script or guest/risc0/host (`prove`)
//   node example.mjs pin <key> <programId> <instanceId> [--mainnet] [--regtest]
//       the covenant pinned to <programId> (SP1 programVKey 0x.. / RISC Zero image id) and <instanceId>: locking
//       bytecode and address. Fund it ONCE with exactly 3 UTXOs; never send change or a second funding to it.
//   node example.mjs spend <key> <programId> <instanceId> <proof.json> <utxos.json> [tx.json] [--regtest]
//       the spending transaction. The outputs are DECODED from proof.json's public values (PV); the covenant
//       rebuilds PV from them on chain. Refused: a PV for another instance, a proof.json that names another program,
//       and a proof that does not verify for the statement derived from <programId>, <instanceId> and the outputs.
//       utxos.json: [{"txid": "<display hex>", "vout": 0, "valueSatoshis": "200000"}, x3]
//   node example.mjs test-proof <sp1|risc0> <proof.json>
//       TEST KEY ONLY: a proof.json of the example statement minted under the test key (published trapdoor), to
//       exercise `pin` / `spend` with key 'test' (needs --regtest) and the test program ids printed here.
//
// keys: 'sp1-v5' (SP1 v5), 'risc0-v3' (risc0-zkvm 3.0.x, released control root), 'risc0' (Track 11's unreleased
// risc0-ethereum main control root; refused by openPinned without opt-in), 'test' (regtest only).
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {openPinned} from './pinned.mjs';
import {decodePV, encodePV} from './pv.mjs';
import {INSTANCE, TEST_PROGRAM_VKEY, TEST_IMAGE_ID, OUTS, EXAMPLE_LOCK_HASH} from './example-params.mjs';

const argv = process.argv.slice(2); const flags = new Set(argv.filter((x) => x.startsWith('--'))); const [cmd, ...a] = argv.filter((x) => !x.startsWith('--'));
const regtest = flags.has('--regtest'), mainnet = flags.has('--mainnet');
assert.ok(!(regtest && mainnet), '--regtest and --mainnet exclude each other');
const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');
const warn = (m) => console.error('WARNING: ' + m);
const systemOf = (key) => (key === 'sp1-v5' ? 'sp1' : key === 'test' ? null : 'risc0');
function paramsFor(key, programId, instanceId) {
  assert.ok(programId && /^[0-9a-f]{64}$/i.test(instanceId ?? ''), '<programId> <instanceId (32 B hex)>');
  const system = systemOf(key) ?? (programId.startsWith('0x') ? 'sp1' : 'risc0');
  if (instanceId.toLowerCase() === INSTANCE) { assert.ok(regtest, 'the example INSTANCE is public: use a fresh random 32-byte INSTANCE (or --regtest)'); warn('example INSTANCE (public), regtest only'); }
  if (key === 'test') assert.ok(regtest, "key 'test' has a public trapdoor: --regtest only");
  const prefix = mainnet ? 'bitcoincash' : regtest ? 'bchreg' : 'bchtest';
  const extra = {prefix, allowTestKey: key === 'test'};
  return system === 'sp1' ? {system, programVKey: programId, instanceId, ...extra} : {system, imageId: programId.replace(/^0x/, ''), instanceId, ...extra};
}
const proofOf = (pf) => pf.proof ?? (pf.system === 'sp1' ? pf.proofHex : pf.sealHex);
const pvOf = (pf) => Buffer.from(pf.publicValuesHex ?? pf.journalHex, 'hex');

if (cmd === 'example-statement') {
  const [out] = a; assert.ok(out, 'example-statement <statement.json>');
  writeFileSync(out, JSON.stringify({note: 'REGTEST / CHIPNET ONLY: the payout locking has no known key (burned) and the INSTANCE is public', instanceId: INSTANCE,
    outputs: OUTS.map((o) => ({lockingHex: o.lockingBytecode, valueSatoshis: String(o.valueSatoshis)}))}, null, 1) + '\n');
  warn(`wrote ${out}: the EXAMPLE statement (regtest / chipnet only)`);
} else if (cmd === 'request') {
  const [secretHex, stPath, out] = a; assert.ok(/^[0-9a-f]*$/i.test(secretHex ?? '') && stPath && out, 'request <secretHex> <statement.json> <request.json>');
  const st = readJson(stPath); assert.ok(/^[0-9a-f]{64}$/i.test(st.instanceId), 'statement.instanceId: 32 B hex');
  const outputs = st.outputs.map((o) => ({lockingBytecode: o.lockingHex, valueSatoshis: BigInt(o.valueSatoshis)}));
  const exampleSecret = createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest('hex') === EXAMPLE_LOCK_HASH;
  const exampleOuts = st.instanceId.toLowerCase() === INSTANCE || outputs.some((o) => o.lockingBytecode === OUTS[0].lockingBytecode);
  if (exampleSecret || exampleOuts) { assert.ok(regtest, 'the example secret / INSTANCE / payout are public or unspendable: replace them (or --regtest)');
    warn('example values (public secret / public INSTANCE / burn payout): regtest only'); }
  const pvBytes = encodePV(st.instanceId, outputs).length; // also enforces the spendability caps
  writeFileSync(out, JSON.stringify({secretHex, instanceId: st.instanceId, outputs: st.outputs.map((o) => ({lockingHex: o.lockingHex, valueSatoshis: String(o.valueSatoshis)}))}, null, 1) + '\n');
  console.log(`wrote ${out}: instance ${st.instanceId.slice(0, 16)}…, ${outputs.length} outputs; PV ${pvBytes} B. Before proving, run cov.preflight (pinned.mjs) with the funded amount.`);
} else if (cmd === 'pin') {
  const [key, programId, instanceId] = a; const cov = await openPinned(key, paramsFor(key, programId, instanceId));
  console.log(JSON.stringify({key, params: cov.params, lockingHex: hex(cov.lockingBytecode), address: cov.address, codeBytes: cov.prog.code.length,
    fund: 'ONCE, with exactly 3 UTXOs. Any later deposit to this address (including change) can be taken by replaying a used proof: the extra value goes to the same outputs or to miner fees.'}, null, 1));
} else if (cmd === 'spend') {
  const [key, programId, instanceId, pfPath, utxoPath, out] = a; const P = paramsFor(key, programId, instanceId);
  const pf = readJson(pfPath); const utxos = readJson(utxoPath);
  const named = pf.programVKey ?? pf.imageId; // proof.json may name its program; it must be the pinned one
  if (named !== undefined) assert.equal(String(named).replace(/^0x/, '').toLowerCase(), String(programId).replace(/^0x/, '').toLowerCase(), 'proof.json names another program than <programId>');
  const pv = pvOf(pf); const {instanceId: pvInstance, outputs} = decodePV(pv);
  assert.equal(pvInstance, instanceId.toLowerCase(), 'proof.json commits another instance id');
  assert.ok(encodePV(instanceId, outputs).equals(pv), 'PV re-encodes exactly');
  const cov = await openPinned(key, P);
  // buildSpend derives (n0, n1) from P and the outputs, refuses a proof that does not verify for them, checks dust,
  // self-payment and the fee floor, and runs libauth verify (consensus + standard) on the finished transaction
  const s = cov.buildSpend({proof: proofOf(pf), outputs, utxos});
  const res = {txid: s.txid, bytes: s.bytes, feeSatoshis: s.fee.toString(), unlocking: s.unlockings.map((u) => u.length), publicInputs: s.publicInputs, hex: s.hex,
    note: 'the txid is not final until confirmed (nothing signs the transaction; relays can re-randomize the proof or change version/locktime/sequence)'};
  if (out) writeFileSync(out, JSON.stringify(res, null, 1) + '\n');
  console.log(`tx ${s.txid}: ${s.bytes} B, fee ${s.fee} sat, unlockings ${res.unlocking.join(' / ')} B; libauth verify: consensus + standard OK${out ? '; wrote ' + out : ''}`);
  console.log('note: the txid may change before confirmation (unsigned transaction); do not chain unconfirmed children on it');
} else if (cmd === 'test-proof') {
  const [system, out] = a; assert.ok(['sp1', 'risc0'].includes(system) && out);
  const {loadKey} = await import('./keys.mjs'); const K = await loadKey('test');
  const programId = system === 'sp1' ? TEST_PROGRAM_VKEY : TEST_IMAGE_ID;
  const pf = system === 'sp1' ? {system, programVKey: TEST_PROGRAM_VKEY} : {system, imageId: TEST_IMAGE_ID};
  const pv = encodePV(INSTANCE, OUTS); const {publicInputsFor} = await import('./pv.mjs');
  const [n0, n1] = publicInputsFor(system === 'sp1' ? {system, programVKey: programId, instanceId: INSTANCE} : {system, imageId: programId, instanceId: INSTANCE}, OUTS);
  const minted = K.mint.mint(n0, n1, K.mint.rng('example.mjs:' + system));
  writeFileSync(out, JSON.stringify({...pf, [system === 'sp1' ? 'publicValuesHex' : 'journalHex']: hex(pv), proof: minted.proof,
    note: 'TEST KEY proof (minted with the published trapdoor of the densless fixture VK); valid only under key "test"'}, null, 1) + '\n');
  console.log(`wrote ${out} (test key, ${system}); spend with: spend test ${programId} ${INSTANCE} ${out} <utxos.json> --regtest`);
} else {
  console.log('usage: example-statement <statement.json> | request <secretHex> <statement.json> <request.json> | pin <key> <programId> <instanceId> [--mainnet] | spend <key> <programId> <instanceId> <proof.json> <utxos.json> [tx.json] | test-proof <sp1|risc0> <proof.json>   (--regtest for example values / the test key)');
  process.exit(1);
}
