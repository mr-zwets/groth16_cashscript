// Track 12: the program-pinned covenant as a small library + transaction builder.
//
//   import {openPinned} from './pinned.mjs';
//   const cov = await openPinned('sp1-v5', {system: 'sp1', programVKey: '0x00ab…', instanceId: '…32 bytes hex…'});
//   cov.lockingBytecode / cov.address        // P2SH32 of the 3-input redeem; fund it with 3 UTXOs
//   cov.publicValuesFor(outputs)             // the exact bytes the guest must commit (pv.mjs layout)
//   cov.buildSpend({proof, outputs, utxos})  // -> {unlockings, transaction (libauth), hex, txid, ...}
//
// `proof` is any of: an SP1 v5 Groth16 proof as hex (`proof.bytes()`: 4-byte selector ‖ 8 words), a RISC Zero
// Groth16 seal as hex (selector ‖ 8 words), or {a, b, c} affine coordinates (decimal strings, as in the fixtures).
// The builder never takes n0, n1 from the caller: it derives them from the parameters and the outputs, exactly as
// the covenant does, and refuses a proof that does not verify for that statement (noble pairing, via proveCore).
import assert from 'node:assert/strict';
import {encodeTransaction, hashTransaction, lockingBytecodeToCashAddress, hash256} from '@bitauth/libauth';
import {loadKey} from './keys.mjs';
import {encodePV, normalizeOutputs, publicInputsFor} from './pv.mjs';

const SELECTORS = {sp1: 'a4594c59'}; // SP1 v5 VERIFIER_HASH prefix (Track 11); RISC Zero selectors are per control root
export function parseProof(proof, system) {
  if (typeof proof !== 'string') { assert.ok(proof.a && proof.b && proof.c, 'proof {a, b, c}'); return proof; }
  const h = proof.replace(/^0x/, ''); assert.equal(h.length, 8 + 8 * 64, 'selector + 8 words');
  if (system === 'sp1') assert.equal(h.slice(0, 8), SELECTORS.sp1, 'SP1 v5 Groth16 selector');
  const w = Array.from({length: 8}, (_, i) => BigInt('0x' + h.slice(8 + 64 * i, 8 + 64 * i + 64)).toString());
  // EIP-197 order: A.x, A.y, B.x.c1, B.x.c0, B.y.c1, B.y.c0, C.x, C.y
  return {a: {x: w[0], y: w[1]}, b: {x: {c0: w[3], c1: w[2]}, y: {c0: w[5], c1: w[4]}}, c: {x: w[6], y: w[7]}};
}

export async function openPinned(key, params) {
  const K = await loadKey(key);
  const prog = K.tpl.buildPinnedProgram(params);
  const locking = K.tx.lockingOf(prog);
  const address = lockingBytecodeToCashAddress({bytecode: locking, prefix: params.prefix ?? 'bitcoincash'});
  const self = {
    key, params, prog, K, lockingBytecode: locking, address: typeof address === 'string' ? address : address.address,
    publicValuesFor: (outputs) => encodePV(params.instanceId, outputs),
    publicInputsFor: (outputs) => publicInputsFor(params, outputs),
    // the 3 unlockings (prover-sized fillers) for a proof of the statement these outputs imply
    unlockingsFor(proof, outputs, opts = {}) {
      const outs = normalizeOutputs(outputs);
      const fx = {proof: parseProof(proof, params.system), publicInputs: publicInputsFor(params, outs).map(String)};
      K.vm.setOutputs(outs); // filler sizing runs the script against these outputs
      return {fx, outs, ...K.tx.transactionFor(fx, prog, opts)};
    },
    // a complete transaction: utxos = 3 × {txid (display hex), vout, valueSatoshis} of this covenant's address
    buildSpend({proof, outputs, utxos, sequenceNumber = 0, locktime = 0, version = 2}) {
      assert.equal(utxos?.length, 3, 'exactly 3 covenant UTXOs (the verifier requires 3 inputs of this locking)');
      const T = self.unlockingsFor(proof, outputs);
      const transaction = {version, locktime, outputs: T.outs,
        inputs: utxos.map((u, i) => ({outpointTransactionHash: Buffer.from(u.txid, 'hex').reverse(), outpointIndex: u.vout, sequenceNumber, unlockingBytecode: T.unlockings[i]}))};
      const fee = utxos.reduce((s, u) => s + BigInt(u.valueSatoshis), 0n) - T.outs.reduce((s, o) => s + o.valueSatoshis, 0n);
      assert.ok(fee >= 0n, 'outputs exceed the covenant UTXOs');
      const raw = encodeTransaction(transaction);
      return {transaction, hex: Buffer.from(raw).toString('hex'), bytes: raw.length, fee, txid: (h => (typeof h === 'string' ? h : Buffer.from(h).toString('hex')))(hashTransaction(raw)), // display order
        unlockings: T.unlockings, fills: T.fills, publicInputs: T.fx.publicInputs, publicValues: encodePV(params.instanceId, T.outs),
        sourceOutputs: utxos.map((u) => ({lockingBytecode: locking, valueSatoshis: BigInt(u.valueSatoshis)}))};
    },
  };
  return self;
}
export {hash256};
