// Track 12: the program-pinned covenant as a small library + transaction builder.
//
//   import {openPinned} from './pinned.mjs';
//   const cov = await openPinned('sp1-v5', {system: 'sp1', programVKey: '0x00ab…', instanceId: '…32 bytes hex…'});
//   cov.lockingBytecode / cov.address        // P2SH32 of the 3-input redeem; fund it ONCE with exactly 3 UTXOs
//   cov.preflight({outputs, utxoTotal})      // BEFORE proving: spendable shape, no self-payment, dust, fee floor
//   cov.publicValuesFor(outputs)             // the exact bytes the guest must commit (pv.mjs layout)
//   cov.buildSpend({proof, outputs, utxos})  // -> {unlockings, transaction (libauth), hex, txid, ...}
//
// params.prefix defaults to 'bchtest' (an address for mainnet needs prefix: 'bitcoincash' explicitly). Key 'test'
// (published trapdoor) needs params.allowTestKey; key 'risc0' (Track 11's root b1f64013 from UNRELEASED risc0 main,
// which released risc0 3.0.x receipts cannot satisfy) needs params.allowUnreleasedRisc0. Use 'risc0-v3' for RISC Zero.
//
// `proof` is any of: an SP1 v5 Groth16 proof as hex (`proof.bytes()`: 4-byte selector ‖ 8 words), a RISC Zero
// Groth16 seal as hex (selector ‖ 8 words), or {a, b, c} affine coordinates (decimal strings, as in the fixtures).
// The builder never takes n0, n1 from the caller: it derives them from the parameters and the outputs, exactly as
// the covenant does, and refuses a proof that does not verify for that statement (noble pairing, via proveCore).
import assert from 'node:assert/strict';
import {encodeTransaction, hashTransaction, lockingBytecodeToCashAddress, hash256} from '@bitauth/libauth';
import {loadKey} from './keys.mjs';
import {encodePV, normalizeOutputs, publicInputsFor, assertSpendableShape} from './pv.mjs';

// relay policy (BCHN defaults): min relay fee 1 sat/B; dust = 3 x (serialized output + 148) sat at 1 sat/B, except
// provably unspendable (OP_RETURN) outputs. The proof freezes the outputs, hence the fee: check BEFORE proving.
export const MIN_FEE_RATE = 1;
const csLen = (n) => (n < 253 ? 1 : n <= 0xffff ? 3 : 5);
export const dustThreshold = (lb) => (lb[0] === 0x6a ? 0n : BigInt(3 * (8 + csLen(lb.length) + lb.length + 148)));
// worst-case spend size: 3 inputs with 10,000 B unlockings, plus the outputs
export const maxSpendBytes = (outs) => 4 + 1 + 3 * (32 + 4 + 3 + 10000 + 4) + 1 + outs.reduce((s, o) => s + 8 + csLen(o.lockingBytecode.length) + o.lockingBytecode.length, 0) + 4;

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
  if (key === 'test') assert.ok(params.allowTestKey, "key 'test' has a PUBLIC trapdoor (anyone can mint proofs): pass allowTestKey only for tests");
  if (key === 'risc0') assert.ok(params.allowUnreleasedRisc0, "key 'risc0' pins control root b1f64013 (unreleased risc0 main); released risc0 3.0.x receipts cannot spend it: use 'risc0-v3', or pass allowUnreleasedRisc0");
  const K = await loadKey(key);
  const prog = K.tpl.buildPinnedProgram(params);
  const locking = K.tx.lockingOf(prog);
  const address = lockingBytecodeToCashAddress({bytecode: locking, prefix: params.prefix ?? 'bchtest'});
  const self = {
    key, params, prog, K, lockingBytecode: locking, address: typeof address === 'string' ? address : address.address,
    publicValuesFor: (outputs) => encodePV(params.instanceId, outputs),
    publicInputsFor: (outputs) => publicInputsFor(params, outputs),
    // checks to run BEFORE proving (a proof freezes the outputs; a failing spend needs a new proof). Returns the
    // fee at the worst-case size. utxoTotal: the value of the 3 covenant UTXOs this proof will spend.
    preflight({outputs, utxoTotal, minFeeRate = MIN_FEE_RATE}) {
      const outs = normalizeOutputs(outputs); assertSpendableShape(outs.length, encodePV(params.instanceId, outs).length);
      outs.forEach((o, k) => {
        assert.ok(!Buffer.from(o.lockingBytecode).equals(Buffer.from(locking)), `output ${k} pays this covenant's own locking: change must go to a covenant with a FRESH INSTANCE (the covenant rejects it on chain)`);
        assert.ok(o.valueSatoshis >= dustThreshold(o.lockingBytecode), `output ${k} is dust (< ${dustThreshold(o.lockingBytecode)} sat): the spend would not relay`);
      });
      const fee = BigInt(utxoTotal) - outs.reduce((s, o) => s + o.valueSatoshis, 0n), bytes = maxSpendBytes(outs);
      assert.ok(fee >= BigInt(Math.ceil(minFeeRate * bytes)), `fee ${fee} sat < ${minFeeRate} sat/B x ${bytes} B (worst-case size): the spend would not relay, and no fee input can be added later`);
      return {fee, maxBytes: bytes};
    },
    // the 3 unlockings (prover-sized fillers) for a proof of the statement these outputs imply
    unlockingsFor(proof, outputs, opts = {}) {
      const outs = normalizeOutputs(outputs);
      const fx = {proof: parseProof(proof, params.system), publicInputs: publicInputsFor(params, outs).map(String)};
      K.vm.setOutputs(outs); // filler sizing runs the script against these outputs
      return {fx, outs, ...K.tx.transactionFor(fx, prog, opts)};
    },
    // a complete transaction: utxos = 3 × {txid (display hex), vout, valueSatoshis} of this covenant's address
    // The txid is NOT final until it confirms: nothing signs the transaction, so any relay can re-randomize A, B, C
    // or change version / locktime / sequence numbers (same outputs, same fee). Do not chain unconfirmed children.
    buildSpend({proof, outputs, utxos, sequenceNumber = 0, locktime = 0, version = 2, minFeeRate = MIN_FEE_RATE}) {
      assert.equal(utxos?.length, 3, 'exactly 3 covenant UTXOs (the verifier requires 3 inputs of this locking)');
      self.preflight({outputs, utxoTotal: utxos.reduce((s, u) => s + BigInt(u.valueSatoshis), 0n), minFeeRate: 0});
      const T = self.unlockingsFor(proof, outputs);
      const transaction = {version, locktime, outputs: T.outs,
        inputs: utxos.map((u, i) => ({outpointTransactionHash: Buffer.from(u.txid, 'hex').reverse(), outpointIndex: u.vout, sequenceNumber, unlockingBytecode: T.unlockings[i]}))};
      const fee = utxos.reduce((s, u) => s + BigInt(u.valueSatoshis), 0n) - T.outs.reduce((s, o) => s + o.valueSatoshis, 0n);
      assert.ok(fee >= 0n, 'outputs exceed the covenant UTXOs');
      const raw = encodeTransaction(transaction);
      assert.ok(fee >= BigInt(Math.ceil(minFeeRate * raw.length)), `fee ${fee} sat < ${minFeeRate} sat/B x ${raw.length} B: would not relay`);
      // the finished transaction must pass libauth (consensus and standard) before it is handed out
      const sourceOutputs = utxos.map((u) => ({lockingBytecode: locking, valueSatoshis: BigInt(u.valueSatoshis)}));
      for (const m of ['consensus', 'standard']) { const v = K.vm.VMS[m].verify({sourceOutputs, transaction}); assert.equal(v, true, `libauth ${m}: ${v}`); }
      return {transaction, hex: Buffer.from(raw).toString('hex'), bytes: raw.length, fee, txid: (h => (typeof h === 'string' ? h : Buffer.from(h).toString('hex')))(hashTransaction(raw)), // display order
        unlockings: T.unlockings, fills: T.fills, publicInputs: T.fx.publicInputs, publicValues: encodePV(params.instanceId, T.outs),
        sourceOutputs};
    },
  };
  return self;
}
export {hash256};
