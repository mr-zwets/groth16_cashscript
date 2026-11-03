// Track 12: the public-values layout of the program-pinned covenant template (pure functions, no VK).
//
// The zkVM guest commits PV (SP1: `sp1_zkvm::io::commit_slice(&pv)`; RISC Zero: `env::commit_slice(&pv)`), and the
// covenant REBUILDS the same bytes on chain from the spending transaction's own outputs (introspection). Nothing in PV
// is pushed by the spender, so the proof can only authorize the exact outputs of the transaction that spends it.
//
//   PV = TAG (8 B, ASCII "BCHPAYv1")
//      ‖ INSTANCE (32 B, a constant of the covenant: which deployment this proof is for)
//      ‖ n (1 B, the transaction's output count; the chain accepts 1..127, the spendable cap below is 96)
//      ‖ for each output k = 0 .. n-1:  value (8 B, u64 LE) ‖ len (2 B, u16 LE) ‖ locking bytecode (len B)
//
// Every output must carry no CashTokens (the covenant requires OP_OUTPUTTOKENCATEGORY k to be empty): token data is
// not in PV, so a token on an output would be an unbound change. (Introspection cannot distinguish every token
// encoding exactly either; see README "Outputs carry no tokens".)
//
// The two systems' public inputs (n0, n1), as their EVM verifiers derive them:
//   SP1 v5     n0 = uint256(programVKey)              n1 = uint256(sha256(PV)) & (2^253 - 1)
//   RISC Zero  (n0, n1) = splitDigest(ReceiptClaimLib.ok(IMAGE_ID, sha256(PV)).digest())
// (the RISC Zero journal IS PV; claims.mjs of Track 11 holds both derivations and is reused here).
import assert from 'node:assert/strict';
import {sp1Inputs, risc0Inputs, sha} from '../real-keys/claims.mjs';

export const PV_TAG = Buffer.from('BCHPAYv1', 'ascii');
assert.equal(PV_TAG.length, 8);
// Spendability caps (liveness, not soundness: a PV outside them can be PROVEN but the covenant can never be SPENT, so the
// encoder refuses to produce one). The count is one byte (OP_NUM2BIN 1 on chain fails above 127), a PV over 10,000 B
// fails the stack-item limit in the rebuild's OP_CAT, and the rebuild costs about n x |PV| op (each OP_CAT is charged
// for the PV built so far), all in role 2. Measured (test key, both systems, prover-sized fillers): 112 x 25 B,
// 40 x 223 B and 1 x 9,949 B spend; 127 x 25 B, 96 x 60 B and 64 x 140 B exceed role 2's op budget at the 10,000 B
// unlocking cap. Every point inside the caps below that was measured spends with >= 5.6% role-2 margin.
export const MAX_OUTPUTS = 96;
export const MAX_PV_BYTES = 9900;
export const MAX_OUTPUTS_X_PV = 300000;
export function assertSpendableShape(n, pvBytes) {
  assert.ok(n >= 1 && n <= MAX_OUTPUTS, `1..${MAX_OUTPUTS} outputs (spendability cap; the chain itself stops at 127)`);
  assert.ok(pvBytes <= MAX_PV_BYTES, `PV ${pvBytes} B > ${MAX_PV_BYTES} B: the covenant could never be spent (10,000 B stack item limit)`);
  assert.ok(n * pvBytes <= MAX_OUTPUTS_X_PV, `outputs x |PV| = ${n * pvBytes} > ${MAX_OUTPUTS_X_PV}: the on-chain rebuild would exceed role 2's op budget`);
}

const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const u16le = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };

// outputs: [{lockingBytecode: Uint8Array|Buffer|hex, valueSatoshis: bigint|number|string, token?: any}]
export function normalizeOutputs(outputs) {
  assert.ok(Array.isArray(outputs) && outputs.length >= 1 && outputs.length <= 127, '1..127 outputs');
  return outputs.map((o) => {
    assert.ok(o.token === undefined, 'outputs of a pinned-template spend carry no tokens');
    const lockingBytecode = Buffer.from(typeof o.lockingBytecode === 'string' ? Buffer.from(o.lockingBytecode, 'hex') : o.lockingBytecode);
    const valueSatoshis = BigInt(o.valueSatoshis); assert.ok(valueSatoshis >= 0n && valueSatoshis < (1n << 63n));
    assert.ok(lockingBytecode.length <= 10000, 'locking bytecode <= 10,000 B');
    return {lockingBytecode, valueSatoshis};
  });
}

export function encodePV(instanceId, outputs) {
  const inst = Buffer.from(instanceId, 'hex'); assert.equal(inst.length, 32, 'instance id: 32 bytes');
  const outs = normalizeOutputs(outputs);
  const pv = Buffer.concat([PV_TAG, inst, Buffer.from([outs.length]),
    ...outs.flatMap((o) => [u64le(o.valueSatoshis), u16le(o.lockingBytecode.length), o.lockingBytecode])]);
  assertSpendableShape(outs.length, pv.length);
  return pv;
}

// strict decoder (used by the builder and the tests to read a PV back)
export function decodePV(pv) {
  pv = Buffer.from(pv); assert.ok(pv.subarray(0, 8).equals(PV_TAG), 'PV tag'); let o = 8;
  const instanceId = pv.subarray(o, o + 32).toString('hex'); o += 32;
  const n = pv[o++]; assert.ok(n >= 1 && n <= 127); const outputs = [];
  for (let k = 0; k < n; k++) {
    const valueSatoshis = pv.readBigUInt64LE(o); o += 8; const len = pv.readUInt16LE(o); o += 2;
    outputs.push({valueSatoshis, lockingBytecode: pv.subarray(o, o + len)}); o += len;
  }
  assert.equal(o, pv.length, 'PV has no trailing bytes');
  return {instanceId, outputs};
}

// the statement (n0, n1) that a proof must carry for these outputs, under template parameters P
//   P = {system: 'sp1', programVKey: '0x..', instanceId} | {system: 'risc0', imageId: '..', instanceId}
export function publicInputsFor(P, outputs) {
  const pv = encodePV(P.instanceId, outputs);
  return P.system === 'sp1' ? sp1Inputs(P.programVKey, pv) : risc0Inputs(P.imageId, pv);
}
export {sha};
