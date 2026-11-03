// Track 12: the public-values layout of the program-pinned covenant template (pure functions, no VK).
//
// The zkVM guest commits PV (SP1: `sp1_zkvm::io::commit_slice(&pv)`; RISC Zero: `env::commit_slice(&pv)`), and the
// covenant REBUILDS the same bytes on chain from the spending transaction's own outputs (introspection). Nothing in PV
// is pushed by the spender, so the proof can only authorize the exact outputs of the transaction that spends it.
//
//   PV = TAG (8 B, ASCII "BCHPAYv1")
//      ‖ INSTANCE (32 B, a constant of the covenant: which deployment this proof is for)
//      ‖ n (1 B, the transaction's output count, 1..127)
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
export const MAX_OUTPUTS = 127; // the count is one byte (OP_NUM2BIN 1 on chain fails above 127)

const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const u16le = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };

// outputs: [{lockingBytecode: Uint8Array|Buffer|hex, valueSatoshis: bigint|number|string, token?: any}]
export function normalizeOutputs(outputs) {
  assert.ok(Array.isArray(outputs) && outputs.length >= 1 && outputs.length <= MAX_OUTPUTS, `1..${MAX_OUTPUTS} outputs`);
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
  return Buffer.concat([PV_TAG, inst, Buffer.from([outs.length]),
    ...outs.flatMap((o) => [u64le(o.valueSatoshis), u16le(o.lockingBytecode.length), o.lockingBytecode])]);
}

// strict decoder (used by the builder and the tests to read a PV back)
export function decodePV(pv) {
  pv = Buffer.from(pv); assert.ok(pv.subarray(0, 8).equals(PV_TAG), 'PV tag'); let o = 8;
  const instanceId = pv.subarray(o, o + 32).toString('hex'); o += 32;
  const n = pv[o++]; assert.ok(n >= 1 && n <= MAX_OUTPUTS); const outputs = [];
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
