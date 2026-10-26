import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {encodeDataPush, bigIntToVmNumber, OpcodesBCH} from '@bitauth/libauth';
import * as equation from '../pairfold5-pevalfuse-deterministic/equation-guard.mjs';
import {assemble} from '../pairfold5-pevalfuse-deterministic/build.mjs';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const identifiers = new Map(equation.functions.map(fn => [fn.name, fn.originalId]));
assert.equal(identifiers.size, equation.functions.length);
export const equationLoader = Buffer.concat([
  assemble(equation.prefix, identifiers),
  ...equation.functions.map(fn => Buffer.from([
    ...encodeDataPush(assemble(fn.body, identifiers)),
    ...encodeDataPush(bigIntToVmNumber(BigInt(fn.originalId))), OpcodesBCH.OP_DEFINE,
  ])),
  assemble(equation.main, identifiers),
]);
export const equationLoaderSha256 = createHash('sha256').update(equationLoader).digest('hex');

// The copied checker has its own proved namespace and leaves the original
// argument frame intact. It is the equation owner; legacy auxiliary checks are
// additional restrictions, with no independent soundness credit.
export function buildGuard({argumentCount, n0Push, n1Push, proofInput, guardInput}) {
  for (const n of [argumentCount, n0Push, n1Push, proofInput, guardInput]) assert(Number.isSafeInteger(n) && n >= 0);
  assert(argumentCount > Math.max(n0Push, n1Push));
  const lines = ['OP_DEPTH NUM ARGUMENT_COUNT OP_NUMEQUALVERIFY'];
  if (proofInput === guardInput) {
    lines.push('NUM PROOF_DEPTH OP_PICK OP_SIZE NUM PROOF_BYTES OP_NUMEQUALVERIFY OP_DROP');
  } else {
    // The proof tuple is the first 448-byte push of the pinned sibling genesis.
    // P2SH push-only execution and this literal header bind the physical bytes.
    lines.push('NUM PROOF_INPUT OP_INPUTBYTECODE OP_3 OP_SPLIT OP_DROP DATA PROOF_HEADER OP_EQUALVERIFY');
  }
  let copies = 0;
  for (const index of [n1Push, n0Push]) {
    lines.push(`NUM PUBLIC_DEPTH_${copies} OP_PICK`);
    copies++;
  }
  // checker_main consumes Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, n0, n1
  // in stack order. The legacy tuple carries -Ay, so restore Ay canonically.
  for (const field of [7, 6, 11, 10, 9, 8, 3, 2]) {
    lines.push(proofInput === guardInput
      ? `NUM BLOB_DEPTH_${copies} OP_PICK NUM FIELD_${field}_OFFSET OP_SPLIT OP_NIP`
      : `NUM PROOF_INPUT OP_INPUTBYTECODE NUM WIRE_${field}_OFFSET OP_SPLIT OP_NIP`);
    lines.push('OP_PUSHBYTES_1 0x20 OP_SPLIT OP_DROP OP_BIN2NUM');
    if (field === 3) lines.push('OP_0 OP_SWAP OP_SUB NUM P OP_MOD NUM P OP_ADD NUM P OP_MOD');
    copies++;
  }
  lines.push('CALL checker_main OP_VERIFY');
  const data = {
    ARGUMENT_COUNT: BigInt(argumentCount), PROOF_DEPTH: BigInt(argumentCount - 1),
    PROOF_BYTES: 448n, PROOF_INPUT: BigInt(proofInput), PROOF_HEADER: Buffer.from('4dc001', 'hex'), P,
    PUBLIC_DEPTH_0: BigInt(argumentCount - 1 - n1Push),
    PUBLIC_DEPTH_1: BigInt(argumentCount - n0Push),
  };
  for (let i = 2; i < 10; i++) data[`BLOB_DEPTH_${i}`] = BigInt(argumentCount - 1 + i);
  for (const field of [7, 6, 11, 10, 9, 8, 3, 2]) {
    data[`FIELD_${field}_OFFSET`] = BigInt(field * 32);
    data[`WIRE_${field}_OFFSET`] = BigInt(3 + field * 32);
  }
  return {bytecode: Buffer.concat([equationLoader, assemble(lines.join('\n'), identifiers, data)]),
    bridgeSource: lines.join('\n'), argumentCount, equationLoaderSha256};
}
