// Remove the dead vk_x auxiliary predicate from the densless genesis program.
//
// With the MSM inputs binding vk_x to the public inputs, the genesis log-derivative predicate
// (witness pushes 19..39 and the code consuming them) checks nothing the verifier relies on.
// genesis-slice.json lists the instructions to drop and the PICK/ROLL depth constants that
// change. It was derived from a copy-aware shadow-stack taint trace of the genesis input on
// all five official fixtures: no surviving instruction reads a removed value, removed code
// consumes no surviving value, no function body is affected, and every rewritten depth is
// identical across all executions. The removed span also held checks on proof data; those
// on B (canonical coordinates and on-curve, instructions 186..245) are kept, while the
// canonical checks on vk_x are dropped because the MSM inputs produce a reduced vk_x and the
// terminal pins its exact bytes. The table only applies to the exact program it
// was derived from (sourceGenesisSha256).
//
// The sliced program starts with OP_DROP so the genesis input can carry a zero pad as its
// last witness push (buying op-cost budget) without shifting any stack depth.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {OpcodesBCH, bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstruction, encodeDataPush, vmNumberToBigInt} from '@bitauth/libauth';

export const table = JSON.parse(readFileSync(new URL('genesis-slice.json', import.meta.url)));

const pushedNumber = (ins) => {
  if (ins.opcode === OpcodesBCH.OP_0) return 0n;
  if (ins.opcode >= OpcodesBCH.OP_1 && ins.opcode <= OpcodesBCH.OP_16) return BigInt(ins.opcode - OpcodesBCH.OP_1 + 1);
  assert(ins.data !== undefined, 'depth constant must be a push');
  return vmNumberToBigInt(ins.data);
};

export function sliceGenesis(program) {
  assert.equal(createHash('sha256').update(program).digest('hex'), table.sourceGenesisSha256, 'genesis program differs from the traced one');
  const ins = decodeAuthenticationInstructions(program);
  assert.equal(ins.length, table.sourceInstructions);
  const removed = new Set();
  for (const [a, b] of table.removeRanges) for (let i = a; i <= b; i++) removed.add(i);
  for (const k of table.keep) removed.delete(k);
  const out = ins.map((x) => x);
  for (const [ipText, {from, to}] of Object.entries(table.depthRewrites)) {
    const ip = Number(ipText);
    assert([OpcodesBCH.OP_PICK, OpcodesBCH.OP_ROLL].includes(ins[ip].opcode), `instruction ${ip} is not PICK/ROLL`);
    assert(!removed.has(ip) && !removed.has(ip - 1), `rewrite ${ip} touches removed code`);
    assert.equal(pushedNumber(ins[ip - 1]), BigInt(from), `depth constant at ${ip - 1}`);
    out[ip - 1] = decodeAuthenticationInstructions(encodeDataPush(bigIntToVmNumber(BigInt(to))))[0];
  }
  const kept = out.filter((_, i) => !removed.has(i));
  return Buffer.concat([Buffer.from([OpcodesBCH.OP_DROP]), ...kept.map((x) => Buffer.from(encodeAuthenticationInstruction(x)))]);
}
