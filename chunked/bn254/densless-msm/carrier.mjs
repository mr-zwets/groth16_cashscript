// Run extra code inside an existing input after its own program (a "carrier").
//
// The carried code's witness pushes are appended after the carrier's own pushes (just before
// the redeem), so every byte offset other inputs read from the carrier's unlocking stays put.
// At the start they are on top of the stack; the wrapper parks them on the altstack, runs the
// carrier's program unchanged (it must leave exactly one true item and keep the altstack
// balanced), verifies its result, restores the parked pushes and runs the carried code, which
// must leave exactly one true item.
//
// The carried code's OP_DEFINE/OP_INVOKE function identifiers are shifted by `idOffset` so they
// cannot collide with the carrier's functions (static invokes only).
import assert from 'node:assert/strict';
import {OpcodesBCH, bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstruction, encodeDataPush, vmNumberToBigInt} from '@bitauth/libauth';

const numberOf = (ins) => {
  if (ins.opcode === OpcodesBCH.OP_0) return 0n;
  if (ins.opcode >= OpcodesBCH.OP_1 && ins.opcode <= OpcodesBCH.OP_16) return BigInt(ins.opcode - OpcodesBCH.OP_1 + 1);
  assert(ins.data !== undefined, 'function identifier must be a constant push');
  return vmNumberToBigInt(ins.data);
};
const push = (n) => decodeAuthenticationInstructions(encodeDataPush(bigIntToVmNumber(n)))[0];
const encode = (list) => Buffer.concat(list.map((x) => Buffer.from(encodeAuthenticationInstruction(x))));

export function remapFunctionIds(bytecode, idOffset) {
  const list = decodeAuthenticationInstructions(bytecode).map((x) => ({...x}));
  for (let i = 0; i < list.length; i++) {
    const op = list[i].opcode;
    if (op !== OpcodesBCH.OP_DEFINE && op !== OpcodesBCH.OP_INVOKE) continue;
    assert(i >= 1, 'function operation without an identifier');
    list[i - 1] = push(numberOf(list[i - 1]) + BigInt(idOffset));
    if (op === OpcodesBCH.OP_DEFINE) {
      assert(i >= 2 && list[i - 2].data !== undefined, 'OP_DEFINE body must be a push');
      list[i - 2] = decodeAuthenticationInstructions(encodeDataPush(remapFunctionIds(Buffer.from(list[i - 2].data), idOffset)))[0];
    }
  }
  return encode(list);
}

export function carrier(program, carried, parked) {
  return Buffer.concat([
    Buffer.alloc(parked, OpcodesBCH.OP_TOALTSTACK),
    program,
    Buffer.from([OpcodesBCH.OP_VERIFY]),
    Buffer.alloc(parked, OpcodesBCH.OP_FROMALTSTACK),
    carried,
  ]);
}
