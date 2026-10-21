import { createHash } from 'node:crypto';
import {
  bigIntToVmNumber, binToHex, decodeAuthenticationInstructions,
  encodeAuthenticationInstructions, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, OpcodesBCH as OP,
} from '@bitauth/libauth';
import { rootFrameGuard } from './_root_frame.mjs';

const require = (condition, message) => { if (!condition) throw new Error(message); };
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(Buffer.from)));
const pushNumber = value => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const encode = encodeAuthenticationInstructions;
const key = instruction => instruction.data !== undefined ? binToHex(instruction.data)
  : instruction.opcode === 0 ? '' : instruction.opcode === 79 ? '81'
    : instruction.opcode >= 81 && instruction.opcode <= 96
      ? (instruction.opcode - 80).toString(16).padStart(2, '0') : undefined;
const sha256 = bytes => Uint8Array.from(createHash('sha256').update(bytes).digest());
const slice = (start, end) => concat(pushNumber(end), Uint8Array.of(OP.OP_SPLIT, OP.OP_DROP),
  ...(start === 0 ? [] : [pushNumber(start), Uint8Array.of(OP.OP_SPLIT, OP.OP_NIP)]));
const locking = redeem => encodeLockingBytecodeP2sh32(hash256(redeem));

// These exact canonical Fp/Fp2 ABIs were independently checked against the native library.
export function mapCoordinatorArithmetic(bytecode) {
  const definitions = [
    ['81','30abaafffffffffeb9ffff53b1feffab1e24f6b0f6a0d23067bf1285f3844b7764d7ac4b43b6a71b4b9ae67f39ea11011a'],
    ['01','934f8a97'], ['02','4f8a7c7b9478937c97'], ['03','954f8a97'],
    ['','6e528a785379518a538a787b518a7b538a'],
  ];
  const instructions = decodeAuthenticationInstructions(bytecode);
  definitions.forEach(([id, body], index) => {
    const offset = index * 3;
    require(binToHex(instructions[offset]?.data ?? new Uint8Array()) === body &&
      key(instructions[offset + 1]) === id && instructions[offset + 2]?.opcode === OP.OP_DEFINE,
    'coordinator private arithmetic owner changed');
  });
  const removed = encode(instructions.slice(0, 15)).length;
  require(removed === 98, 'coordinator private prefix width changed');
  const body = instructions.slice(15), mapping = new Map([
    ['81','81'], ['01','0b'], ['02','09'], ['03',''], ['','07'],
  ]), calls = {};
  body.forEach((instruction, index) => {
    require(!instruction.malformed && ![OP.OP_DEFINE, OP.OP_ACTIVEBYTECODE,
      OP.OP_CODESEPARATOR, OP.OP_RETURN].includes(instruction.opcode),
    'delegated coordinator arithmetic is context-sensitive');
    if (instruction.opcode !== OP.OP_INVOKE) return;
    const old = key(body[index - 1]);
    require(mapping.has(old), 'coordinator arithmetic callee is not owned');
    body[index - 1] = decodeAuthenticationInstructions(
      encodeDataPush(Uint8Array.from(Buffer.from(mapping.get(old), 'hex'))))[0];
    calls[old] = (calls[old] ?? 0) + 1;
  });
  return { bytecode: encode(body), info: { privateBytesRemoved: removed, calls } };
}

// The trusted root enforces the final worker-locking commitment before importing code.
export function fuseCoordinatorHead({argumentBytes, prefix, head, delegated, libraryLoad,
  workers, compileBinding, workerPrelude = new Uint8Array()}) {
  require(workers.length === 8 && workers.every((worker, index) => worker.input === index + 1),
    'nine-input workers must own the ordered physical inputs');
  require(!decodeAuthenticationInstructions(delegated).some(instruction =>
    [OP.OP_ACTIVEBYTECODE, OP.OP_CODESEPARATOR, OP.OP_RETURN].includes(instruction.opcode)),
  'delegated coordinator must be context-free');
  const redeems = new Map(workers.map(worker => [worker.block, Uint8Array.from(worker.redeem)]));
  const parts = [];
  let cursor = 0;
  for (const block of [5, 8, 11, 16]) {
    const worker = workers.find(item => item.block === block);
    require(worker !== undefined, 'coordinator funding carrier is missing');
    const instructions = decodeAuthenticationInstructions(worker.redeem), funding = instructions[0];
    require(funding.opcode === OP.OP_PUSHDATA_2 && funding.data.every(byte => byte === 0) &&
      instructions[1].opcode === OP.OP_DROP, 'canonical worker funding prefix changed');
    const count = Math.min(funding.data.length, delegated.length - cursor);
    require(count > 0, 'unexpected unused coordinator funding carrier');
    redeems.get(block).set(delegated.slice(cursor, cursor + count), 3);
    parts.push({block, input:worker.input, start:3, bytes:count, capacity:funding.data.length});
    cursor += count;
  }
  const overflow = delegated.slice(cursor), first = workers.find(worker => worker.block === 0);
  require(first !== undefined && overflow.length > 0, 'coordinator First/Tail overflow owner changed');
  const push = encodeDataPush(overflow);
  redeems.set(0, concat(push, Uint8Array.of(OP.OP_DROP), redeems.get(0)));
  parts.push({block:0, input:first.input, start:push.length-overflow.length,
    bytes:overflow.length, capacity:overflow.length});
  if(workerPrelude.length){
    for(const worker of workers)redeems.set(worker.block,concat(workerPrelude,redeems.get(worker.block)));
    for(const part of parts)part.start+=workerPrelude.length;
  }
  require(binToHex(concat(...parts.map(part => redeems.get(part.block)
    .slice(part.start, part.start + part.bytes)))) === binToHex(delegated),
  'coordinator code pages do not reconstruct the exact program');
  const digest = sha256(concat(...workers.map(worker => locking(redeems.get(worker.block)))));
  const binder = compileBinding(digest);
  require(!decodeAuthenticationInstructions(binder).some(instruction =>
    [OP.OP_DEFINE, OP.OP_INVOKE, OP.OP_ACTIVEBYTECODE, OP.OP_CODESEPARATOR, OP.OP_RETURN]
      .includes(instruction.opcode)), 'worker binding must remain immutable inline code');
  const loader = concat(...parts.flatMap((part, index) => [
    pushNumber(part.input), Uint8Array.of(OP.OP_INPUTBYTECODE, OP.OP_SIZE),
    pushNumber(redeems.get(part.block).length), Uint8Array.of(OP.OP_SUB, OP.OP_SPLIT, OP.OP_NIP),
    slice(part.start, part.start + part.bytes), ...(index === 0 ? [] : [Uint8Array.of(OP.OP_CAT)]),
  ]));
  const id = encodeDataPush(Uint8Array.of(0x12));
  const coordinator = concat(prefix, rootFrameGuard(argumentBytes), binder,
    Uint8Array.of(OP.OP_VERIFY), workerPrelude, libraryLoad,
    Uint8Array.of(OP.OP_TOALTSTACK, OP.OP_TOALTSTACK, OP.OP_TOALTSTACK),
    loader, id, Uint8Array.of(OP.OP_DEFINE), id, Uint8Array.of(OP.OP_INVOKE, OP.OP_VERIFY),
    Uint8Array.of(OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK), head);
  require(coordinator.length > 255 && encodeDataPush(coordinator).length - coordinator.length === 3,
    'root redeem must have the three-byte minimal PUSHDATA2 header');
  return {coordinator, workers:redeems, info:{argumentBytes, rootProgramBytes:coordinator.length,
    delegatedBytes:delegated.length, overflowBytes:overflow.length, prefixBytes:prefix.length,
    bindingBytes:binder.length, loaderBytes:loader.length, headBytes:head.length,workerPreludeBytes:workerPrelude.length,
    functionKey:'12', parts, siblingDigest:binToHex(digest)}};
}
