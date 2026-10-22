import { createHash } from 'node:crypto';
import {
  bigIntToVmNumber, binToHex, decodeAuthenticationInstructions,
  encodeAuthenticationInstructions, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, OpcodesBCH as OP,
} from '@bitauth/libauth';

const require = (condition, message) => {
  if (!condition) throw new Error(message);
};
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(Buffer.from)));
const sha256 = bytes => Uint8Array.from(createHash('sha256').update(bytes).digest());
const pushNumber = value => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const encode = instructions => encodeAuthenticationInstructions(instructions);
const key = instruction => instruction.data !== undefined ? binToHex(instruction.data)
  : instruction.opcode === 0 ? '' : instruction.opcode === 79 ? '81'
    : instruction.opcode >= 81 && instruction.opcode <= 96
      ? (instruction.opcode - 80).toString(16).padStart(2, '0') : undefined;
const slice = (start, end) => concat(
  pushNumber(end), Uint8Array.of(OP.OP_SPLIT, OP.OP_DROP),
  ...(start === 0 ? [] : [pushNumber(start), Uint8Array.of(OP.OP_SPLIT, OP.OP_NIP)]),
);

// Carried code executes only after the original immutable sibling-locking check.
// Funding data keeps its encoded width and host PUSH/DROP behavior; no padding is added.
export function carryCoordinatorTail(coordinator, workers, limit) {
  require(workers.every((worker, index) => worker.input === index + 1),
    'coordinator workers must own the complete ordered physical inputs');
  const slots = [5, 8].map(block => {
    const worker = workers.find(item => item.block === block);
    require(worker !== undefined, 'coordinator tail funding carrier is missing');
    const instructions = decodeAuthenticationInstructions(worker.redeem);
    require(instructions[0].opcode === OP.OP_PUSHDATA_2 &&
      instructions[0].data?.every(byte => byte === 0) &&
      instructions[1].opcode === OP.OP_DROP, 'canonical zero funding prefix changed');
    return { ...worker, start: 3, capacity: instructions[0].data.length };
  });
  require(Number.isInteger(limit) && limit > 0 &&
    limit <= slots.reduce((sum, slot) => sum + slot.capacity, 0),
  'coordinator tail limit exceeds existing funding payloads');
  const locking = redeem => encodeLockingBytecodeP2sh32(hash256(redeem));
  const digest = sha256(concat(...workers.map(worker => locking(worker.redeem))));
  const instructions = decodeAuthenticationInstructions(coordinator);
  require(instructions.every(instruction => !instruction.malformed), 'malformed coordinator');
  const offsets = [0];
  instructions.forEach(instruction => offsets.push(offsets.at(-1) + encode([instruction]).length));
  const sites = instructions.flatMap((instruction, index) =>
    instruction.data !== undefined && binToHex(instruction.data) === binToHex(digest)
      ? [index] : []);
  require(sites.length === 1 && encode([instructions[sites[0]]]).length === 33 &&
    instructions[sites[0] + 1]?.opcode === OP.OP_EQUALVERIFY,
  'unique immutable sibling-locking check changed');
  const bindingEnd = offsets[sites[0] + 2];
  const keys = new Set();
  const inspectKeys = bytes => {
    const body = decodeAuthenticationInstructions(bytes);
    body.forEach((instruction, index) => {
      if (![OP.OP_DEFINE, OP.OP_INVOKE].includes(instruction.opcode)) return;
      require(index > 0 && key(body[index - 1]) !== undefined,
        'coordinator function key must be literal');
      keys.add(key(body[index - 1]));
      if (instruction.opcode === OP.OP_DEFINE && body[index - 2]?.data !== undefined)
        inspectKeys(body[index - 2].data);
    });
  };
  inspectKeys(coordinator);
  require(!keys.has('12'), 'coordinator tail function key is already owned');
  let conditional = 0, loop = 0;
  const cuts = [];
  instructions.forEach((instruction, index) => {
    if (conditional === 0 && loop === 0 && offsets[index] >= bindingEnd &&
      offsets[index] >= coordinator.length - limit) cuts.push(index);
    if ([OP.OP_IF, OP.OP_NOTIF].includes(instruction.opcode)) conditional += 1;
    if (instruction.opcode === OP.OP_ENDIF) conditional -= 1;
    if (instruction.opcode === OP.OP_BEGIN) loop += 1;
    if (instruction.opcode === OP.OP_UNTIL) loop -= 1;
    require(conditional >= 0 && loop >= 0, 'unbalanced coordinator control flow');
  });
  require(conditional === 0 && loop === 0 && cuts.length > 0, 'no balanced coordinator tail');
  const index = cuts[0], cut = offsets[index], tail = coordinator.slice(cut);
  require(tail.length > 0 && tail.length <= limit, 'invalid coordinator tail width');
  const tailInstructions = instructions.slice(index);
  require(tailInstructions.every(instruction => ![
    OP.OP_ACTIVEBYTECODE, OP.OP_CODESEPARATOR, OP.OP_RETURN, OP.OP_DEFINE,
  ].includes(instruction.opcode)), 'coordinator tail is context-sensitive or defines helpers');
  tailInstructions.forEach((instruction, position) => {
    if (instruction.opcode === OP.OP_INVOKE)
      require(position > 0 && keys.has(key(tailInstructions[position - 1])),
        'coordinator tail has an unknown callee');
  });
  const redeems = new Map(workers.map(worker => [worker.block, Uint8Array.from(worker.redeem)]));
  const parts = [];
  let cursor = 0;
  for (const slot of slots) {
    if (cursor === tail.length) break;
    const count = Math.min(slot.capacity, tail.length - cursor);
    redeems.get(slot.block).set(tail.slice(cursor, cursor + count), slot.start);
    parts.push({ block: slot.block, input: slot.input, start: slot.start,
      capacity: slot.capacity, programLength: slot.redeem.length, bytes: count });
    cursor += count;
  }
  require(cursor === tail.length, 'coordinator tail does not fit funding payloads');
  const nextDigest = sha256(concat(...workers.map(worker => locking(redeems.get(worker.block)))));
  const prefix = Uint8Array.from(coordinator.slice(0, cut));
  prefix.set(encodeDataPush(nextDigest), offsets[sites[0]]);
  const loads = concat(...parts.flatMap((part, position) => [
    pushNumber(part.input), Uint8Array.of(OP.OP_INPUTBYTECODE, OP.OP_SIZE),
    pushNumber(part.programLength), Uint8Array.of(OP.OP_SUB, OP.OP_SPLIT, OP.OP_NIP),
    slice(part.start, part.start + part.bytes),
    ...(position === 0 ? [] : [Uint8Array.of(OP.OP_CAT)]),
  ]));
  const rawKey = encodeDataPush(Uint8Array.of(0x12));
  const redeem = concat(prefix, loads, rawKey, Uint8Array.of(OP.OP_DEFINE),
    rawKey, Uint8Array.of(OP.OP_INVOKE));
  require(redeem.length < coordinator.length, 'coordinator tail increases total bytecode');
  return { coordinator: redeem, workers: redeems, info: {
    cut, carriedBytes: tail.length, originalProgramBytes: coordinator.length,
    programBytes: redeem.length, bytesSaved: coordinator.length - redeem.length,
    functionKey: '12', tailSha256: binToHex(sha256(tail)), parts,
    remainingCarrierZeroBytes: parts.reduce((sum, part) => sum + part.capacity - part.bytes, 0),
  } };
}
