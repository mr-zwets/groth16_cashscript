import {
  bigIntToVmNumber, binToHex, decodeAuthenticationInstructions,
  encodeAuthenticationInstructions, encodeDataPush, OpcodesBCH as OP,
} from '@bitauth/libauth';

const require = (condition, message) => { if (!condition) throw new Error(message); };
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(Buffer.from)));
const number = value => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const key = instruction => instruction?.data !== undefined ? binToHex(instruction.data)
  : instruction?.opcode === 0 ? '' : instruction?.opcode === 79 ? '81'
    : instruction?.opcode >= 81 && instruction?.opcode <= 96
      ? (instruction.opcode - 80).toString(16).padStart(2, '0') : undefined;
const same = (a, b) => binToHex(a) === binToHex(b);
const rawKey = Uint8Array.of(0x67);

// Cache a literal data push, never executable bytes supplied by the witness.
export function coordinatorPrefix(headerBytes, statementBytes, {splitFields = false} = {}) {
  require(typeof splitFields === 'boolean', 'invalid prefix cache mode');
  const functionKeys = splitFields ? ['67', '68'] : ['67'];
  const prefixBytes = headerBytes + statementBytes;
  require(Number.isInteger(headerBytes) && headerBytes > 0 &&
    Number.isInteger(statementBytes) && statementBytes > 0 && prefixBytes <= 65535,
  'invalid coordinator prefix layout');
  const encoded = encodeDataPush(new Uint8Array(prefixBytes));
  require(encoded.length - prefixBytes === 3 && encoded[0] === OP.OP_PUSHDATA_2,
    'coordinator prefix requires a three-byte PUSHDATA2 header');
  const wholeInitializer = concat(Uint8Array.of(OP.OP_0, OP.OP_INPUTBYTECODE),
    number(prefixBytes), Uint8Array.of(OP.OP_SPLIT, OP.OP_DROP),
    encodeDataPush(encoded.slice(0, 3)), Uint8Array.of(OP.OP_SWAP, OP.OP_CAT),
    encodeDataPush(rawKey), Uint8Array.of(OP.OP_DEFINE));
  const fieldHeader = bytes => {
    const data = encodeDataPush(new Uint8Array(bytes));
    return data.slice(0, data.length - bytes);
  };
  const defineField = (bytes, id) => concat(encodeDataPush(fieldHeader(bytes)),
    Uint8Array.of(OP.OP_SWAP, OP.OP_CAT), encodeDataPush(Uint8Array.of(id)),
    Uint8Array.of(OP.OP_DEFINE));
  const initializer = splitFields ? concat(
    Uint8Array.of(OP.OP_0, OP.OP_INPUTBYTECODE), number(prefixBytes),
    Uint8Array.of(OP.OP_SPLIT, OP.OP_DROP), number(headerBytes),
    Uint8Array.of(OP.OP_SPLIT), defineField(statementBytes, 0x68),
    defineField(headerBytes, 0x67),
  ) : wholeInitializer;
  const call = id => decodeAuthenticationInstructions(concat(
    encodeDataPush(Uint8Array.of(id)), Uint8Array.of(OP.OP_INVOKE)));
  const inspectNamespace = instructions => {
    instructions.forEach((instruction, index) => {
      if (![OP.OP_DEFINE, OP.OP_INVOKE].includes(instruction.opcode)) return;
      const id = key(instructions[index - 1]);
      require(id !== undefined && !functionKeys.includes(id), 'coordinator prefix key is already owned');
      if (instruction.opcode === OP.OP_DEFINE) {
        require(instructions[index - 2]?.data !== undefined,
          'coordinator prefix consumer has a nonliteral definition');
        inspectNamespace(decodeAuthenticationInstructions(instructions[index - 2].data));
      }
    });
  };
  const rewrite = (bytecode, expectedSites) => {
    const instructions = decodeAuthenticationInstructions(bytecode);
    require(instructions.every(instruction => !instruction.malformed),
      'malformed coordinator prefix consumer');
    inspectNamespace(instructions);
    const mapped = [];
    let sites = 0, removedBytes = 0;
    const literal = (index, value) => instructions[index] !== undefined &&
      same(encodeAuthenticationInstructions([instructions[index]]), number(value));
    for (let index = 0; index < instructions.length; index += 1) {
      if (instructions[index].opcode !== OP.OP_0 ||
        instructions[index + 1]?.opcode !== OP.OP_INPUTBYTECODE) {
        mapped.push(instructions[index]);
        continue;
      }
      const header = literal(index + 2, headerBytes) &&
        instructions[index + 3]?.opcode === OP.OP_SPLIT;
      const boundedHeader = header && instructions[index + 4]?.opcode === OP.OP_DROP;
      const boundedStatement = header && instructions[index + 4]?.opcode === OP.OP_NIP &&
        literal(index + 5, statementBytes) && instructions[index + 6]?.opcode === OP.OP_SPLIT &&
        instructions[index + 7]?.opcode === OP.OP_DROP;
      require(boundedHeader || boundedStatement,
        'coordinator read consumes more than its header or statement prefix');
      const count = splitFields ? (boundedHeader ? 5 : 8) : 2;
      removedBytes += encodeAuthenticationInstructions(instructions.slice(index, index + count)).length;
      mapped.push(...call(splitFields && boundedStatement ? 0x68 : 0x67));
      sites += 1;
      index += count - 1;
    }
    require(sites === expectedSites, 'coordinator prefix read sites changed');
    const result = encodeAuthenticationInstructions(mapped);
    require(result.length === bytecode.length - removedBytes + 3 * sites,
      'coordinator prefix call width changed');
    return result;
  };
  return { functionKey: '67', functionKeys, prefixBytes, initializer, rewrite };
}
