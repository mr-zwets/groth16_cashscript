// Omit reviewed, uncalled neutral registrations only in the slim variant.
// The shared parent slicer and parent/spec emitted programs remain unchanged.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {sliceGenesis as sliceParentGenesis} from '../densless-msm/genesis-slice.mjs';
import {OpcodesBCH, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';

const sourceHash = "46c74d8cdca8d0f5e9c8ac01c201f3131aa7799f4cd08377130771234e4de03d";
const omittedBodies = [
  {
    "key": "06",
    "bodySha256": "e65b060ad820d00ff67b47428a384f10b38a7b8e61887fe8011efbae4a149bc6"
  },
  {
    "key": "07",
    "bodySha256": "9eec3c62285445bb9725b948e4b2e3c70d9cb6b71f1286415f081f3c6d87a127"
  },
  {
    "key": "12",
    "bodySha256": "1c1f6a7bf1936fb34330ac49ab2c61b1a860c875ca25c52ffe1934d8cab73b3d"
  },
  {
    "key": "08",
    "bodySha256": "6f1b60634d28122de8e78319a510870454ff8dcd127381aa4355626e830ba942"
  },
  {
    "key": "0b",
    "bodySha256": "07861a7b944199e7fae23794db1288dd00cef0246c393d8aa511b22c9db65a5a"
  },
  {
    "key": "15",
    "bodySha256": "cd8d4a170520728b19c4186d9f18f79117fc21a8b506251a09c1308218a68a0c"
  },
  {
    "key": "16",
    "bodySha256": "92f400c3fe7f61ed7f88b4d3c9db7529c27fe0fe119b1b00e2da24013ecfaecb"
  },
  {
    "key": "1a",
    "bodySha256": "47ba438b9ca0e2f927bac83155f2372c6438d70f0d942834944e6041a14d5ad0"
  },
  {
    "key": "1b",
    "bodySha256": "5b1b2238382250b1f665f5cb960ac716113ccd83e2eaac97f124493469df1185"
  },
  {
    "key": "1c",
    "bodySha256": "1c957e18b92848034220b1471e296905274f975e009715bb95cb24eb91026203"
  },
  {
    "key": "1d",
    "bodySha256": "d01319c53abeabe2d1b16dfe561eacba235415d0cc145380c756f339ff9a2b41"
  }
];
const keyBytes = instruction => {
  if (instruction.data !== undefined) return instruction.data;
  if (instruction.opcode === OpcodesBCH.OP_0) return new Uint8Array();
  assert(instruction.opcode >= OpcodesBCH.OP_1 && instruction.opcode <= OpcodesBCH.OP_16,
    'definition key must be a literal push');
  return Uint8Array.of(instruction.opcode - OpcodesBCH.OP_1 + 1);
};

export function sliceGenesis(program) {
  const sliced = sliceParentGenesis(program);
  assert.equal(createHash('sha256').update(sliced).digest('hex'), sourceHash,
    'slim omission input differs from the reviewed genesis');
  const instructions = decodeAuthenticationInstructions(sliced);
  assert.equal(instructions[0].opcode, OpcodesBCH.OP_DROP);
  const omitted = new Map(omittedBodies.map(({key, bodySha256}) => [key, bodySha256]));
  assert.equal(omitted.size, omittedBodies.length);
  const drop = new Set();
  for (let i = 1; i + 2 < instructions.length && instructions[i + 2].opcode === OpcodesBCH.OP_DEFINE; i += 3) {
    const key = Buffer.from(keyBytes(instructions[i + 1])).toString('hex');
    if (!omitted.has(key)) continue;
    assert(instructions[i].data !== undefined, 'definition body must be a literal push');
    assert.equal(createHash('sha256').update(instructions[i].data).digest('hex'), omitted.get(key),
      `omitted definition ${key} differs from its reviewed body`);
    omitted.delete(key);
    for (let j = i; j <= i + 2; j++) drop.add(j);
  }
  assert.equal(omitted.size, 0, 'reviewed omitted definition missing');
  return Buffer.concat(instructions.filter((_, i) => !drop.has(i))
    .map(instruction => Buffer.from(encodeAuthenticationInstruction(instruction))));
}
