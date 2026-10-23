// Symbolic assembler of ../densless-msm-spec/build.mjs, copied verbatim (that module also loads the
// co-8 MSM compiler; this build uses only zk-language for its MSM). Same tokens, same bytes.
import assert from 'node:assert/strict';
import {OpcodesBCH, encodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import {BASE_FIELD, SCALAR_FIELD, layout} from '../densless-recovered/constants.mjs';

const numbers = {
  BASE_FIELD, SCALAR_FIELD, SQUARE_BIAS: 64n * BASE_FIELD,
  FRAGMENT_OFFSET: BigInt(layout.fragmentOffset),
  ...Object.fromEntries(layout.fragmentLengths.map((length, i) => [`FRAGMENT_${i}_BYTES`, BigInt(length)])),
};

// Preserve explicit push opcodes and unsigned payload lengths. Symbols describe
// static function references; INVOKE_STACK preserves the two dynamic sites.
export function assemble(body, identifiers, data = {}) {
  const tokens = body.trim() ? body.trim().split(/\s+/) : [];
  const encoded = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['CALL', 'DEFINE_STACK', 'NUM', 'DATA'].includes(token)) {
      const name = tokens[++i];
      const value = token === 'NUM' ? numbers[name] : token === 'DATA' ? data[name] : identifiers.get(name);
      assert(value !== undefined, `unknown ${token} symbol: ${name}`);
      encoded.push(...encodeDataPush(token === 'DATA' ? value : bigIntToVmNumber(BigInt(value))));
      if (token === 'CALL') encoded.push(OpcodesBCH.OP_INVOKE);
      if (token === 'DEFINE_STACK') encoded.push(OpcodesBCH.OP_DEFINE);
      continue;
    }
    if (token === 'INVOKE_STACK') {
      encoded.push(OpcodesBCH.OP_INVOKE);
      continue;
    }
    const opcode = OpcodesBCH[token];
    assert(Number.isInteger(opcode), `unknown opcode: ${token}`);
    assert(opcode !== OpcodesBCH.OP_INVOKE && opcode !== OpcodesBCH.OP_DEFINE,
      'function operations require an explicit symbolic or stack-selected form');
    if (opcode > 0 && opcode <= 78) {
      const length = opcode < 76 ? opcode : Number(tokens[++i]);
      const hex = tokens[++i];
      assert(/^0x(?:[0-9a-f]{2})+$/.test(hex), `invalid push payload: ${hex}`);
      const bytes = Buffer.from(hex.slice(2), 'hex');
      assert.equal(bytes.length, length);
      encoded.push(...encodeAuthenticationInstructions([{opcode, data: bytes}]));
    } else encoded.push(opcode);
  }
  return Buffer.from(encoded);
}

