import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {OpcodesBCH, encodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import {functions, main} from './program.mjs';
import {BLS_X} from './field.mjs';

// Keep data-push lengths as unsigned wire lengths. The generic text assembler
// treats lengths 128..255 as signed Script numbers and changes their encoding.
export function assemble(body, identifiers) {
  const tokens = body.trim().split(/\s+/);
  const encoded = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === 'CALL' || token === 'CONST') {
      const name = tokens[++i];
      const value = token === 'CALL' ? identifiers.get(name) : name === 'BLS_X' ? BLS_X : undefined;
      assert(value !== undefined, `unknown ${token}: ${name}`);
      encoded.push(...encodeDataPush(bigIntToVmNumber(BigInt(value))));
      if (token === 'CALL') encoded.push(OpcodesBCH.OP_INVOKE);
      continue;
    }
    const opcode = OpcodesBCH[token];
    assert(Number.isInteger(opcode), `unknown opcode: ${token}`);
    if (opcode > 0 && opcode <= 78) {
      const length = opcode < 76 ? opcode : Number(tokens[++i]);
      const hex = tokens[++i];
      assert(/^0x(?:[0-9a-f]{2})+$/.test(hex), `invalid push: ${hex}`);
      const data = Uint8Array.from(Buffer.from(hex.slice(2), 'hex'));
      assert.equal(data.length, length);
      encoded.push(...encodeAuthenticationInstructions([{opcode, data}]));
    } else {
      assert(opcode !== OpcodesBCH.OP_INVOKE && opcode !== OpcodesBCH.OP_DEFINE,
        'function identifiers must use symbolic declarations/calls');
      encoded.push(opcode);
    }
  }
  return Uint8Array.from(encoded);
}

export function build(identifiers = new Map(functions.map(f => [f.name, f.originalId]))) {
  assert.equal(identifiers.size, functions.length);
  const keys = [...identifiers.values()].map(n => Buffer.from(bigIntToVmNumber(BigInt(n))).toString('hex'));
  assert.equal(new Set(keys).size, functions.length, 'duplicate function identifier');
  const declarations = functions.map(f => ({...f, bytecode: assemble(f.body, identifiers)}));
  const mainBytecode = assemble(main, identifiers);
  const bytecode = Uint8Array.from([
    ...declarations.flatMap(f => [
      ...encodeDataPush(f.bytecode),
      ...encodeDataPush(bigIntToVmNumber(BigInt(identifiers.get(f.name)))),
      OpcodesBCH.OP_DEFINE,
    ]),
    ...mainBytecode,
  ]);
  return {bytecode, declarations, mainBytecode};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert(process.argv[2], 'usage: node build.mjs output.json');
  const {bytecode, declarations, mainBytecode} = build();
  const sha256 = createHash('sha256').update(bytecode).digest('hex');
  assert.equal(bytecode.length, 3425);
  assert.equal(sha256, '44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1');
  writeFileSync(process.argv[2], JSON.stringify({
    status: 'PASS recovered symbolic source emits exact frozen leader',
    historicalCompilerRecovered: false,
    lockingBytes: bytecode.length, lockingSha256: sha256,
    functionCount: declarations.length, mainBytes: mainBytecode.length,
    lockingHex: Buffer.from(bytecode).toString('hex'),
  }, null, 2) + '\n');
  console.log(JSON.stringify({lockingBytes: bytecode.length, sha256}));
}
