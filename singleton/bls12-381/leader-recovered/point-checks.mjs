import assert from 'node:assert/strict';
import {OpcodesBCH, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import {program, candidateIdentifiers} from './compact.mjs';
import {assemble} from './build.mjs';
import {completeG2Decoder} from './complete-points.mjs';

// Private research profile. These checks enforce canonical compressed coordinates
// and the curve equations. Subgroup membership remains a separate obligation.
const field = depth => `OP_${depth} OP_PICK OP_DUP OP_0 OP_GREATERTHANOREQUAL
  OP_VERIFY CALL fieldPrime OP_LESSTHAN OP_VERIFY`;
const bit = depth => `OP_${depth} OP_PICK OP_0 OP_2 OP_WITHIN OP_VERIFY`;

export function checkedPoints() {
  const declarations = program.declarations.map(original => {
    let body = original.body;
    if (original.name === 'decompressG1') {
      assert.equal((body.match(/CALL sqrtFp/g) ?? []).length, 1);
      body = `${field(0)} ${bit(1)} ` + body.replace('CALL sqrtFp',
        'OP_DUP CALL sqrtFp OP_DUP OP_DUP CALL mulFp OP_ROT OP_NUMEQUALVERIFY');
    } else if (original.name === 'decompressG2') {
      body = `${field(0)} ${field(1)} ${bit(2)} ${bit(3)} ${completeG2Decoder()}`;
    }
    return body === original.body ? original : {
      ...original, body, bytecode: assemble(body, candidateIdentifiers),
    };
  });
  const prefix = declarations.flatMap(f => [
    ...encodeDataPush(f.bytecode),
    ...encodeDataPush(bigIntToVmNumber(BigInt(candidateIdentifiers.get(f.name)))),
    OpcodesBCH.OP_DEFINE,
  ]);
  return {...program, declarations,
    bytecode: Uint8Array.from([...prefix, ...program.mainBytecode])};
}
