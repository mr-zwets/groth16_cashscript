import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {OpcodesBCH,decodeAuthenticationInstructions,encodeAuthenticationInstruction,encodeDataPush,bigIntToVmNumber,hexToBin,binToHex,flattenBinArray} from '@bitauth/libauth';

// The reviewed layout belongs to a fixed compiled helper hash. Scratch P stays
// below its owned arguments; existing relative-depth operands remain unchanged.
export function cachePrimeLiterals(body,layout,count){
  assert.equal(createHash('sha256').update(body).digest('hex'),layout.originalBodySha256);
  assert([3,5].includes(layout.arity)&&layout.outputs===3);
  assert(Number.isInteger(count)&&count>0&&count<=layout.primeSites.length);
  const prime=hexToBin(layout.primeHex);assert.equal(prime.length,32);
  const literal=encodeDataPush(prime),sites=new Map();
  layout.primeSites.forEach((site,index)=>{
    assert(Number.isInteger(site.offset)&&site.offset>=0&&Number.isInteger(site.depth)&&site.depth>=0&&site.depth<=16);
    assert(!sites.has(site.offset));if(index)assert(layout.primeSites[index-1].offset<site.offset);
    sites.set(site.offset,{...site,selected:index<count});
  });
  const op=OpcodesBCH,prologue=layout.arity===3?[op.OP_SWAP,op.OP_2SWAP,op.OP_ROT]:[op.OP_5,op.OP_ROLL,op.OP_2ROT,op.OP_2ROT];
  const result=[literal,Uint8Array.from(prologue)];let at=0,hits=0;
  for(const instruction of decodeAuthenticationInstructions(body)){
    assert(!('malformed'in instruction));
    const encoded=encodeAuthenticationInstruction(instruction),site=sites.get(at);
    if(site){assert.equal(binToHex(encoded),binToHex(literal));hits++;}
    result.push(site?.selected?flattenBinArray([encodeDataPush(bigIntToVmNumber(BigInt(site.depth))),Uint8Array.of(op.OP_PICK)]):encoded);
    at+=encoded.length;
  }
  assert.equal(at,body.length);assert.equal(hits,sites.size);
  result.push(Uint8Array.of(op.OP_3,op.OP_ROLL,op.OP_DROP));
  return flattenBinArray(result);
}
