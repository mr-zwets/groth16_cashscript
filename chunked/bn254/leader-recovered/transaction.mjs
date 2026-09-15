import assert from 'node:assert/strict';
import {encodeDataPush,bigIntToVmNumber} from '@bitauth/libauth';
import {build} from './build.mjs';
import {produceWitness} from './witness.mjs';
import {produceGenesisAuxiliary} from './genesis-auxiliary.mjs';

export function produceTransaction(vk,proof,publicInputs){
 const program=build(),w=produceWitness(vk,proof,publicInputs),aux=produceGenesisAuxiliary(vk,publicInputs);
 assert.equal(String(aux.vkx.x),w.fields[4]);assert.equal(String(aux.vkx.y),w.fields[5]);
 const quotient=Buffer.concat(w.quotient.map(x=>Buffer.from(BigInt(x).toString(16).padStart(64,'0'),'hex')));
 const inputs=[];let offset=0;
 for(let i=0;i<3;i++){
  const length=program.layout.quotientLengths[i];
  inputs.push([Buffer.from(w.accumulatorHeaderHex[i],'hex'),program.sharedFragments[i],Buffer.from(w.executorWitnessHex[i],'hex'),Buffer.from(w.fixedTableHex[i],'hex'),Buffer.concat([quotient.subarray(offset,offset+length),program.quotientSuffixes[i]]),program.redeems[i]]);
  offset+=length;
 }
 const genesis=Array(39);
 for(const [index,hex]of Object.entries(w.genesisKnownPushes))genesis[Number(index)]=Buffer.from(hex,'hex');
 genesis[1]=Buffer.from(bigIntToVmNumber(BigInt(w.selector)));
 aux.pushes.forEach((push,i)=>genesis[17+i]=push);genesis[38]=program.redeems[3];
 assert.ok(genesis.every(x=>Buffer.isBuffer(x)));inputs.push(genesis);
 inputs.push([Buffer.from(w.accumulatorHeaderHex[3],'hex'),quotient.subarray(offset),...w.terminalWitnessHex.map(x=>Buffer.from(x,'hex')),program.terminalPadding,program.redeems[4]]);
 assert.equal(quotient.length-offset,0);
 return inputs.map((pushes,i)=>({locking:program.lockings[i].toString('hex'),unlocking:Buffer.concat(pushes.map(p=>Buffer.from(encodeDataPush(p)))).toString('hex')}));
}
