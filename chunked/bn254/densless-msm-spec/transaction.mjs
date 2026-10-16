import assert from 'node:assert/strict';
import {encodeDataPush,bigIntToVmNumber} from '@bitauth/libauth';
import {build} from './build.mjs';
import {witness as msmWitness} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {produceWitness} from '../densless-recovered/witness.mjs';

export function produceTransaction(vk,proof,publicInputs){
 const program=build(),w=produceWitness(vk,proof,publicInputs);
 const quotient=Buffer.concat(w.quotient.map(x=>Buffer.from(BigInt(x).toString(16).padStart(64,'0'),'hex')));
 const inputs=[];let offset=0;
 for(let i=0;i<3;i++){
  const length=program.layout.quotientLengths[i];
  inputs.push([Buffer.from(w.accumulatorHeaderHex[i],'hex'),program.sharedFragments[i],Buffer.from(w.executorWitnessHex[i],'hex'),Buffer.from(w.fixedTableHex[i],'hex'),Buffer.concat([quotient.subarray(offset,offset+length),program.quotientSuffixes[i]]),program.redeems[i]]);
  offset+=length;
 }
 const genesis=Array(19); // sliced genesis; the carried MSM's pushes follow its pad
 for(const [index,hex]of Object.entries(w.genesisKnownPushes))if(Number(index)<19)genesis[Number(index)]=Buffer.from(hex,'hex');
 genesis[1]=Buffer.from(bigIntToVmNumber(BigInt(w.selector)));
 assert.ok(Array.from(genesis).every(x=>Buffer.isBuffer(x)));
 const m=msmWitness(BigInt(publicInputs[0]),BigInt(publicInputs[1]),0),num=x=>Buffer.from(bigIntToVmNumber(x));
 assert.equal(m.vkx.toString('hex'),Buffer.from(w.genesisKnownPushes[0],'hex').subarray(128,192).toString('hex'));
 inputs.push([...genesis,Buffer.alloc(0),num(m.zInv),Buffer.concat([m.wa,m.wb]),num(BigInt(publicInputs[1])),num(BigInt(publicInputs[0])),program.redeems[3]]);
 inputs.push([Buffer.from(w.accumulatorHeaderHex[3],'hex'),quotient.subarray(offset),...w.terminalWitnessHex.map(x=>Buffer.from(x,'hex')),program.redeems[4]]);
 assert.equal(quotient.length-offset,2336);
 return inputs.map((pushes,i)=>({locking:program.lockings[i].toString('hex'),unlocking:Buffer.concat(pushes.map(p=>Buffer.from(encodeDataPush(p)))).toString('hex')}));
}
