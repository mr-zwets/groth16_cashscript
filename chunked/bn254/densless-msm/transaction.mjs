import assert from 'node:assert/strict';
import {encodeDataPush,bigIntToVmNumber} from '@bitauth/libauth';
import {build, MSM_SPLIT, MSM_PAD, GENESIS_PAD} from './build.mjs';
import {witness as msmWitness} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {produceWitness} from '../densless-recovered/witness.mjs';

// msmPad: zero-padding bytes for the two vk_x MSM inputs (sized to their op-cost budget)
export function produceTransaction(vk,proof,publicInputs,msmPad=MSM_PAD){
 const program=build(),w=produceWitness(vk,proof,publicInputs);
 const quotient=Buffer.concat(w.quotient.map(x=>Buffer.from(BigInt(x).toString(16).padStart(64,'0'),'hex')));
 const inputs=[];let offset=0;
 for(let i=0;i<3;i++){
  const length=program.layout.quotientLengths[i];
  inputs.push([Buffer.from(w.accumulatorHeaderHex[i],'hex'),program.sharedFragments[i],Buffer.from(w.executorWitnessHex[i],'hex'),Buffer.from(w.fixedTableHex[i],'hex'),Buffer.concat([quotient.subarray(offset,offset+length),program.quotientSuffixes[i]]),program.redeems[i]]);
  offset+=length;
 }
 const genesis=Array(19); // sliced genesis: the densless pushes 19..39 (dead predicate, n1, n0) are gone
 for(const [index,hex]of Object.entries(w.genesisKnownPushes))if(Number(index)<19)genesis[Number(index)]=Buffer.from(hex,'hex');
 genesis[1]=Buffer.from(bigIntToVmNumber(BigInt(w.selector)));
 assert.ok(Array.from(genesis).every(x=>Buffer.isBuffer(x)));
 inputs.push([...genesis,Buffer.alloc(GENESIS_PAD),program.redeems[3]]);
 inputs.push([Buffer.from(w.accumulatorHeaderHex[3],'hex'),quotient.subarray(offset),...w.terminalWitnessHex.map(x=>Buffer.from(x,'hex')),program.redeems[4]]);
 const m=msmWitness(BigInt(publicInputs[0]),BigInt(publicInputs[1]),MSM_SPLIT),num=x=>Buffer.from(bigIntToVmNumber(x));
 // the MSM's vk_x must be the one genesis push 0 carries (fields 4, 5) for the terminal binding
 assert.equal(m.vkx.toString('hex'),Buffer.from(w.genesisKnownPushes[0],'hex').subarray(128,192).toString('hex'));
 inputs.push([Buffer.alloc(msmPad.a),m.wa,num(BigInt(publicInputs[1])),num(BigInt(publicInputs[0])),program.redeems[5]]);
 inputs.push([m.vkx,m.st,m.wb,Buffer.alloc(msmPad.b),num(m.zInv),program.redeems[6]]);
 assert.equal(quotient.length-offset,2336);
 return inputs.map((pushes,i)=>({locking:program.lockings[i].toString('hex'),unlocking:Buffer.concat(pushes.map(p=>Buffer.from(encodeDataPush(p)))).toString('hex')}));
}
