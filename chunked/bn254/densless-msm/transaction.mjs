import assert from 'node:assert/strict';
import {encodeDataPush,bigIntToVmNumber} from '@bitauth/libauth';
import {build, MSM_SPLIT, CUTS, STAGE_PADS, GENESIS_PAD} from './build.mjs';
import {witness as msmWitness} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {produceWitness} from '../densless-recovered/witness.mjs';

// stagePads: zero-padding bytes for the MSM stages in the executors and the terminal (op-cost budget)
export function produceTransaction(vk,proof,publicInputs,stagePads=STAGE_PADS){
 const program=build(),w=produceWitness(vk,proof,publicInputs);
 const quotient=Buffer.concat(w.quotient.map(x=>Buffer.from(BigInt(x).toString(16).padStart(64,'0'),'hex')));
 const n0=BigInt(publicInputs[0]),n1=BigInt(publicInputs[1]);
 const m=msmWitness(n0,n1,MSM_SPLIT,CUTS),num=x=>Buffer.from(bigIntToVmNumber(x));
 const fixed32=v=>Buffer.from(v.toString(16).padStart(64,'0'),'hex').reverse();
 // MSM stage state pushes: the accumulator after witness byte CUTS[k], n0, n1 and all 64 witness bytes
 // slim layout: executors X,Y,Z,w; terminal w,X,Y,Z (n0, n1 are terminal number pushes)
 const state=k=>Buffer.concat([...(k===3?[m.w]:[]),...m.states[CUTS[k]].map(fixed32)]);
 const execPadded=STAGE_PADS.slice(0,3).some(Boolean),pad=k=>(k<3?execPadded:STAGE_PADS[3]>0)?[Buffer.alloc(stagePads[k])]:[];
 const inputs=[];let offset=0;
 for(let i=0;i<3;i++){
  const length=program.layout.quotientLengths[i];
  inputs.push([Buffer.from(w.accumulatorHeaderHex[i],'hex'),program.sharedFragments[i],Buffer.from(w.executorWitnessHex[i],'hex'),Buffer.from(w.fixedTableHex[i],'hex'),Buffer.concat([quotient.subarray(offset,offset+length),program.quotientSuffixes[i]]),...pad(i),state(i),program.redeems[i]]);
  offset+=length;
 }
 const genesis=Array(19); // sliced genesis: the densless pushes 19..39 (dead predicate, n1, n0) are gone
 for(const [index,hex]of Object.entries(w.genesisKnownPushes))if(Number(index)<19)genesis[Number(index)]=Buffer.from(hex,'hex');
 genesis[1]=Buffer.from(bigIntToVmNumber(BigInt(w.selector)));
 assert.ok(Array.from(genesis).every(x=>Buffer.isBuffer(x)));
 // genesis carries MSM part A: its pushes (wa, n1, n0) follow the genesis pad (see carrier.mjs)
 inputs.push([...genesis,Buffer.alloc(GENESIS_PAD),program.redeems[3]]);
 // the terminal carries the final MSM stage: pushes (pad), zInv, state after the redeem's own pushes
 inputs.push([Buffer.from(w.accumulatorHeaderHex[3],'hex'),quotient.subarray(offset),...w.terminalWitnessHex.map(x=>Buffer.from(x,'hex')),...pad(3),num(n1),num(n0),num(m.zInv),state(3),program.redeems[4]]);
 // the MSM's vk_x must be the one genesis push 0 carries (fields 4, 5), which the terminal stage checks
 assert.equal(m.vkx.toString('hex'),Buffer.from(w.genesisKnownPushes[0],'hex').subarray(128,192).toString('hex'));
 assert.equal(quotient.length-offset,2336);
 return inputs.map((pushes,i)=>({locking:program.lockings[i].toString('hex'),unlocking:Buffer.concat(pushes.map(p=>Buffer.from(encodeDataPush(p)))).toString('hex')}));
}
