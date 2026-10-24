// Apply two typed frame gates to the exact frozen registered BN254 grouped26 artifact.
// Usage: node chunked/grouped/repair_registered26.mjs original.json positives.json
// This artifact repair does not execute or certify the newer signed-Miller producer.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const manifest=JSON.parse(readFileSync(new URL('./registered26-repair.json',import.meta.url),'utf8'));
const sha256=b=>createHash('sha256').update(b).digest();
const digest=b=>sha256(b).toString('hex');
const hash256=b=>sha256(sha256(b));
const repairs=new Map(manifest.repairs.map(r=>[r.input,r]));
assert.equal(manifest.originalProgramSha256.length,26);
assert.equal(manifest.selectedProgramSha256.length,26);
assert.deepEqual([...repairs.keys()],[5,25]);
for(const r of repairs.values()){
 const typed=manifest.typedGuards.find(t=>t.length===r.requiredLength);
 assert(typed);assert.equal(digest(Buffer.from(typed.source)),typed.sourceSha256);
 assert.equal(typed.gateHex.slice(0,2),'76');
 assert([2,12].includes(r.argumentDepth));
 assert.equal(r.gateHex,`${(80+r.argumentDepth).toString(16)}79${typed.gateHex.slice(2)}`);
}

function pushes(bytes){
 const rows=[];let offset=0;
 while(offset<bytes.length){
  const start=offset,op=bytes[offset++];let data;
  if(op===0)data=Buffer.alloc(0);
  else if(op===79)data=Buffer.from([129]);
  else if(op>=81&&op<=96)data=Buffer.from([op-80]);
  else{
   let length=op;
   if(op>75){assert(op===76||op===77||op===78,'unlocking must be push-only');const width=op===76?1:op===77?2:4;assert(offset+width<=bytes.length);length=bytes.readUIntLE(offset,width);offset+=width;}
   assert(offset+length<=bytes.length);data=bytes.subarray(offset,offset+length);offset+=length;
  }
  rows.push({start,end:offset,data});
 }
 return rows;
}

// Only executable code is pushed anew. Existing argument pushes remain byte-for-byte intact.
function pushCode(bytes){
 assert(bytes.length>1&&bytes.length<=65535);
 const header=bytes.length<=75?Buffer.from([bytes.length]):bytes.length<=255?Buffer.from([76,bytes.length]):Buffer.from([77,bytes.length&255,bytes.length>>>8]);
 return Buffer.concat([header,bytes]);
}
export function lockingBytecode(body){return Buffer.concat([Buffer.from('aa20','hex'),hash256(body),Buffer.from('87','hex')]);}
export function repairBody(body,input){
 assert(Number.isInteger(input)&&input>=0&&input<26);
 assert.equal(digest(body),manifest.originalProgramSha256[input],`original body ${input}`);
 const r=repairs.get(input);
 if(r){assert.equal(body[0],0x75);assert.equal(digest(body.subarray(0,r.gateOffset)),r.registryPrefixSha256);}
 const selected=r?Buffer.concat([body.subarray(0,r.gateOffset),Buffer.from(r.gateHex,'hex'),body.subarray(r.gateOffset)]):body;
 assert.equal(digest(selected),manifest.selectedProgramSha256[input],`selected body ${input}`);
 return selected;
}

function repairRun(run){
 assert.equal(run.steps.length,26);assert.deepEqual(run.groups.map(g=>[g.lo,g.hi]),[[0,8],[9,17],[18,25]]);
 const steps=run.steps.map((step,input)=>{
  const unlocking=Buffer.from(step.unlocking,'hex'),args=pushes(unlocking),final=args.at(-1);assert(final);
  assert(pushCode(final.data).equals(unlocking.subarray(final.start)),'noncanonical final code push');
  assert.equal(lockingBytecode(final.data).toString('hex'),step.locking,`original P2SH32 ${input}`);
  const r=repairs.get(input);if(r){assert.equal(args.length,r.argumentDepth+3);assert.equal(args[0].data.length,r.requiredLength);}
  const selected=repairBody(final.data,input),prefix=unlocking.subarray(0,final.start),next=Buffer.concat([prefix,pushCode(selected)]);
  assert(next.subarray(0,prefix.length).equals(prefix));
  return {...step,locking:lockingBytecode(selected).toString('hex'),unlocking:next.toString('hex')};
 });
 const groups=run.groups.map((g,i)=>{
  if(i+1<run.groups.length){
   const next=run.groups[i+1].lo;
   assert.equal(g.outLocking,run.steps[next].locking);
   // Neither gate changes a group genesis, so commitments and output locking remain exact.
   assert.equal(steps[next].locking,run.steps[next].locking);
  }else assert.equal(g.outLocking,null);
  return {...g};
 });
 return {...run,steps,groups};
}

export function repairPositiveArtifact(originalBytes){
 assert.equal(digest(originalBytes),manifest.inputFixtureSha256,'requires exact frozen registered grouped26 artifact');
 const original=JSON.parse(originalBytes.toString('utf8'));assert.equal(original.extraValidProofs.length,1);
 const valid=repairRun(original.valid);
 return {
  description:'Frozen registered BN254 grouped26 mathematical repair: exact228-byte table carrier and1664-byte terminal owner; original positive contexts only. Native admission HOLD.',
  method:original.method,deployment:original.deployment,category:original.category,numInputs:26,numGroups:3,budgetPerInput:original.budgetPerInput,
  totalBytes:valid.steps.reduce((n,s)=>n+(s.locking.length+s.unlocking.length)/2,0),valid,
  extraValidProofs:original.extraValidProofs.map(repairRun),worstCaseProof:repairRun(original.worstCaseProof),
  repair:{schema:manifest.schema,originalFixtureSha256:manifest.inputFixtureSha256,selectedProgramSha256:manifest.selectedProgramSha256,statement:manifest.statement,premises:manifest.premises,nativeAdmission:'HOLD',standardAdmission:'HOLD',producer:'This tool repairs only the frozen registered artifacts; it does not execute or certify the current signed-Miller producer.',negatives:'Original negative fixtures remain in the unchanged historical artifact; none are generated or included here.'},
 };
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [input,output,...extra]=process.argv.slice(2);assert(input&&output&&extra.length===0,'usage: node repair_registered26.mjs <exact-original.json> <new-positive-only.json>');assert.notEqual(resolve(input),resolve(output));
 const packet=repairPositiveArtifact(readFileSync(input));writeFileSync(output,`${JSON.stringify(packet,null,2)}\n`,{flag:'wx'});
 console.log(JSON.stringify({inputs:26,positiveContexts:3,guardedPrograms:2,nativeAdmission:'HOLD',output}));
}
