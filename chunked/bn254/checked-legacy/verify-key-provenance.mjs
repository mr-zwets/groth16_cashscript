// Reproduce the public fixed-key and coefficient readback without executing a proof producer or VM.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {decodeAuthenticationInstructions,encodeAuthenticationInstructions} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
import * as equation from '../pairfold5-pevalfuse-deterministic/equation-guard.mjs';
import {assemble} from '../pairfold5-pevalfuse-deterministic/build.mjs';
import {equationLoader} from './guard.mjs';
const [benchmark,output]=process.argv.slice(2);
assert(benchmark && output && process.argv.length===4, 'usage: node verify-key-provenance.mjs benchmark-dir new-report.json');
const sha=b=>createHash('sha256').update(b).digest('hex');
const qualification=JSON.parse(readFileSync(new URL('./qualification.json',import.meta.url)));
assert.equal(sha(equationLoader),qualification.equationLoaderSha256,
  'the established caller proof requires the exact checked function bank');
const keyBytes=readFileSync(join(benchmark,qualification.verificationKeyOwner.file));
assert.equal(sha(keyBytes),qualification.verificationKeyOwner.sha256);
const {vk,p,r}=JSON.parse(keyBytes);
assert.equal(BigInt(p),bn254.fields.Fp.ORDER);
assert.equal(BigInt(r),bn254.fields.Fr.ORDER);
const expected=[];
const add=(name,p)=>{if(typeof p==='string')expected.push({name,value:BigInt(p)});else if(Array.isArray(p))p.forEach((v,i)=>add(name+'.'+i,v));else for(const [k,v]of Object.entries(p))add(name+'.'+k,v);};add('vk',vk);assert.equal(expected.length,20);
const ids=new Map(equation.functions.map(f=>[f.name,f.originalId]));
const bank=equation.functions.map(f=>({...f,instructions:decodeAuthenticationInstructions(assemble(f.body,ids))}));
const little=n=>Buffer.from(n.toString(16).padStart(64,'0'),'hex').reverse();
const coordinates=expected.map(({name,value})=>({name,matches:bank.flatMap(f=>f.instructions.flatMap((ins,index)=>ins.data&&Buffer.from(ins.data).equals(little(value))?[{function:f.name,id:f.originalId,instruction:index}]:[]))}));
assert(coordinates.every(c=>c.matches.length>0));
const g1=p=>bn254.G1.Point.fromAffine({x:BigInt(p.x),y:BigInt(p.y)});
const g2=p=>bn254.G2.Point.fromAffine({x:{c0:BigInt(p.x.c0),c1:BigInt(p.x.c1)},y:{c0:BigInt(p.y.c0),c1:BigInt(p.y.c1)}});
const alpha=g1(vk.alpha),beta=g2(vk.beta);[alpha,beta,g2(vk.gamma),g2(vk.delta),...vk.ic.map(g1)].forEach(p=>p.assertValidity());
const f=bn254.pairing(alpha,beta,false);const flat=[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const profile=JSON.parse(readFileSync(new URL('./profiles.json',import.meta.url))).profiles
  .find(p=>p.originalId==='bch-groth16-intratx-pairfold7');
assert(profile,'missing PairFold-7 artifact owner');
const oldBytes=readFileSync(join(benchmark,'src/bch',profile.file));
assert.equal(sha(oldBytes),profile.originalSha256);
const raw=JSON.parse(oldBytes).steps.at(-1).unlocking;const terminal=decodeAuthenticationInstructions(Buffer.from(raw,'hex')).at(-1).data;
const instructions=decodeAuthenticationInstructions(terminal);let offset=0,depth=0;
const positioned=instructions.map((i,index)=>{const row={...i,index,offset,depth};offset+=encodeAuthenticationInstructions([i]).length;if(i.opcode===0x63||i.opcode===0x64)depth++;else if(i.opcode===0x68)depth--;assert(depth>=0);return row;});
assert.equal(depth,0);
const factors=flat.map((n,limb)=>{const match=positioned.filter(i=>i.opcode===32&&i.data&&Buffer.from(i.data).equals(little(n)));assert.equal(match.length,1);assert.equal(match[0].depth,0);return {limb,instruction:match[0].index,opcodeOffset:match[0].offset,dataOffset:match[0].offset+1,hex:little(n).toString('hex')};});
const occurrences=expected.filter(x=>!x.name.startsWith('vk.alpha')&&!x.name.startsWith('vk.beta')).map(({name,value})=>({name,carriers:JSON.parse(oldBytes).steps.flatMap((step,input)=>{const bytes=Buffer.from(step.unlocking,'hex'),needle=little(value),offset=bytes.indexOf(needle);return offset<0?[]:[{input,unlockingByteOffset:offset}];})}));
assert.equal(occurrences.length,14);assert(occurrences.every(x=>x.carriers.length>0));
const first=factors[0].instruction;assert.equal(factors[1].instruction,first+1);
for(let limb=1;limb<12;limb++){const i=factors[limb].instruction;assert.equal(positioned[i+1].opcode,0x50+13-limb);assert.equal(positioned[i+2].opcode,0x79);assert.equal(positioned[i+3].opcode,0x95);assert.equal(positioned[i+4].opcode,0x93);if(limb<11)assert.equal(factors[limb+1].instruction,i+5);}
writeFileSync(output,JSON.stringify({status:'PASS_CURRENT_CHECKER_20_COORDINATES_AND_ORIGINAL_PF7_FIXED_MILLER_COEFFICIENTS',node:process.version,readbackToolSha256:sha(readFileSync(new URL(import.meta.url))),keyArtifactSha256:sha(keyBytes),equationLoaderSha256:sha(equationLoader),equationLoaderBytes:equationLoader.length,coordinates,pairfold7:{originalSha256:sha(oldBytes),terminalSha256:sha(terminal),factors,coefficientSha256:sha(Buffer.concat(flat.map(little))),pointConstantOccurrences:occurrences,encoding:'12 separate PUSH32 instruction data values, with polynomial-evaluation arithmetic between them',polynomialOwner:'Exact coefficient push and PICK/MUL/ADD block; coefficients evaluate c0+sum(ci*basis_i). The prior challenge-power basis and rest of the legacy verifier are separate unclaimed obligations.'},scope:'Public-key arithmetic and exact instruction-boundary readback only. No proof producer, fixture generation, negative suite or VM execution. The current checker bank transfers its established caller/role proof by exact byte identity; literal readback alone is not a new binding theorem. Original PairFold-7 individual alpha/beta declaration, point-role proof and full legacy verifier soundness are not established by this readback.'},null,2)+'\n',{flag:'wx'});
