// Reconstruction stage: consumes public VK and inputs only. The separate checker
// compares generated values against the leader artifact.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {produceAuxiliary} from './auxiliary-polynomials.mjs';
import {bn254 as b} from '@noble/curves/bn254.js';
import * as lib from '@bitauth/libauth';
const P=b.fields.Fp.ORDER,mod=x=>(x%P+P)%P,inv=x=>b.fields.Fp.inv(mod(x));
const le32=x=>Buffer.from(x.toString(16).padStart(64,'0'),'hex').reverse();
const hash=x=>createHash('sha256').update(x).digest();
export function produceGenesisAuxiliary(vk,publicInputs){
 const auxiliary=produceAuxiliary(vk,publicInputs);
 const frame=Buffer.concat([...publicInputs.map(x=>le32(BigInt(x))),le32(auxiliary.vkx.x),le32(auxiliary.vkx.y),auxiliary.blob]);
 assert.equal(frame.length,832);
 let digest=hash(frame),x,y;const skipped=[];
 for(let attempt=0;attempt<=2;attempt++){
  x=mod(lib.vmNumberToBigInt(digest.subarray(0,31),{requireMinimalEncoding:false}));
  const rhs=mod(x*x*x+3n);y=b.fields.Fp.pow(rhs,(P+1n)/4n);
  if(mod(y*y)===rhs)break;
  const rejection=b.fields.Fp.pow(mod(3n*rhs),(P+1n)/4n);
  assert.equal(mod(rejection*rejection),mod(3n*rhs));
  skipped.push(rejection);digest=hash(le32(x));
 }
 assert.equal(mod(y*y),mod(x*x*x+3n));assert.ok(skipped.length<=2);
 const tangent=mod(3n*x*x*inv(2n*y));
 const x2=mod(tangent*tangent-2n*x),y2=mod(tangent*(x-x2)-y),intercept=mod(y-tangent*x);
 const secant=mod((-y2-y)*inv(x2-x));
 const derivative=mod(2n*(x-x2)*(-y2)*inv(3n*x2*x2-2n*(-y2)*secant));
 const points=[...vk.ic,auxiliary.vkx].map(p=>({x:BigInt(p.x),y:BigInt(p.y)}));
 const weights=auxiliary.expansions;
 const terms=[[points[3],-1n,1n],[points[2],-1n,weights[1].minus],[points[2],1n,weights[1].plus],[points[1],-1n,weights[0].minus],[points[1],1n,weights[0].plus],[points[0],-1n,0n],[points[0],1n,1n]];
 const values=terms.map(([point,sign,weight])=>mod((x-point.x)*weight*inv(sign*point.y-tangent*point.x-intercept)));
 const dx=points.reduce((a,p)=>mod(a*(x-p.x)),1n),dx2=points.reduce((a,p)=>mod(a*(x2-p.x)),1n);
 values.push(inv(dx2*(x2*x2*x2+3n)),inv(dx2),inv(dx*(x*x*x+3n)),inv(dx),derivative,secant,tangent,skipped[1]??0n,skipped[0]??0n,BigInt(skipped.length),y);
 assert.equal(values.length,18);
 return {pushes:[...values.map(n=>Buffer.from(lib.bigIntToVmNumber(n))),auxiliary.blob],vkx:auxiliary.vkx};
}
