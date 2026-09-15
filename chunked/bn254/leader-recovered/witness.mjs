import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import {bigIntToVmNumber} from '@bitauth/libauth';
import {residueWitness,LAMBDA,SCALING} from './root-witness.mjs';
import {deploymentTag} from './constants.mjs';
export function produceWitness(vk,proof,publicInputs){
const P=bn254.fields.Fp.ORDER,F=bn254.fields.Fp2,T=bn254.fields.Fp12;
const mod=x=>(x%P+P)%P;
const point=x=>bn254.G1.Point.fromAffine({x:BigInt(x.x),y:BigInt(x.y)});
let vkx=point(vk.ic[0]);
publicInputs.forEach((x,i)=>{const k=BigInt(x);assert.ok(k>=0n&&k<bn254.fields.Fr.ORDER);if(k!==0n)vkx=vkx.add(point(vk.ic[i+1]).multiply(k));});
const vp=vkx.toAffine();
const fields=[0n,0n,BigInt(proof.a.x),mod(-BigInt(proof.a.y)),vp.x,vp.y,BigInt(proof.c.x),BigInt(proof.c.y),BigInt(proof.b.x.c0),BigInt(proof.b.x.c1),BigInt(proof.b.y.c0),BigInt(proof.b.y.c1),0n,0n];
const flat = x => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const factorRows=[];
const line = (cy, cx, cb, x, y) => { const value=({ c0: { c0: F.mul(cy, { c0: y, c1: 0n }), c1: F.ZERO, c2: F.ZERO },
  c1: { c0: F.mul(cx, { c0: x, c1: 0n }), c1: cb, c2: F.ZERO } }); factorRows.at(-1).push(value); return value; };
const points = [
  bn254.G2.Point.fromAffine({ x: { c0: fields[8], c1: fields[9] }, y: { c0: fields[10], c1: fields[11] } }),
  ...['gamma', 'delta'].map(key => bn254.G2.Point.fromAffine({
    x: { c0: BigInt(vk[key].x.c0), c1: BigInt(vk[key].x.c1) },
    y: { c0: BigInt(vk[key].y.c0), c1: BigInt(vk[key].y.c1) },
  })),
];
points.forEach(point => point.assertValidity());
const running = [...points], digits = [];
for (let n = 6n * 4965661367192848881n + 2n; n > 1n; n >>= 1n) {
  if (!(n & 1n)) digits.unshift(0);
  else if ((n & 3n) === 3n) { digits.unshift(-1); n++; }
  else digits.unshift(1);
}

// Public Miller arithmetic: no imported initial state or inverse witness enters raw.
const slopeRows=Array.from({length:65},()=>[]);
const bPointsAfter={};
let raw=T.ONE;
for(let event=0;event<digits.length;event++) {
 factorRows.push([]);
 raw=T.sqr(raw);
 for(let pair=0;pair<3;pair++) {
  const a=running[pair].toAffine(),slope=F.div(F.mul(F.sqr(a.x),{c0:3n,c1:0n}),F.add(a.y,a.y));
  const scale=pair===0?F.neg(F.add(a.y,a.y)):event===64?F.ONE:F.add(a.y,a.y);
  raw=T.mul(raw,line(scale,F.mul(F.neg(slope),scale),F.mul(F.sub(F.mul(slope,a.x),a.y),scale),fields[2+2*pair],fields[3+2*pair]));
  if(pair===0)slopeRows[event].push(slope.c0,slope.c1);
  running[pair]=running[pair].double();
  if(digits[event]) {
   const target=digits[event]<0?points[pair].negate():points[pair],b=target.toAffine(),a=running[pair].toAffine();
   const slope=F.div(F.sub(b.y,a.y),F.sub(b.x,a.x)),scale=pair===0?F.sub(a.x,b.x):F.ONE;
   raw=T.mul(raw,line(scale,F.mul(F.neg(slope),scale),F.mul(F.sub(F.mul(slope,a.x),a.y),scale),fields[2+2*pair],fields[3+2*pair]));
   if(pair===0)slopeRows[event].push(slope.c0,slope.c1);
   running[pair]=running[pair].add(target);
  }
 }
 const a=running[0].toAffine();bPointsAfter[event]=[a.x.c0,a.x.c1,a.y.c0,a.y.c1];
}

const {psi}=psiFrobenius(bn254.fields.Fp,F,F.NONRESIDUE);
for(let pair=0;pair<3;pair++) {
 const q=points[pair].toAffine(),q1=psi(q.x,q.y),q2=psi(q1[0],q1[1]);
 for(const b of [{x:q1[0],y:q1[1]},{x:q2[0],y:F.neg(q2[1])}]) {
  const a=running[pair].toAffine(),slope=F.div(F.sub(b.y,a.y),F.sub(b.x,a.x)),scale=pair===0?F.sub(a.x,b.x):F.ONE;
  raw=T.mul(raw,line(scale,F.mul(F.neg(slope),scale),F.mul(F.sub(F.mul(slope,a.x),a.y),scale),fields[2+2*pair],fields[3+2*pair]));
  if(pair===0)slopeRows[64].push(slope.c0,slope.c1);
  running[pair]=running[pair].add(bn254.G2.Point.fromAffine(b));
 }
}
const alpha=bn254.G1.Point.fromAffine({x:BigInt(vk.alpha.x),y:BigInt(vk.alpha.y)});
const beta=bn254.G2.Point.fromAffine({x:{c0:BigInt(vk.beta.x.c0),c1:BigInt(vk.beta.x.c1)},y:{c0:BigInt(vk.beta.y.c0),c1:BigInt(vk.beta.y.c1)}});
raw=T.mul(raw,bn254.pairing(alpha,beta,false));
assert.ok(T.eql(T.finalExponentiate(raw),T.ONE));

const witness=residueWitness(raw);
assert.ok(T.eql(T.pow(witness.c,LAMBDA),T.mul(raw,witness.w)));

const polynomial=c=>{
 const out=Array(12).fill(0n);
 for(const [i,d] of [0,2,4,1,3,5].entries()){out[d]=mod(c[2*i]-9n*c[2*i+1]);out[d+6]=c[2*i+1];}
 return out;
};
const multiply=(a,b)=>{
 const out=Array(a.length+b.length-1).fill(0n);
 for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)out[i+j]=mod(out[i+j]+a[i]*b[j]);
 return out;
};
assert.equal(factorRows.length,65);
factorRows[64].push(bn254.pairing(alpha,beta,false));
let accumulated=polynomial(flat(witness.cInv));
const aggregate=Array(190).fill(0n),states=[],quotients=[];
for(let event=0;event<65;event++) {
 accumulated=multiply(accumulated,accumulated);
 for(const factor of factorRows[event]) accumulated=multiply(accumulated,polynomial(flat(factor)));
 if(digits[event]) accumulated=multiply(accumulated,polynomial(flat(digits[event]<0?witness.c:witness.cInv)));
 if(event===0 || event%2===1 || event===64) {
 const residual=[...accumulated],q=Array(Math.max(1,residual.length-12)).fill(0n);
 for(let i=residual.length-1;i>=12;i--){const v=residual[i];q[i-12]=v;residual[i]=0n;residual[i-6]=mod(residual[i-6]+18n*v);residual[i-12]=mod(residual[i-12]-82n*v);}
 const reduced=residual.slice(0,12);
 const exponent=event===0?0:event===64?33:(event+1)/2;
 while(q.length>1&&q.at(-1)===0n)q.pop();
 assert.ok(q.length<=190);

 accumulated=reduced;
 // Invert the tower-to-polynomial map to produce wire coefficients.
 const c=Array(12).fill(0n);
 for(const [i,d] of [0,2,4,1,3,5].entries()){c[2*i+1]=reduced[d+6];c[2*i]=mod(reduced[d]+9n*reduced[d+6]);}
 states.push({event,coefficients:c.map(String)});quotients.push({event,degree:q.length-1,weightExponent:exponent,coefficients:q});
 }
}

const hash=b=>createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const be32=x=>Buffer.from(x.toString(16).padStart(64,'0'),'hex');
const u32=x=>{const b=Buffer.alloc(4);b.writeUInt32BE(x);return b;};
const fingerprint=c=>mod(c.reduce((sum,x,i)=>sum+BigInt(x)*7n**BigInt(i),0n));
const selector=[T.ONE,SCALING,T.sqr(SCALING)].findIndex(x=>T.eql(x,witness.w));
assert.ok(selector>=0);
// Pinned deployment tag embedded at genesis instruction1267. Historical tag derivation is unavailable.
const tag=deploymentTag;
const payload=Buffer.concat([[fields[2],mod(-fields[3]),...fields.slice(8,12),fields[6],fields[7],fields[4],fields[5]].map(be32),[tag],flat(witness.c).map(be32),flat(witness.cInv).map(be32),[Buffer.from([selector])]].flat());
assert.equal(payload.length,1121);
let digest=hash(Buffer.from('BN254-SZ/g/v4-s-vk'));
digest=hash(Buffer.concat([digest,u32(0),u32(payload.length),payload]));
const fps=[fingerprint(flat(witness.cInv)),...states.map(s=>fingerprint(s.coefficients))];
const stateDigests={};
for(const [i,value] of fps.entries()){
 digest=hash(Buffer.concat([digest,u32(i+1),u32(32),be32(value)]));
 if(i>0)stateDigests[states[i-1].event]=digest;
}
fields[0]=mod(BigInt('0x'+hash(Buffer.concat([digest,Buffer.from('BN254-SZ/gf/v4-s-vk'),u32(36)])).toString('hex')));
for(const q of quotients){const weight=mod(fields[0]**BigInt(q.weightExponent));q.coefficients.forEach((v,i)=>aggregate[i]=mod(aggregate[i]+weight*v));}
fields[1]=mod(BigInt('0x'+hash(Buffer.concat([Buffer.from('BN254-SZ/z/v4-s-vk'),be32(fields[0]),...aggregate.map(be32)])).toString('hex')));
const z=fields[1],basis=[];
for(const d of [0n,2n,4n,1n,3n,5n])basis.push(mod(z**d),mod(z**d*(z**6n-9n)));
[ witness.c,witness.cInv ].forEach((x,i)=>fields[12+i]=mod(flat(x).reduce((sum,c,j)=>sum+c*basis[j],0n)));
const fixedTables=[[],[],[]];
for(let event=1;event<=63;event++){
 const row=factorRows[event],stride=digits[event]?2:1;
 const values=[];
 for(let column=0;column<stride;column++){
  const gamma=flat(row[stride+column]),delta=flat(row[2*stride+column]);
  const ge=mod(gamma.reduce((sum,x,i)=>sum+x*basis[i],0n)),de=mod(delta.reduce((sum,x,i)=>sum+x*basis[i],0n));
  values.push(mod(ge*de));
 }
 fixedTables[event<=21?0:event<=41?1:2].push(...values);
}
const fixedTableHex=fixedTables.map(values=>Buffer.concat(values.map(x=>Buffer.from(be32(x)).reverse())).toString('hex'));
assert.deepEqual(fixedTableHex.map(x=>x.length/2),[928,832,928]);
const executorWitnessParts=[[],[],[]];
for(let event=1;event<=63;event++){
 const parts=executorWitnessParts[event<=21?0:event<=41?1:2];
 parts.push(...slopeRows[event].map(x=>Buffer.from(be32(x)).reverse()));
 if(event%2===1){
  const state=states.find(s=>s.event===event).coefficients.map(BigInt);
  const evaluation=mod(state.reduce((sum,x,i)=>sum+x*basis[i],0n));
  parts.push(be32(fingerprint(state)),be32(evaluation));
 }
}
const executorWitnessHex=executorWitnessParts.map(parts=>Buffer.concat(parts).toString('hex'));
assert.deepEqual(executorWitnessHex.map(x=>x.length/2),[2560,2304,2560]);
let left=0n,right=0n;
const accumulatorHeaderHex=[];
const extensionModulus=mod(z**12n-18n*z**6n+82n);
for(const [i,state] of states.entries()){
 const c=state.coefficients.map(BigInt),q=quotients[i];
 const reducedEvaluation=mod(c.reduce((sum,x,j)=>sum+x*basis[j],0n));
 let qEvaluation=0n;for(let j=q.coefficients.length-1;j>=0;j--)qEvaluation=mod(qEvaluation*z+q.coefficients[j]);
 const computedEvaluation=mod(reducedEvaluation+qEvaluation*extensionModulus);
 const weight=mod(fields[0]**BigInt(q.weightExponent));
 left=mod(left+weight*computedEvaluation);right=mod(right+weight*reducedEvaluation);
 if([0,21,41,63].includes(state.event)){
  const numbers=[left,right,mod(weight*fields[0]),reducedEvaluation,...bPointsAfter[state.event]];
  const bytes=Buffer.concat([stateDigests[state.event],Buffer.alloc(8),...numbers.map(x=>Buffer.from(be32(x)).reverse())]);
  assert.equal(bytes.length,296);accumulatorHeaderHex.push(bytes.toString('hex'));
 }
}
assert.equal(accumulatorHeaderHex.length,4);
const terminalValues=[...slopeRows[64]].reverse().concat([...states.at(-1).coefficients].reverse().map(BigInt),flat(witness.cInv).reverse(),flat(witness.c).reverse());
assert.equal(terminalValues.length,42);
const terminalWitnessHex=terminalValues.map(x=>Buffer.from(bigIntToVmNumber(x)).toString('hex'));
const genesisKnownPushes={
 0:Buffer.concat(fields.map(x=>Buffer.from(be32(x)).reverse())).toString('hex'),
 2:Buffer.from(bigIntToVmNumber(slopeRows[0][1])).toString('hex'),
 3:Buffer.from(bigIntToVmNumber(slopeRows[0][0])).toString('hex'),
 16:Buffer.concat([...flat(witness.c),...flat(witness.cInv)].map(be32)).toString('hex'),
 36:Buffer.from(bigIntToVmNumber(BigInt(publicInputs[1]))).toString('hex'),
 37:Buffer.from(bigIntToVmNumber(BigInt(publicInputs[0]))).toString('hex')
};
[...states[0].coefficients].reverse().forEach((x,i)=>genesisKnownPushes[4+i]=Buffer.from(bigIntToVmNumber(BigInt(x))).toString('hex'));
return {genesisKnownPushes,terminalWitnessHex,accumulatorHeaderHex,executorWitnessHex,fixedTableHex,fields:fields.map(String),c:flat(witness.c).map(String),cInv:flat(witness.cInv).map(String),selector,states,
 quotient:aggregate.map(String),transcriptFinalDigest:digest.toString('hex'),
 scope:'Public fixture and pinned deployment tag only. No supplied challenge, root, state or quotient inputs. Wire layout and complete source program emission remain separate.'};
}
