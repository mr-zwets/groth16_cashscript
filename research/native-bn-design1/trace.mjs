// Per-instruction op-cost trace of the glue sections of bn-native-sound (fixture 0, standard), to calibrate design-1 estimates.
//   SEC=r0:remote,r1:remote node trace.mjs
const D=new URL('../../chunked/bn254/bn-native-sound/', import.meta.url).href;
const {decodeAuthenticationInstructions, encodeAuthenticationInstruction, disassembleBytecodeBCH}=await import('@bitauth/libauth');
const {FIXTURES}=await import(D+'../sound-si-gls/math.mjs');
const {buildProgram}=await import(D+'script.mjs');
const {transactionFor}=await import(D+'transaction.mjs');
const {programOf,VMS}=await import(D+'vm.mjs');
const prog=buildProgram(); const tx=transactionFor(FIXTURES.fixtures[0],prog);
const roleIns=[0,1,2].map((i)=>{const d=decodeAuthenticationInstructions(prog.funcCodes['role'+i]);const o=[];let x=0;for(const t of d){o.push(x);x+=encodeAuthenticationInstruction(t).length;}return {n:d.length,offs:o};});
const marks=prog.marks.slice().sort((a,b)=>a.roff-b.roff);
const want=(process.env.SEC??'').split(',').filter(Boolean);
const fnOf=new Map(); for(const[n,c]of Object.entries(prog.funcCodes)){fnOf.set(decodeAuthenticationInstructions(c).length,n);}
for(let i=0;i<3;i++){const tr=VMS.standard.debug(programOf(tx.unlockings.map(()=>tx.locking),tx.unlockings,i));
 let prev=0,cur='unlocking/R'; const sec=new Map();
 for(let k=0;k<tr.length;k++){const s=tr[k]; const c=s.metrics?.operationCost??0; const d=c-prev; prev=c;
  const ri=roleIns.findIndex((x)=>x.n===s.instructions?.length);
  if(ri>=0){let n='r'+ri+':start'; for(const m of marks) if(m.role===ri&&m.roff<=roleIns[ri].offs[Math.max(0,s.ip-1)]) n=m.name; cur=n;}
  sec.set(cur,(sec.get(cur)??0)+d);
  if(want.includes(cur)||(want.includes('R')&&cur==='unlocking/R')){const p=tr[k-1]; const ins=p?.instructions?.[p.ip]; const fn=fnOf.get(p?.instructions?.length)??'';
   if(d) console.log(i,cur,fn,d, ins? disassembleBytecodeBCH(encodeAuthenticationInstruction(ins)).slice(0,40):'', 'top', s.stack?.at(-1)?.length);}
 }
 console.log('input',i,[...sec].map(([k,v])=>k+'='+v).join(' '));
}
