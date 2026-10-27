const D=new URL('../../chunked/bn254/bn-native-sound/', import.meta.url).href;
const {decodeAuthenticationInstructions}=await import('@bitauth/libauth');
const {FIXTURES}=await import(D+'../sound-si-gls/math.mjs');
const {buildProgram}=await import(D+'script.mjs');
const {transactionFor}=await import(D+'transaction.mjs');
const {programOf,VMS}=await import(D+'vm.mjs');
const prog=buildProgram(); const tx=transactionFor(FIXTURES.fixtures[0],prog);
const fnOf=new Map(); for(const[n,c]of Object.entries(prog.funcCodes)){fnOf.set(decodeAuthenticationInstructions(c).length,n);}
const want=(process.env.FN??'LOOP').split(',');
for(let i=0;i<3;i++){const tr=VMS.standard.debug(programOf(tx.unlockings.map(()=>tx.locking),tx.unlockings,i));
 let prev=0; const by=new Map(); let tot=0, n=0;
 for(let k=0;k<tr.length;k++){const s=tr[k]; const c=s.metrics?.operationCost??0; const d=c-prev; prev=c;
  const prevS=tr[k-1]; if(!prevS) continue; const fn=fnOf.get(prevS.instructions?.length); if(!want.includes(String(fn))) continue;
  const ins=prevS.instructions[prevS.ip]; if(!ins) continue; const op=ins.opcode; by.set(op,(by.get(op)??[0,0])); const e=by.get(op); e[0]+=d; e[1]++; tot+=d; n++;}
 console.log('input',i,want.join(),'total',tot,'instr',n, [...by].sort((a,b)=>b[1][0]-a[1][0]).slice(0,14).map(([o,[c,k]])=>`0x${o.toString(16)}:${c}/${k}`).join(' '));}
