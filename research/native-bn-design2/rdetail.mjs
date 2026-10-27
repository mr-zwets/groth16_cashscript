const D=new URL("../../chunked/bn254/bn-native-sound/", import.meta.url).href; // per-instruction op of R and the body prologue
const {decodeAuthenticationInstructions}=await import('@bitauth/libauth');
const {FIXTURES}=await import(D+'../sound-si-gls/math.mjs');
const {buildProgram}=await import(D+'script.mjs');
const {transactionFor}=await import(D+'transaction.mjs');
const {programOf,VMS}=await import(D+'vm.mjs');
const prog=buildProgram(); const tx=transactionFor(FIXTURES.fixtures[0],prog);
const nR=decodeAuthenticationInstructions(prog.R).length;
const nBody=decodeAuthenticationInstructions(prog.code).length;
for(let i=0;i<3;i++){const tr=VMS.standard.debug(programOf(tx.unlockings.map(()=>tx.locking),tx.unlockings,i));
 let prev=0; const rows=[]; let unl=0;
 for(let k=1;k<tr.length;k++){const s=tr[k]; const c=s.metrics?.operationCost??0; const d=c-prev; prev=c; const ps=tr[k-1];
  const L=ps.instructions?.length; const ins=ps.instructions?.[ps.ip]; if(!ins) continue;
  if(L===nR) rows.push(`R:0x${ins.opcode.toString(16)}:${d}`); else if(L===nBody) rows.push(`B:0x${ins.opcode.toString(16)}:${d}`); else if(rows.length===0) unl+=d; }
 console.log('input',i,'unlocking-phase',unl); console.log(rows.join(' '));}
