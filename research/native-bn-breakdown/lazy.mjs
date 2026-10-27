const D=new URL('../../chunked/bn254/bn-native-sound/', import.meta.url).href;
const {FIXTURES}=await import(D+'../sound-si-gls/math.mjs');
const {buildProgram}=await import(D+'script.mjs');
const {transactionFor}=await import(D+'transaction.mjs');
const {spendAll}=await import(D+'vm.mjs');
const prog=buildProgram(); console.log('code',prog.code.length);
const tx=transactionFor(FIXTURES.fixtures[0],prog,{fills:[0,0,0]});
for(const m of ['standard','consensus']){const r=spendAll(tx.unlockings.map(()=>tx.locking),tx.unlockings,m); console.log(m,r.map(x=>`${x.accepted?'ok':x.error} op ${x.opCost} len ${x.length}`).join(' | '), 'sum', r.reduce((a,x)=>a+x.opCost,0));}
