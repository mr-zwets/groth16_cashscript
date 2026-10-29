import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';
const opts = JSON.parse(process.argv[3] ?? '{}');
const {prm, proof} = loadVector(process.argv[2]);
const sp = spendB(prm, proof.subarray(0, 16), proof, {...opts, markers: true});
const r = evaluate('looseStd', sp.locking, sp.unlocking);
const sp2 = spendB(prm, proof.subarray(0, 16), proof, opts);
const r2 = evaluate('looseStd', sp2.locking, sp2.unlocking);
const S = r.snaps, labels = sp.built.codeSizes.map(x=>x[0]); const nm = labels.filter(l=>!l.startsWith('q-')&&l!=='end').length;
const q = {}; for (let k=0;k<prm.s;k++) for (let j=0;j<5;j++){const a=S[nm+k*5+j-1],b=S[nm+k*5+j]; q[labels[nm+j]]=(q[labels[nm+j]]??0)+b.op-a.op-100;}
const mainPh = {}; for (let i=1;i<nm;i++) mainPh[labels[i]] = S[i].op - S[i-1].op - 100;
console.log(prm.name, JSON.stringify(opts), 'acc', r2.accepted, 'op', r2.opCost, 'redeem', sp2.redeem.length, 'unl', sp2.unlocking.length, Object.entries(q).map(([k,v])=>k+':'+Math.round(v/prm.s)).join(' '), 'unpack', mainPh.unpack, 'merkle', mainPh.merkle);
