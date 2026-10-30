// node chainprof.mjs <circuit> : per-input inclusive op-cost of each function (top 12)
import {loadVectors, parseVK} from './plonk.mjs';
import {makePlan, buildMulti, multiWitness, planOpts} from './multi.mjs';
import {chainTx, sizeFills} from './chain.mjs';
import {fprof} from './fprof.mjs';
const [c = 'mul2'] = process.argv.slice(2);
const d = loadVectors(c); const vk = parseVK(d.vk.hex);
const plan = makePlan(vk, planOpts(vk, c)); const built = buildMulti(vk, plan);
const names = {...built.ids}; plan.blobs.forEach((_, b) => { names[b] = 'C' + (b + 1); }); names[plan.blobs.length] = 'C0'; plan.roles.forEach((r, i) => { names[built.roleBase + i] = 'role' + i + r.kind; });
const w = multiWitness(vk, plan, built, d.valid[0].proof, d.valid[0].publicInputs);
const tx = chainTx(vk, plan, built, w.pushes, process.env.NOFILL ? null : sizeFills(vk, plan, built, w.pushes));
for (let i = 0; i < tx.length; i++) { const r = fprof(tx, i, names); const top = Object.entries(r.incl).sort((a, b) => b[1] - a[1]).slice(0, 14);
  console.log(`in${i} ${plan.roles[i].kind} total ${(r.total / 1e6).toFixed(3)}M ${r.error ?? ''} ${r.errAt ? JSON.stringify(r.errAt) : ''}`); if (process.env.OPF) console.log('   ops', Object.entries(r.byOp).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([o, v]) => `${Number(o).toString(16)}:${(v / 1e3).toFixed(0)}k`).join(' '));
  console.log('   ' + top.map(([n, v]) => `${n} ${(v / 1e6).toFixed(3)}`).join(' | ')); }
