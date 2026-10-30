// Planning aid for the today's-rules chain: per input, data bytes (without FILL), op-cost in an unbudgeted VM and
// the unlocking size that op-cost needs ((41 + U) * 800 >= op).   PLAN='{...}' node plan.mjs <circuit>
import {loadVectors, parseVK} from './plonk.mjs';
import {makePlan, buildMulti, multiWitness} from './multi.mjs';
import {chainTx} from './chain.mjs';
import {spendTx} from './vm.mjs';
const [c = 'mul2', pi = '0'] = process.argv.slice(2);
const d = loadVectors(c); const vk = parseVK(d.vk.hex);
const plan = makePlan(vk, JSON.parse(process.env.PLAN ?? '{}')); const built = buildMulti(vk, plan);
console.log('C0', built.code.length, 'blobs', built.cb.map((b) => b.length).join(','), 'redeem', built.redeem.length);
const w = multiWitness(vk, plan, built, d.valid[Number(pi)].proof, d.valid[Number(pi)].publicInputs);
const tx = chainTx(vk, plan, built, w.pushes); const free = spendTx('free', 'standard', tx);
let tot = 0;
free.forEach((x, i) => { const need = Math.ceil(x.opCost / 800) - 41; const u = tx[i].unlocking.length; const U = Math.max(u + (need > u ? need - u + 64 : 0), u); tot += U;
  const ro = plan.roles[i]; console.log(`in${i} ${ro.kind} ${ro.hi ?? ro.e0 ?? ''}-${ro.lo ?? ro.e1 ?? ''} data ${u} op ${(x.opCost / 1e6).toFixed(3)}M need ${need} -> ${U}${U > 10000 ? ' OVER' : ''} ${x.error && !/budget|density/.test(x.error) ? x.error : ''} [${w.pushes[i].length} pushes: ${plan.roles[i].fixed.map((f, k) => f[0] + ' ' + w.pushes[i][k].length).join(', ')}]`); });
console.log('estimated total unlocking', tot);
