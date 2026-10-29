// quick check: build layout (b) for one vector and run the valid proof on the loose VM (with phase markers)
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';

const {v, vk, proof, pis} = loadVector(process.argv[2]);
const markers = process.argv.includes('--markers');
const sp = spendB(vk, pis, proof, pis, {markers});
const r = evaluate('looseStd', sp.locking, sp.unlocking);
console.log(v.air, v.set.name, 'redeem', sp.redeem.length, 'unlocking', sp.unlocking.length, 'accepted', r.accepted, r.error ?? '', 'op', r.opCost, 'markers', r.markers);
if (markers) {
  const labels = sp.built.marks.map(([l]) => l);
  let prev = 0;
  r.snaps.forEach((s, i) => { console.log(String(i).padStart(3), (labels[i] ?? '?').padEnd(16), s.op - prev); prev = s.op; });
}
if (!r.accepted) console.log(r.stackTop);
