// Per-chunk op cost of the worker event loop, measured end-to-end in the VM (proto_worker.segment) over several
// proofs (random and edge statements) and random challenges; writes chunk-costs.json {perChunk: [{min,max,mean}], ...}.
//   node chunks.mjs [nRandom=6] [out=chunk-costs-9.json]   (then: node sweep.mjs merge chunk-costs-9.json sweep/chunks-*.json)
import {writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {r, mod} from './blsmath.mjs';
import {prove, randProof, mintProof, uniformBounds} from './protocol.mjs';
import {segment} from './proto_worker.mjs';
const NR = Number(process.argv[2] ?? 6); const bounds = uniformBounds(2);
const proofs = [...Array.from({length: NR}, (_, i) => ['rand' + i, randProof(1000 + i)]),
  ['n=0,0 b=1', mintProof([0n, 0n], 1n, 1n)], ['n=r-1', mintProof([r - 1n, r - 1n], 2n, 3n)], ['n=|x|^3-1', mintProof([0xd201000000010000n ** 3n - 1n, 1n], 5n, 7n)]];
const H = (s) => mod(BigInt('0x' + createHash('sha256').update(s).digest('hex')));
const per = bounds.map(() => []);
for (const [name, pf] of proofs) {
  const pr = prove(pf, {bounds}); const z = H(name + 'z'), rho = H(name + 'rho');
  bounds.forEach((b, k) => { const s = segment(pr, k ? bounds[k - 1] : 0, b, {bounds, z, rho}); per[k].push(s.op); });
  console.error(name, 'total', per.reduce((a, x) => a + x.at(-1), 0));
}
const stat = per.map((xs) => ({min: Math.min(...xs), max: Math.max(...xs), mean: Math.round(xs.reduce((a, b) => a + b, 0) / xs.length)}));
const totMax = stat.reduce((a, s) => a + s.max, 0);
writeFileSync(process.argv[3] ?? 'chunk-costs-9.json', JSON.stringify({bounds, proofs: proofs.map((x) => x[0]), perChunk: stat, totalOfMax: totMax}, null, 1));
console.log('sum of per-chunk max', totMax); stat.forEach((s, k) => console.log(k, bounds[k], s.min, s.max));
