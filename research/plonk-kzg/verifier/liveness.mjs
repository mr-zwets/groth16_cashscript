// Liveness of the today's-rules chain against the honest quotient size n_q (Track 7, GT fold).
//   node liveness.mjs <circuit> [samples=20000]   -> results/liveness-<circuit>.json
// The chain's quotient WQ = WQa || WQb grows with n_q (32 B per word), and so does the work of every input that reads
// or evaluates it (ST: transcript hash and Horner; the WQb host: its own bytes; remote readers of the WQb host). n_q
// varies per proof: the GT fold multiplies 6 degrees per set nibble bit into each event, so n_q follows the nibbles of
// the folded scalars s_i. This tool
//   1. checks the n_q model (si.mjs nqOfNibbles) against proveSI's n_q on every valid vector;
//   2. samples uniform scalars s_i (the s_i of a proof are transcript-derived) for the honest n_q distribution;
//   3. finds the chain's cap: the largest n_q (step 4 words, the WQ size unit) for which the stress witness
//      (chain.mjs nqStress: pseudo-random nonzero high words, so the op-cost is that of a real n_q proof) fits, with
//      BCHN-adjusted FILLs, every input <= 10,000 B unlocking and within budget, and the transaction <= 100,000 B;
//      it tries the structural maximum NQ first (si.mjs nqMax: no honest proof exceeds it);
//   4. reports P(n_q > cap) from the samples (0 observed in S samples gives the 95% bound 3/S); exit 1 if cap < NQ.
import {mkdirSync, writeFileSync} from 'node:fs';
import {loadVectors, parseVK} from './plonk.mjs';
import {r, mod} from './math.mjs';
import {makePlan, buildMulti, multiWitness, planOpts} from './multi.mjs';
import {nqStress} from './chain.mjs';
import {nqOfNibbles} from './si.mjs';
import {nibbles} from './gt.mjs';
import {sha} from './plonk.mjs';

const [c = 'mul2', Ss = '20000'] = process.argv.slice(2); const S = Number(Ss);
const d = loadVectors(c); const vk = parseVK(d.vk.hex);
const plan = makePlan(vk, planOpts(vk, c)); const built = buildMulti(vk, plan);
const out = {circuit: c, foldedBases: plan.m, NQ_MAX: plan.NQ, plan: planOpts(vk, c), model: [], fits: []};
// 1. the model against the vectors
const W0 = [];
for (const [i, pr] of d.valid.entries()) { const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs); W0.push(w);
  const mdl = nqOfNibbles(w.V.gt.N); out.model.push({i, nq: w.S.nq, model: mdl}); if (mdl !== w.S.nq) throw new Error(`n_q model ${mdl} != proveSI ${w.S.nq} (proof ${i})`); }
console.log('n_q model = proveSI on', d.valid.length, 'valid proofs:', out.model.map((x) => x.nq).join(', '));
// 2. honest distribution (deterministic pseudo-random scalars)
const hist = new Map(); let seed = 0;
const rnd = () => mod(BigInt('0x' + sha(Buffer.from(`live-${c}-${seed++}`)).toString('hex') + sha(Buffer.from(`live2-${c}-${seed}`)).toString('hex')), r);
for (let k = 0; k < S; k++) { const nq = nqOfNibbles(nibbles(Array.from({length: plan.m}, rnd)).N); hist.set(nq, (hist.get(nq) ?? 0) + 1); }
const qs = [...hist.keys()].sort((a, b) => a - b); const cdf = (x) => qs.filter((q) => q <= x).reduce((s, q) => s + hist.get(q), 0) / S;
const pct = (f) => qs.find((q) => cdf(q) >= f);
out.honest = {samples: S, min: qs[0], p50: pct(0.5), p99: pct(0.99), p999: pct(0.999), max: qs.at(-1), hist: Object.fromEntries(qs.map((q) => [q, hist.get(q)]))};
console.log(`honest n_q over ${S} samples: min ${qs[0]} p50 ${pct(0.5)} p99 ${pct(0.99)} p99.9 ${pct(0.999)} max ${qs.at(-1)} (structural max ${plan.NQ})`);
// 3. the cap
const pr0 = d.valid[0];
const fits = (nq) => { const x = nqStress(vk, plan, built, pr0.proof, pr0.publicInputs, nq); const {perInput, ...rest} = x; out.fits.push(rest);
  console.log(`n_q ${nq}: ${x.ok ? 'fits' : 'DOES NOT FIT'}, tx ${x.txBytes} B, largest input in${x.maxInput.i} ${x.maxInput.role} ${x.maxInput.unlocking} B${x.bad.length ? ', over: ' + x.bad.join('; ') : ''}`);
  return x.ok; };
const up4 = (x) => 4 * Math.ceil(x / 4);
let lo = up4(Math.max(...out.model.map((x) => x.nq))), hi = plan.NQ;
if (!fits(lo)) { out.cap = null; console.log('the honest maximum of the vectors does not fit'); }
else if (fits(hi)) out.cap = hi;
else { while (hi - lo > 4) { const mid = up4((lo + hi) / 2 - 2); if (mid <= lo || mid >= hi) break; if (fits(mid)) lo = mid; else hi = mid; } out.cap = lo; }
// 4. probability
const over = out.cap == null ? S : qs.filter((q) => q > out.cap).reduce((s, q) => s + hist.get(q), 0);
out.summary = {nqCap: out.cap, nqStructuralMax: plan.NQ, honestMin: qs[0], honestP50: pct(0.5), honestMax: qs.at(-1), samples: S, samplesOverCap: over,
  pOverCap: over ? over / S : `< ${(3 / S).toExponential(1)} (0 of ${S}, 95%)`};
console.log('cap', out.cap, 'samples over cap', over, '/', S);
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
writeFileSync(new URL(`./results/liveness-${c}.json`, import.meta.url), JSON.stringify(out, null, 1) + '\n');
if (out.cap !== plan.NQ) { console.log(`FAIL: the chain does not carry every n_q up to the structural ${plan.NQ}`); process.exit(1); }
console.log(`OK: every n_q up to the structural maximum ${plan.NQ} fits`);
