// PICK/ROLL pair census over the FINAL (rescheduled) grouped-residue chunk redeems.
// Reads the built vectors, extracts each step's redeem (last unlocking push), splits it
// into OP_DEFINE bodies + main, and counts <depth> OP_PICK/OP_ROLL access pairs — static
// (per script) and dynamically weighted (bodies multiplied by their transitive INVOKE
// counts). The depth histogram separates residual shallow shuffles (schedulable) from
// deep multi-use fetches (irreducible without a layout/frame redesign).
//   node chunked/rescheduler/census.mjs [path-to-vectors.json]
import { readFileSync } from 'node:fs';
import { parse } from '../../singleton/bn254/recompiler/asm.mjs';

const VECTORS = process.argv[2] ?? 'C:/Users/mathi/Desktop/verifier/src/bch/groth16-grouped-residue-vectors.json';
const vec = JSON.parse(readFileSync(VECTORS, 'utf8'));

const hexToBin = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const lastPush = (unlockingHex) => {
  const ops = parse(hexToBin(unlockingHex));
  return ops[ops.length - 1].data;
};
const numOf = (o) => {
  if (o.data !== undefined) { let n = 0; for (let i = o.data.length - 1; i >= 0; i--) n = (n << 8) | o.data[i]; return n; }
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.op === 0x4f) return -1;
  return undefined;
};
const isConst = (o) => o.data !== undefined || o.op === 0 || o.op === 0x4f || (o.op >= 0x51 && o.op <= 0x60);

// census one script: pairs = const push immediately followed by PICK(0x79)/ROLL(0x7a)
function censusOps(ops) {
  const res = { elements: ops.length, pairs: 0, depthSum: 0, depths: [], invokes: new Map() };
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if ((o.op === 0x79 || o.op === 0x7a) && i > 0 && isConst(ops[i - 1])) {
      const d = numOf(ops[i - 1]);
      if (d !== undefined) { res.pairs += 1; res.depthSum += d; res.depths.push(d); }
    }
    if (o.op === 0x8a && i > 0) { // INVOKE
      const id = numOf(ops[i - 1]);
      if (id !== undefined) res.invokes.set(id, (res.invokes.get(id) ?? 0) + 1);
    }
  }
  return res;
}

function dissect(bytes) {
  const ops = parse(bytes);
  const bodies = new Map(); const order = [];
  let i = 0;
  while (i + 2 < ops.length && ops[i].data && ops[i + 2] && ops[i + 2].op === 0x89) {
    bodies.set(numOf(ops[i + 1]), ops[i].data); order.push(numOf(ops[i + 1])); i += 3;
  }
  return { bodies, order, mainOps: ops.slice(i) };
}

// transitive invocation multipliers: main executes once; a body's multiplier is the sum
// over its callers of (caller multiplier x call sites)
function multipliers(d, mainCensus, bodyCensus) {
  const mult = new Map(d.order.map((id) => [id, 0]));
  for (const [id, n] of mainCensus.invokes) mult.set(id, (mult.get(id) ?? 0) + n);
  // iterate to fixpoint (call graph is a DAG; a few passes suffice)
  for (let pass = 0; pass < 10; pass++) {
    let changed = false;
    for (const id of d.order) {
      const m = mult.get(id) ?? 0;
      if (m === 0) continue;
      for (const [callee, n] of bodyCensus.get(id).invokes) {
        const cur = mult.get(callee) ?? 0;
        const next = [...mainCensus.invokes].reduce(() => 0, 0); // placeholder, recomputed below
      }
    }
    // recompute from scratch each pass: mult = main + sum over bodies (mult[body] * calls)
    const fresh = new Map(d.order.map((id) => [id, mainCensus.invokes.get(id) ?? 0]));
    for (const id of d.order) {
      const m = mult.get(id) ?? 0;
      if (m === 0) continue;
      for (const [callee, n] of bodyCensus.get(id).invokes) {
        fresh.set(callee, (fresh.get(callee) ?? 0) + m * n);
      }
    }
    for (const id of d.order) { if (fresh.get(id) !== mult.get(id)) changed = true; mult.set(id, fresh.get(id)); }
    if (!changed) break;
  }
  return mult;
}

const steps = vec.valid.steps;
let totElements = 0; let totStaticPairs = 0; let totDynPairs = 0; let totDynCost = 0;
let mainPairs = 0; let bodyStaticPairs = 0;
const allDepthsMain = []; const allDepthsBodyDyn = [];
const perChunk = [];

for (const step of steps) {
  const redeem = lastPush(step.unlocking);
  const d = dissect(redeem.slice(1)); // skip the prepended OP_DROP
  const mainC = censusOps(d.mainOps);
  const bodyC = new Map(d.order.map((id) => [id, censusOps(parse(d.bodies.get(id)))]));
  const mult = multipliers(d, mainC, bodyC);

  let stat = mainC.pairs; let dyn = mainC.pairs; let dynCost = 0; let elems = mainC.elements;
  mainC.depths.forEach((dep) => { allDepthsMain.push(dep); dynCost += 200 + 33 + dep; });
  for (const id of d.order) {
    const c = bodyC.get(id); const m = mult.get(id) ?? 0;
    stat += c.pairs; dyn += c.pairs * m; elems += c.elements;
    c.depths.forEach((dep) => { for (let k = 0; k < m; k++) allDepthsBodyDyn.push(dep); dynCost += m * (200 + 33 + dep); });
  }
  totElements += elems; totStaticPairs += stat; totDynPairs += dyn; totDynCost += dynCost;
  mainPairs += mainC.pairs; bodyStaticPairs += stat - mainC.pairs;
  perChunk.push({ label: step.label.slice(0, 36), stat, dyn, dynCostK: Math.round(dynCost / 1000), mainPairs: mainC.pairs });
}

const stats = (arr) => {
  if (arr.length === 0) return { n: 0 };
  const sorted = [...arr].sort((a, b) => a - b);
  const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
  const pct = (p) => sorted[Math.floor(p * (sorted.length - 1))];
  return { n: arr.length, avg: avg.toFixed(1), p50: pct(0.5), p90: pct(0.9), max: sorted[sorted.length - 1], le2: arr.filter((d) => d <= 2).length, gt16: arr.filter((d) => d > 16).length };
};

console.log(`chunks: ${steps.length}  total script elements: ${totElements.toLocaleString()}`);
console.log(`static pairs: ${totStaticPairs.toLocaleString()} (${(totStaticPairs * 2 / totElements * 100).toFixed(1)}% of elements as pair-elements)`);
console.log(`  in mains: ${mainPairs.toLocaleString()}   in bodies (static): ${bodyStaticPairs.toLocaleString()}`);
console.log(`dynamic pair executions: ${totDynPairs.toLocaleString()}  est. op-cost ~${(totDynCost / 1e6).toFixed(1)}M`);
console.log('main-pair depths   :', JSON.stringify(stats(allDepthsMain)));
console.log('body-pair depths(dyn):', JSON.stringify(stats(allDepthsBodyDyn)));
console.log('\nper chunk (top 8 by dyn cost):');
perChunk.sort((a, b) => b.dynCostK - a.dynCostK).slice(0, 8).forEach((c) => console.log(`  ${String(c.dynCostK).padStart(6)}K op  stat=${String(c.stat).padStart(4)} dyn=${String(c.dyn).padStart(5)} main=${String(c.mainPairs).padStart(4)}  ${c.label}`));
