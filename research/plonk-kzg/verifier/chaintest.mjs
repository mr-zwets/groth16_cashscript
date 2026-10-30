// Tests of the today-regime chain (libauth BCH 2026 VM, consensus and standard).
//   node chaintest.mjs <circuit> [--quick]   -> results/chain-<circuit>.json
import {mkdirSync, writeFileSync} from 'node:fs';
import {loadVectors, parseVK, Reject, le32, verifyPlonk} from './plonk.mjs';
import {p, aff, G1} from './math.mjs';
import {makePlan, buildMulti, multiWitness, planOpts} from './multi.mjs';
import {chainTx, sizeFills, txBytes} from './chain.mjs';
import {spendTx, verifyTx, p2sh32, encodeUnlocking} from './vm.mjs';

const [circuit = 'mul2'] = process.argv.slice(2); const quick = process.argv.includes('--quick');
const d = loadVectors(circuit); const vk = parseVK(d.vk.hex);
const plan = makePlan(vk, planOpts(vk, circuit)); const built = buildMulti(vk, plan);
const out = {circuit, plan: plan.roles.map((r) => ({kind: r.kind, hi: r.hi, lo: r.lo, e0: r.e0, e1: r.e1, host: r.host})), codeBytes: [built.code.length, built.c1.length], redeemBytes: built.redeem.length, valid: [], tampered: [], manipulations: []};
let bad = 0; const fail = (m) => { bad++; console.log('UNEXPECTED', m); };
const both = (tx) => ['consensus', 'standard'].map((m) => verifyTx('bch2026', m, tx));
// ---- valid ----
let base;
for (const [i, pr] of (quick ? d.valid.slice(0, 1) : d.valid).entries()) {
  const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs); const fills = sizeFills(vk, plan, built, w.pushes); const tx = chainTx(vk, plan, built, w.pushes, fills);
  const per = spendTx('bch2026', 'standard', tx); const v = both(tx); const ok = v.every((x) => x.accepted);
  if (!ok || !w.accept) fail(`valid ${i}: ${v.map((x) => x.error).join(' / ')}`);
  if (i === 0) base = {w, fills, tx};
  out.valid.push({i, accepted: ok, txBytes: txBytes(tx), unlocking: tx.reduce((s, x) => s + x.unlocking.length, 0), inputs: tx.length,
    perInput: per.map((x, k) => ({role: plan.roles[k].kind, unlocking: x.unlockingLen, fill: fills[k], opCost: x.opCost, budget: x.budget}))});
  console.log(`valid ${i}: ${ok ? 'accepted' : 'REJECTED'}, tx ${txBytes(tx)} B, op ${per.reduce((s, x) => s + x.opCost, 0)}`);
}
const run = (name, pushes, fills, mutate) => { let tx = chainTx(vk, plan, built, pushes, fills ?? base.fills); if (mutate) tx = mutate(tx); const v = both(tx); const rej = v.every((x) => !x.accepted);
  if (!rej) fail(name); return {name, rejected: rej, error: v[1].error?.slice(0, 160)}; };
// ---- tampered vectors ----
for (const t of quick ? d.tampered.slice(0, 6) : d.tampered) {
  let ps, how, fl;
  try { const w = multiWitness(vk, plan, built, t.proof, t.publicInputs); if (w.accept) fail('reference accepts ' + t.name); ps = w.pushes; how = 'adaptive'; fl = sizeFills(vk, plan, built, ps, {strict: false}); }
  catch (e) { if (!(e instanceof Reject) && !/exceptional|singular|chain MSM|deepEqual|Expected/.test(e.message)) throw e;
    ps = base.w.pushes.map((x) => x.slice()); const st = ps[plan.iST]; const f = plan.roles[plan.iST].fixed.map((x) => x[0]);
    st[f.indexOf('PROOF')] = Buffer.from(t.proof, 'hex'); st[f.indexOf('PI')] = Buffer.concat(t.publicInputs.map((h) => Buffer.from(h, 'hex'))); how = 'reused'; }
  out.tampered.push({...run(t.name, ps, how === 'adaptive' ? fl : base.fills), how});
}
console.log(`tampered: ${out.tampered.filter((x) => x.rejected).length}/${out.tampered.length} rejected`);
// ---- manipulations of valid proof 0 ----
const P = () => base.w.pushes.map((ps) => ps.map((b) => Buffer.from(b)));
const fi = (ix, name) => plan.roles[ix].fixed.findIndex((x) => x[0] === name);
const iMA = plan.roles.findIndex((r) => r.kind === 'MA' && !r.conv), iSI2 = plan.roles.findIndex((r) => r.kind === 'SI' && !r.first);
const M = [];
const m = (name, f, mutate) => { const ps = P(); f(ps); M.push([name, ps, mutate]); };
m('MA hand-over word + 1', (ps) => { ps[iMA][fi(iMA, 'HAND')][0] ^= 1; });
m('MA hand-over word + p (alias)', (ps) => { const b = ps[iMA][fi(iMA, 'HAND')]; const v = BigInt('0x' + Buffer.from(b.subarray(0, 32)).reverse().toString('hex')); if (v + p < 1n << 256n) le32(v + p).copy(b, 0); });
m('SI hand-over R word flipped', (ps) => { const b = ps[iSI2][fi(iSI2, 'HAND')]; b[b.length - 5] ^= 4; });
m('slope bit flip (MA)', (ps) => { ps[iMA][plan.roles[iMA].fixed.length + 2][7] ^= 1; });
m('TV entry bit flip', (ps) => { ps[plan.iTV][fi(plan.iTV, 'TV')][500] ^= 1; });
if (plan.iTV2 >= 0) m('TV2 entry bit flip', (ps) => { ps[plan.iTV2][fi(plan.iTV2, 'TV2')][500] ^= 1; });
if (plan.iTF >= 0) m('TF entry bit flip', (ps) => { ps[plan.iTF][fi(plan.iTF, 'TF')][500] ^= 1; });
m('DS (chain slopes) bit flip', (ps) => { ps[iSI2][fi(iSI2, 'DS')][100] ^= 1; });
m('WS state bit flip', (ps) => { ps[plan.iST][fi(plan.iST, 'WS')][3000] ^= 1; });
m('WQ word bit flip', (ps) => { ps[plan.iWQ][fi(plan.iWQ, 'WQ')][1900] ^= 1; });
m('G0 scalar bit flip', (ps) => { ps[plan.iST][fi(plan.iST, 'G0')][100] ^= 1; });
m('code blob C0 byte flip', (ps) => { ps[0][0][2000] ^= 1; });
plan.blobs.forEach(([ix], b) => m(`code blob C${b + 1} byte flip`, (ps) => { ps[ix][fi(ix, 'C' + (b + 1))][100] ^= 1; }));
if (plan.m) { // Track 7: the GT fold and the moved SI transcript
  const g0 = 32 + 32 * plan.nbm + 64; // offset of rho in G0
  m('G0 rho word flipped', (ps) => { ps[plan.iST][fi(plan.iST, 'G0')][g0 + 3] ^= 1; });
  m('G0 z word flipped', (ps) => { ps[plan.iST][fi(plan.iST, 'G0')][g0 + 35] ^= 1; });
  m('G0 QZ (Horner value) flipped', (ps) => { ps[plan.iST][fi(plan.iST, 'G0')][g0 + 67] ^= 1; });
  if (!plan.bindST) m('G0 folded scalar s_0 flipped', (ps) => { ps[plan.iST][fi(plan.iST, 'G0')][g0 + 99] ^= 1; });
  m('WS nibble byte + 1', (ps) => { ps[plan.iST][fi(plan.iST, 'WS')][192 + 7] ^= 1; });
  m('WS nibble byte = 0x10 (out of range)', (ps) => { ps[plan.iST][fi(plan.iST, 'WS')][192 + 3] = 0x10; });
  m('WS nibble byte = 0x81 (negative)', (ps) => { ps[plan.iST][fi(plan.iST, 'WS')][192 + 5] = 0x81; });
  m('GZ word flipped', (ps) => { ps[plan.iGZ][fi(plan.iGZ, 'GZ')][300] ^= 1; });
  m('WQa word flipped', (ps) => { ps[plan.iWQa][fi(plan.iWQa, 'WQa')][4000] ^= 1; });
  m('WQb extra zero word (wrong size)', (ps) => { const k = fi(plan.iWQ, 'WQ'); ps[plan.iWQ][k] = Buffer.concat([Buffer.alloc(32), ps[plan.iWQ][k]]); });
}
m('X: Fr inverse * 2', (ps) => { const b = ps[plan.iST][fi(plan.iST, 'X')]; b[64] ^= 2; });
m('two MA inputs swapped', () => {}, (tx) => { const t = tx.slice(); const j = iMA, k2 = iMA + 1; [t[j], t[k2]] = [t[k2], t[j]]; return t; });
m('nonzero FILL byte', () => {}, (tx) => tx.map((x, k) => { if (k !== iMA) return x; const pushes = []; return {...x, unlocking: (() => { const u = Buffer.from(x.unlocking); const pos = u.length - built.redeem.length - 2 - 10; u[pos] ^= 1; return u; })()}; }));
m('extra input with the same locking', () => {}, (tx) => [...tx, tx[1]]);
m('extra foreign input', () => {}, (tx) => [...tx, {locking: Uint8Array.of(0x51), unlocking: Uint8Array.of()}]);
m('input dropped (last SI)', () => {}, (tx) => tx.slice(0, -1));
for (const [nm, f] of [['adaptive: Lambda\' = 2 Lambda', (L) => L.double()], ['adaptive: Lambda\' = Lambda + G', (L) => L.add(G1.BASE)]]) {
  const pr = d.valid[0]; const V = verifyPlonk(vk, pr.proof, pr.publicInputs); const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs, {lam: aff(f(V.lamTrue))});
  if (w.accept) fail('reference accepts ' + nm); M.push([nm, w.pushes, null, sizeFills(vk, plan, built, w.pushes, {strict: false})]); }
if (plan.m) for (const i of [...new Set([0, ...plan.FX.flatMap((nm, x) => (nm.startsWith('Qcp') ? [x] : [])), plan.m - 1])]) { /* BSB22: also each folded Qcp_j */ const pr = d.valid[0]; const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs, {fsDelta: [i, 1n]});
  if (w.accept) fail('reference accepts nibbles for s + 1'); M.push([`adaptive: nibbles of folded base ${i} encode s + 1 (SI re-witnessed)`, w.pushes, null, sizeFills(vk, plan, built, w.pushes, {strict: false})]); }
{ const w = multiWitness(vk, plan, built, d.valid[1].proof, d.valid[0].publicInputs); M.push(['adaptive: proof 1 with the public inputs of proof 0', w.pushes, null, sizeFills(vk, plan, built, w.pushes, {strict: false})]); }
for (const [name, ps, mutate, fills] of M) out.manipulations.push(run(name, ps, fills, mutate));
console.log(`manipulations: ${out.manipulations.filter((x) => x.rejected).length}/${out.manipulations.length} rejected`);
out.unexpected = bad;
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
if (!quick) writeFileSync(new URL(`./results/chain-${circuit}.json`, import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(bad ? `FAIL: ${bad} unexpected` : 'OK: 0 unexpected'); process.exit(bad ? 1 : 0);
