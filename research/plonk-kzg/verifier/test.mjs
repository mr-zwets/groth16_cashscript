// Acceptance and rejection tests of the single-input verifier on the real libauth VMs (consensus and standard).
//   node test.mjs <circuit> <regime: spec|txv5> <J> [JR=0] [--quick]   -> results/test-<circuit>-<regime>.json
// 1. every valid vector is accepted (both modes), and the JS reference (plonk.mjs verifyPlonk + si.mjs) agrees;
// 2. every tampered vector of the prover track is rejected. Where the tampered statement still decodes, the witness is
//    rebuilt for it adaptively (consistent slopes, Lambda', inverse, SI states and floor quotients), so the script
//    runs to its last check; otherwise the valid witness is reused with the tampered bytes;
// 3. witness manipulations of a valid proof (count-preserving ones included) are rejected.
import assert from 'node:assert/strict';
import {mkdirSync, writeFileSync} from 'node:fs';
import {loadVectors, parseVK, Reject, le32, be32, verifyPlonk, proofLen} from './plonk.mjs';
import {p, r, aff, mod, G1} from './math.mjs';
import {buildRedeem} from './script.mjs';
import {witnessFor, pushesOf} from './witness.mjs';
import {p2sh32, encodeUnlocking, spend} from './vm.mjs';
import {padFor} from './single.mjs';

const [circuit = 'mul2', regime = 'spec', Js = '13', JRs = '0'] = process.argv.slice(2);
const quick = process.argv.includes('--quick');
const J = Number(Js), JR = Number(JRs), pad = regime === 'txv5';
const d = loadVectors(circuit); const vk = parseVK(d.vk.hex);
const {redeem} = buildRedeem(vk, {J, JR, pad});
const locking = p2sh32(redeem);
const run = (pushes, padLen) => { const u = encodeUnlocking([...pushes, ...(pad ? [Buffer.alloc(padLen ?? 1)] : []), redeem]);
  return Object.fromEntries(['consensus', 'standard'].map((m) => { const x = spend(regime, m, locking, u); return [m, {accepted: x.accepted, error: x.error, opCost: x.opCost, budget: x.budget, unlocking: u.length}]; })); };
// pad sized for the honest op-cost of the valid witness (the TXv5 grade pads every input to its need)
const padNeed = (pushes) => { if (!pad) return 0; const u = encodeUnlocking([...pushes, Buffer.alloc(1), redeem]); const x = spend('free', 'standard', locking, u); return padFor(x.opCost, u.length, regime).length; };
const out = {circuit, regime, J, JR, redeemBytes: redeem.length, valid: [], tampered: [], manipulations: []};
let bad = 0;
const fail = (what) => { bad++; console.log('UNEXPECTED', what); };

// ---- 1. valid ----
const wts = [];
for (const [i, pr] of d.valid.entries()) {
  const wt = witnessFor(vk, pr.proof, pr.publicInputs, {J, JR}); wts.push(wt);
  const pushes = pushesOf(wt); const pl = padNeed(pushes); const res = run(pushes, pl);
  const ok = res.consensus.accepted && res.standard.accepted; if (!ok || !wt.accept) fail(`valid ${i}: ${res.consensus.error} / ${res.standard.error}`);
  out.valid.push({i, ref: wt.accept, ...res, pad: pl, slopes: wt.w.slopes.length, nq: wt.S.nq, proofBytes: proofLen(vk), piBytes: 32 * vk.nbPublic});
  console.log(`valid ${i}: ${ok ? 'accepted' : 'REJECTED'} op ${res.standard.opCost} / ${res.standard.budget}, unlocking ${res.standard.unlocking}`);
}
const base = wts[0]; const basePushes = pushesOf(base); const basePad = padNeed(basePushes);

// ---- 2. tampered vectors ----
for (const t of quick ? d.tampered.slice(0, 12) : d.tampered) {
  let pushes, how;
  try { const wt = witnessFor(vk, t.proof, t.publicInputs, {J, JR}); if (wt.accept) fail('reference accepts tampered ' + t.name); pushes = pushesOf(wt); how = 'adaptive'; }
  catch (e) { if (!(e instanceof Reject) && !/exceptional|singular/.test(e.message)) throw e;
    pushes = basePushes.slice(); pushes[pushes.length - 1] = Buffer.from(t.proof, 'hex'); pushes[pushes.length - 2] = Buffer.concat(t.publicInputs.map((h) => Buffer.from(h, 'hex'))); how = 'reused:' + e.message; }
  const res = run(pushes, basePad); const rej = !res.consensus.accepted && !res.standard.accepted;
  if (!rej) fail('tampered accepted ' + t.name);
  out.tampered.push({name: t.name, how, rejected: rej, error: res.standard.error});
}
console.log(`tampered: ${out.tampered.filter((x) => x.rejected).length}/${out.tampered.length} rejected`);

// ---- 3. witness manipulations of valid proof 0 ----
const nP = base.pieces.length; const idx = {WQ: nP, WS: nP + 1, X: nP + 2, PI: nP + 3, PROOF: nP + 4};
const M = [];
const edit = (name, f) => M.push({name, pushes: f(basePushes.map((b) => Buffer.from(b)))});
const flip = (b, i, bit = 1) => { b[i] ^= bit; return b; };
edit('slope bit flip (first piece)', (P) => { flip(P[0], 5); return P; });
edit('slope bit flip (middle piece)', (P) => { flip(P[Math.floor(nP / 2)], 40); return P; });
edit('slope + p alias', (P) => { const b = P[3]; const l = BigInt('0x' + Buffer.from(b.subarray(0, 32)).reverse().toString('hex')); if (l + p < 1n << 256n) le32(l + p).copy(b, 0); return P; });
edit('two slope pieces swapped', (P) => { [P[1], P[2]] = [P[2], P[1]]; return P; });
edit('last slope piece dropped', (P) => { P.splice(nP - 1, 1); return P; });
edit('extra slope piece', (P) => { P.splice(nP, 0, Buffer.from(P[0])); return P; });
edit('empty slope piece inserted', (P) => { P.splice(1, 0, Buffer.alloc(0)); return P; });
edit('slope piece of 31 bytes appended', (P) => { P[nP - 1] = Buffer.concat([P[nP - 1], Buffer.alloc(31, 1)]); return P; });
edit('X: Lambda\' x + 1', (P) => { const b = P[idx.X]; be32(mod(BigInt('0x' + b.subarray(0, 32).toString('hex')) + 1n)).copy(b, 0); return P; });
edit('X: batch inverse + r (alias)', (P) => { const b = P[idx.X]; const v = BigInt('0x' + Buffer.from(b.subarray(64, 96)).reverse().toString('hex')); le32(v + r).copy(b, 64); return P; });
edit('X: batch inverse * 2', (P) => { const b = P[idx.X]; const v = BigInt('0x' + Buffer.from(b.subarray(64, 96)).reverse().toString('hex')); le32(mod(2n * v, r)).copy(b, 64); return P; });
if (J > 0 || JR > 0) edit('X: Jacobian zi * 2', (P) => { const b = P[idx.X]; const o = b.length - 32; const v = BigInt('0x' + Buffer.from(b.subarray(o)).reverse().toString('hex')); le32(mod(2n * v)).copy(b, o); return P; });
edit('WS: residue root word + 1', (P) => { flip(P[idx.WS], 0); return P; });
edit('WS: state word bit flip', (P) => { flip(P[idx.WS], 1000); return P; });
const so = 192 + (base.V.gt ? 65 * base.V.gt.fixed.length : 0); // first state word (after s^c and the GT nibbles)
edit('WS: state word + p alias', (P) => { const b = P[idx.WS]; const v = BigInt('0x' + Buffer.from(b.subarray(so, so + 32)).reverse().toString('hex')); if (v + p < 1n << 256n) le32(v + p).copy(b, so); return P; });
if (base.V.gt) { edit('WS: GT nibble byte xor 1', (P) => { flip(P[idx.WS], 192 + 7); return P; }); edit('WS: GT nibble byte = 16', (P) => { P[idx.WS][192 + 3] = 16; return P; }); edit('WS: GT nibble byte = 0x81', (P) => { P[idx.WS][192 + 5] = 0x81; return P; }); }
edit('WS: truncated by 32', (P) => { P[idx.WS] = P[idx.WS].subarray(0, P[idx.WS].length - 32); return P; });
edit('WQ: word bit flip', (P) => { flip(P[idx.WQ], 40); return P; });
edit('WQ: leading zero word', (P) => { P[idx.WQ] = Buffer.concat([Buffer.alloc(32), P[idx.WQ]]); return P; });
edit('WQ: extra trailing word', (P) => { P[idx.WQ] = Buffer.concat([P[idx.WQ], Buffer.alloc(32, 7)]); return P; });
edit('WQ: empty', (P) => { P[idx.WQ] = Buffer.alloc(0); return P; });
edit('WQ and WS swapped', (P) => { [P[idx.WQ], P[idx.WS]] = [P[idx.WS], P[idx.WQ]]; return P; });
edit('PROOF and PI swapped', (P) => { [P[idx.PI], P[idx.PROOF]] = [P[idx.PROOF], P[idx.PI]]; return P; });
edit('extra push on top', (P) => { P.push(Buffer.from([1])); return P; });
// adaptive: a wrong Lambda' with every other witness part rebuilt consistently (the t'-fold must reject it)
for (const [nm, f] of [['adaptive: Lambda\' = 2 Lambda', (L) => L.double()], ['adaptive: Lambda\' = Lambda + G', (L) => L.add(G1.BASE)], ['adaptive: Lambda\' = -Lambda', (L) => L.negate()]]) {
  const pr = d.valid[0]; const V = verifyPlonk(vk, pr.proof, pr.publicInputs);
  const wt = witnessFor(vk, pr.proof, pr.publicInputs, {J, JR, lam: aff(f(V.lamTrue))}); if (wt.accept) fail('reference accepts ' + nm);
  M.push({name: nm, pushes: pushesOf(wt)});
}
// adaptive (GT fold): the nibbles of a folded base encode s + 1, every other witness part rebuilt (states, quotient)
if (base.V.gt) for (const i of [0, base.V.gt.fixed.length - 1]) { const pr = d.valid[0]; const wt = witnessFor(vk, pr.proof, pr.publicInputs, {J, JR, fsDelta: [i, 1n]});
  if (wt.accept) fail('reference accepts nibbles for s + 1'); M.push({name: `adaptive: nibbles of folded base ${i} encode s + 1`, pushes: pushesOf(wt)}); }
// adaptive: a proof for other public inputs (statement swap) with a fully rebuilt witness
{ const pr = d.valid[1]; const wt = witnessFor(vk, pr.proof, d.valid[0].publicInputs, {J, JR}); M.push({name: 'adaptive: proof 1 with the public inputs of proof 0', pushes: pushesOf(wt)}); }
for (const m of M) {
  const res = run(m.pushes, basePad); const rej = !res.consensus.accepted && !res.standard.accepted;
  if (!rej) fail('manipulation accepted: ' + m.name);
  out.manipulations.push({name: m.name, rejected: rej, error: res.standard.error});
}
// tampered redeem (P2SH32 commitment)
{ const rd = Buffer.from(redeem); rd[rd.length - 10] ^= 1; const u = encodeUnlocking([...basePushes, ...(pad ? [Buffer.alloc(basePad)] : []), rd]);
  const rej = ['consensus', 'standard'].every((m) => !spend(regime, m, locking, u).accepted); if (!rej) fail('tampered redeem accepted'); out.manipulations.push({name: 'redeem byte flipped', rejected: rej}); }
console.log(`manipulations: ${out.manipulations.filter((x) => x.rejected).length}/${out.manipulations.length} rejected`);
out.unexpected = bad;
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
if (!quick) writeFileSync(new URL(`./results/test-${circuit}-${regime}.json`, import.meta.url), JSON.stringify(out, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 1) + '\n');
console.log(bad ? `FAIL: ${bad} unexpected` : 'OK: 0 unexpected');
process.exit(bad ? 1 : 0);
