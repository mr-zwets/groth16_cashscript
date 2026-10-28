// Layout (b) accept/reject sweep on the loosened BCH 2026 VM (standard and consensus): every valid vector must be
// accepted, every tamper case of the vectors (and the extra on-chain cases below) must be rejected.
// usage: node test-b.mjs [vector files...]
import {loadVector, spendB} from './layout-b.mjs';
import {evaluate} from './vm.mjs';
import {applyTamper} from './test-model.mjs';
import {le8} from './field.mjs';

const files = process.argv.slice(2);
let bad = 0;
const run = (sp, vm = 'looseStd') => evaluate(vm, sp.locking, sp.unlocking);
// where a rejection happened: the last marker passed (markers build)
function phaseOf(sp, markers) {
  const labels = sp.built.codeSizes.map(([l]) => l);
  const main = labels.filter((l) => !l.startsWith('q-')), q = labels.filter((l) => l.startsWith('q-'));
  const nMainBefore = main.indexOf('merkle') >= 0 ? main.length - 1 : main.length; // 'end' comes after the queries
  if (markers <= nMainBefore) return 'after ' + (main[markers - 1] ?? 'start');
  const k = markers - nMainBefore; return `query ${Math.floor((k - 1) / q.length)} after ${q[(k - 1) % q.length]}`;
}
for (const path of files) {
  const {v, prm, proof} = loadVector(path);
  const st = Uint8Array.from(proof.subarray(0, 16));
  const sp = spendB(prm, st, proof);
  const a = run(sp), c = run(sp, 'looseCons');
  console.log(`${path}: std ${a.accepted ? 'ACCEPT' : 'REJECT ' + a.error} cons ${c.accepted ? 'ACCEPT' : 'REJECT ' + c.error} op ${a.opCost} unl ${sp.unlocking.length}`);
  bad += !(a.accepted && c.accepted);
  if (!v.tampered) continue;
  const cases = v.tampered.map((tc) => ({name: tc.name, mk: () => {
    // the statement is baked into the redeem: a case that patches the proof's statement bytes is run against the
    // verifier for the patched statement (the rest of the proof was made for the original one)
    const tp = applyTamper(proof, tc);
    const want = tc.want_statement ? Uint8Array.from([...le8(BigInt(tc.want_statement[0])), ...le8(BigInt(tc.want_statement[1]))]) : Uint8Array.from(tp.subarray(0, 16));
    return spendB(prm, want, tp, {markers: true});
  }}));
  // on-chain cases: Merkle program bytes, sigma, hints and witness layout
  const mut = (name, f) => cases.push({name, mk: () => spendB(prm, st, proof, {markers: true}, f)});
  mut('record_sigma_swap', (it) => { const x = [...it]; const a0 = Uint8Array.from(x[0]), a1 = Uint8Array.from(x[1]); [a0[0], a1[0]] = [a1[0], a0[0]]; x[0] = a0; x[1] = a1; return x; });
  mut('record_sigma_dup', (it) => { const x = [...it]; const a1 = Uint8Array.from(x[1]); a1[0] = x[0][0]; x[1] = a1; return x; });
  mut('record_order_swap', (it) => { const x = [...it]; [x[0], x[1]] = [x[1], x[0]]; return x; });
  mut('record_trailing_byte', (it) => { const x = [...it]; x[3] = Uint8Array.from([...x[3], 0]); return x; });
  mut('record_op_flip_to_park', (it, enc) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[1] = 8; x[0] = r0; void enc; return x; });
  mut('record_bad_opcode', (it) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[1] = 16; x[0] = r0; return x; });
  mut('record_sibling_flip', (it) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[r0.length - 1] ^= 1; x[0] = r0; return x; });
  const nR = (it) => it.length - prm.s - (prm.r + 4);   // record groups = items - leaf blobs - PT items (rT rC OOD rF.. FIN NONCE)
  mut('T_hint_flip', (it) => { const x = [...it]; const n = nR(it); const L = Uint8Array.from(x[n]); L[L.length - 1] ^= 1; x[n] = L; return x; });
  mut('leaf_blob_extra_byte', (it) => { const x = [...it]; const n = nR(it); x[n] = Uint8Array.from([...x[n], 0]); return x; });
  mut('leaf_blobs_swapped', (it) => { const x = [...it]; const n = nR(it); [x[n], x[n + 1]] = [x[n + 1], x[n]]; return x; });
  mut('record_group_split', (it) => { const x = [...it]; const g = x[0]; const cut = 1 + Math.floor(g.length / 2); x.splice(0, 1, g.subarray(0, cut), g.subarray(cut)); return x; });
  mut('fin_coeff_flip', (it) => { const x = [...it]; const k = x.length - 2; const f = Uint8Array.from(x[k]); f[5] ^= 1; x[k] = f; return x; });
  mut('ood_value_flip', (it) => { const x = [...it]; const k = x.length - 2 - (prm.r - 1) - 1; const f = Uint8Array.from(x[k]); f[3] ^= 4; x[k] = f; return x; });
  mut('extra_push', (it) => [new Uint8Array(1), ...it]);
  mut('missing_record', (it) => it.slice(1));
  for (const cs of cases) {
    let r;
    let sp;
    try { sp = cs.mk(); r = run(sp); } catch (err) { r = {accepted: false, error: 'encoder: ' + err.message}; }
    const where = sp && !r.accepted ? phaseOf(sp, r.markers) : '';
    console.log(`   ${cs.name.padEnd(28)} ${r.accepted ? 'ACCEPT  <-- UNEXPECTED' : 'REJECT ' + String(r.error).slice(0, 70) + ' [' + where + ']'}`);
    bad += r.accepted;
  }
}
console.log(bad ? `${bad} unexpected` : 'all as expected');
process.exit(bad ? 1 : 0);
