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
for (const path of files) {
  const {v, prm, proof} = loadVector(path);
  const st = Uint8Array.from(proof.subarray(0, 16));
  const sp = spendB(prm, st, proof);
  const a = run(sp), c = run(sp, 'looseCons');
  console.log(`${path}: std ${a.accepted ? 'ACCEPT' : 'REJECT ' + a.error} cons ${c.accepted ? 'ACCEPT' : 'REJECT ' + c.error} op ${a.opCost} unl ${sp.unlocking.length}`);
  bad += !(a.accepted && c.accepted);
  if (!v.tampered) continue;
  const cases = v.tampered.map((tc) => ({name: tc.name, mk: () => {
    const want = tc.want_statement ? Uint8Array.from([...le8(BigInt(tc.want_statement[0])), ...le8(BigInt(tc.want_statement[1]))]) : st;
    return spendB(prm, want, applyTamper(proof, tc));
  }}));
  // on-chain cases: Merkle program bytes, sigma, hints and witness layout
  const mut = (name, f) => cases.push({name, mk: () => spendB(prm, st, proof, {}, f)});
  mut('record_sigma_swap', (it) => { const x = [...it]; const a0 = Uint8Array.from(x[0]), a1 = Uint8Array.from(x[1]); [a0[0], a1[0]] = [a1[0], a0[0]]; x[0] = a0; x[1] = a1; return x; });
  mut('record_sigma_dup', (it) => { const x = [...it]; const a1 = Uint8Array.from(x[1]); a1[0] = x[0][0]; x[1] = a1; return x; });
  mut('record_order_swap', (it) => { const x = [...it]; [x[0], x[1]] = [x[1], x[0]]; return x; });
  mut('record_trailing_byte', (it) => { const x = [...it]; x[3] = Uint8Array.from([...x[3], 0]); return x; });
  mut('record_op_flip_to_park', (it, enc) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[1] = 8; x[0] = r0; void enc; return x; });
  mut('record_bad_opcode', (it) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[1] = 16; x[0] = r0; return x; });
  mut('record_sibling_flip', (it) => { const x = [...it]; const r0 = Uint8Array.from(x[0]); r0[r0.length - 1] ^= 1; x[0] = r0; return x; });
  mut('T_hint_flip', (it, enc) => { const x = [...it]; const n = enc.records.flat().length; const L = Uint8Array.from(x[n]); L[L.length - 1] ^= 1; x[n] = L; return x; });
  mut('leaf_blob_extra_byte', (it, enc) => { const x = [...it]; const n = enc.records.flat().length; x[n] = Uint8Array.from([...x[n], 0]); return x; });
  mut('leaf_blobs_swapped', (it, enc) => { const x = [...it]; const n = enc.records.flat().length; [x[n], x[n + 1]] = [x[n + 1], x[n]]; return x; });
  mut('extra_push', (it) => [new Uint8Array(1), ...it]);
  mut('missing_record', (it) => it.slice(1));
  for (const cs of cases) {
    let r;
    try { r = run(cs.mk()); } catch (err) { r = {accepted: false, error: 'encoder: ' + err.message}; }
    console.log(`   ${cs.name.padEnd(28)} ${r.accepted ? 'ACCEPT  <-- UNEXPECTED' : 'REJECT ' + String(r.error).slice(0, 90)}`);
    bad += r.accepted;
  }
}
console.log(bad ? `${bad} unexpected` : 'all as expected');
process.exit(bad ? 1 : 0);
