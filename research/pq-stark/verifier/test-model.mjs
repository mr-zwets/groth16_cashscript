// Model vs the independent reference verifier (../prover/verify.mjs): same verdict on every valid and tampered case,
// and, on valid proofs, the same SHA-256 transcript inputs as Plonky3 recorded (vector transcript_hash_inputs).
// usage: node test-model.mjs ../prover/vectors/*.json
import {readFileSync} from 'node:fs';
import {verify, vkFromVector, V} from '../prover/verify.mjs';
import {vkxFromVector, verifyModel, applyTamper} from './model.mjs';

let total = 0, bad = 0;
for (const f of process.argv.slice(2)) {
  const v = JSON.parse(readFileSync(f, 'utf8'));
  const vk0 = vkFromVector(v), vk = vkxFromVector(v);
  const cases = [{name: 'valid', hex: v.proof_hex, pis: v.public_values}, ...(v.tampered ?? []).map((t) => ({name: t.name, hex: applyTamper(v.proof_hex, t), pis: t.public_values ?? v.public_values}))];
  let fb = 0;
  for (const c of cases) {
    const buf = Buffer.from(c.hex, 'hex'), pis = c.pis.map(BigInt);
    let ref; try { verify(vk0, pis, buf); ref = true; } catch (e) { if (!(e instanceof V)) throw e; ref = false; }
    const m = verifyModel(vk, buf, pis);
    let note = '';
    if (c.name === 'valid' && m.ok) {
      const mine = m.enc.t.hashes, rt = v.transcript_hash_inputs;
      if (mine.length !== rt.length || mine.some((x, i) => x !== rt[i])) { note = ` transcript differs (${mine.length} vs ${rt.length})`; }
    }
    const good = ref === m.ok && !note && (c.name !== 'valid' || ref);
    total++; if (!good) { bad++; fb++; }
    if (!good) console.log(`FAIL ${f.split('/').pop()} ${c.name}: ref ${ref} model ${m.ok} ${m.reason ?? ''}${note}`);
  }
  console.log(`${f.split('/').pop()}: ${cases.length} cases, ${fb} mismatches`);
}
console.log(`test-model: ${total} cases, ${bad} mismatches`);
process.exit(bad ? 1 : 0);
