// Cross-check the reference model and the layout (b) encoder against the prover's vectors:
// every valid vector accepts with the vector's G and indices, every tamper case rejects, and the LIFO Merkle programs
// use exactly the canonical multiproof's sibling count.
// usage: node test-model.mjs [vector files...]
import {readFileSync} from 'node:fs';
import {makeParams} from './params.mjs';
import {verifyModel, encodeB} from './model.mjs';
import {hex} from './field.mjs';

export function applyTamper(proof, tc) {
  if (tc.proof_hex) return Buffer.from(tc.proof_hex, 'hex');
  let b = Buffer.from(proof);
  for (const pa of tc.patches ?? []) {
    if (pa.xor) Buffer.from(pa.xor, 'hex').forEach((x, i) => { b[pa.offset + i] ^= x; });
    else Buffer.from(pa.bytes, 'hex').copy(b, pa.offset);
  }
  if (tc.truncate !== undefined) b = b.subarray(0, Number(tc.truncate));
  if (tc.append) b = Buffer.concat([b, Buffer.from(tc.append, 'hex')]);
  return b;
}

const files = process.argv.slice(2);
let bad = 0;
for (const path of files) {
  const v = JSON.parse(readFileSync(path, 'utf8'));
  const prm = makeParams(v.params);
  const proof = Buffer.from(v.proof, 'hex');
  const st = [BigInt(v.statement.x_in), BigInt(v.statement.y_out)];
  const m = verifyModel(prm, proof, st);
  const same = m.ok && hex(m.derived.tr.G) === v.derived.G && m.derived.tr.idx.every((x, i) => x === v.derived.indices[i]);
  const enc = encodeB(prm, proof);
  const sib = enc.siblings.reduce((a, b) => a + b, 0) * prm.h;
  const canSib = v.sections.siblings_total;
  console.log(`${path}: ${m.ok ? 'ACCEPT' : 'REJECT ' + m.reason} ${same ? 'G/idx match' : 'MISMATCH'} siblings ${sib}/${canSib}`);
  bad += !(m.ok && same && sib === canSib);
  for (const tc of v.tampered ?? []) {
    const want = tc.want_statement ? tc.want_statement.map(BigInt) : st;
    const mt = verifyModel(prm, applyTamper(proof, tc), want);
    console.log(`   ${tc.name.padEnd(28)} ${mt.ok ? 'ACCEPT' : 'REJECT'} ${mt.reason ?? ''} (prover: ${tc.observed_reason})`);
    bad += mt.ok;
  }
}
console.log(bad ? `${bad} unexpected` : 'all as expected');
process.exit(bad ? 1 : 0);
