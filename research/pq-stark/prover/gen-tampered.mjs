#!/usr/bin/env node
// Adds a `tampered` list to each vector file: constructive rejection tests (every case must be rejected
// by verify.mjs and by Plonky3's own verifier through `pq-stark-prover check`).
// Usage: node gen-tampered.mjs vectors/*.json
import { readFileSync, writeFileSync } from 'node:fs';
import { P, parse, verify, vkFromVector, le64 } from './verify.mjs';

const MAX_REGRIND_BITS = 22; // honest re-grind of the query PoW after tampering (JS search)

function cases(v) {
  const vk = vkFromVector(v);
  const buf = Buffer.from(v.proof_hex, 'hex');
  const pr = parse(buf, vk);
  const S = pr.sec; const out = [];
  // same-length edits are stored as overwrite patches against the valid proof bytes
  const patch = (b) => { const p = []; for (let i = 0; i < b.length; i++) if (b[i] !== buf[i]) { let j = i; while (j < b.length && b[j] !== buf[j]) j++; p.push({ at: i, hex: b.subarray(i, j).toString('hex') }); i = j; } return p; };
  const mk = (name, f) => { const b = Buffer.from(buf); f(b); out.push({ name, patch: patch(b) }); };
  const flip = (name, [o]) => mk(name, (b) => { b[o] ^= 0x01; });
  const inc = (name, [o]) => mk(name, (b) => { b.writeBigUInt64LE((b.readBigUInt64LE(o) + 1n) % P, o); });
  const roots = S.roots; const nr = vk.zk ? 3 : 2;
  flip('trace root', roots[0]);
  flip('quotient root', roots[1]);
  if (vk.zk) flip('random-polynomial root', roots[2]);
  flip('first FRI commit-phase root', roots[nr]);
  flip('last FRI commit-phase root', roots[roots.length - 1]);
  const ood = S.ood; const D = vk.D;
  inc('OOD trace_local[0]', ood[0]);
  inc('OOD trace_next[0]', ood[vk.width * D]);
  inc('OOD quotient chunk 0', ood[2 * vk.width * D]);
  if (vk.C > 1) inc('OOD last quotient chunk', ood[2 * vk.width * D + (vk.C - 1) * D * D]);
  if (vk.zk) { inc('OOD random polynomial', ood[2 * vk.width * D + vk.C * D * D]); inc('OOD random-codeword opening (last)', ood[ood.length - 1]); }
  inc('final polynomial coeff 0 (PoW breaks)', S.final[0]);
  if (vk.qpow) inc('query PoW witness + 1', S.pow[S.pow.length - 1]);
  // honest re-grind: final polynomial coeff + 1 with a valid query PoW, so only the FRI checks can catch it
  if (vk.qpow <= MAX_REGRIND_BITS) {
    const b = Buffer.from(buf); const fo = S.final[0][0];
    b.writeBigUInt64LE((b.readBigUInt64LE(fo) + 1n) % P, fo);
    const wOff = S.pow[S.pow.length - 1][0];
    verify(vk, v.public_values.map(BigInt), b, { atQueryPow: (ch) => {
      for (let w = 0n; ; w++) { const c = ch.clone(); if (c.pow(vk.qpow, w)) { b.writeBigUInt64LE(w, wOff); return; } }
    } });
    out.push({ name: 'final polynomial coeff 0 + 1, query PoW re-ground', patch: patch(b) });
  }
  // input leaves: batches in claim order
  let k = 0;
  vk.claims.forEach((round, bi) => {
    const per = vk.Q * round.reduce((s, m) => s + m.width, 0);
    const label = vk.zk ? ['random', 'trace', 'quotient'][bi] : ['trace', 'quotient'][bi];
    inc(`input leaf ${label} q0[0]`, S.input_leaves[k]);
    inc(`input leaf ${label} q${vk.Q - 1}[last]`, S.input_leaves[k + per - 1]);
    k += per;
  });
  flip('input sibling (first)', S.input_siblings[0]);
  flip('input sibling (last)', S.input_siblings[S.input_siblings.length - 1]);
  inc('FRI sibling value (first)', S.fri_leaves[0]);
  inc('FRI sibling value (last)', S.fri_leaves[S.fri_leaves.length - 1]);
  flip('FRI Merkle sibling (first)', S.fri_siblings[0]);
  flip('FRI Merkle sibling (last)', S.fri_siblings[S.fri_siblings.length - 1]);
  if (vk.zk) { inc('leaf salt (first)', S.salts[0]); inc('leaf salt (last)', S.salts[S.salts.length - 1]); }
  // encoding
  mk('non-canonical field element (0xff..ff in final polynomial)', (b) => { b.writeBigUInt64LE((1n << 64n) - 1n, S.final[0][0]); });
  mk('degree_bits + 1', (b) => { b[0] += 1; });
  out.push({ name: 'truncated by one byte', truncate: buf.length - 1 });
  out.push({ name: 'one trailing byte', insert: { at: buf.length, hex: '00' } });
  { // an extra (zero) digest in the first multiproof, with its count raised to match
    const [co] = S.counts[0]; const n = buf.readUInt16LE(co); const end = co + 2 + 32 * n;
    const cnt = Buffer.alloc(2); cnt.writeUInt16LE(n + 1);
    out.push({ name: 'extra sibling digest in first multiproof (count + 1)', patch: [{ at: co, hex: cnt.toString('hex') }], insert: { at: end, hex: '00'.repeat(vk.h) } });
  }
  // statement
  const pis = [...v.public_values]; pis[pis.length - 1] = ((BigInt(pis[pis.length - 1]) + 1n) % P).toString();
  out.push({ name: 'public output + 1 (different statement)', public_values: pis });
  const pis0 = [...v.public_values]; pis0[0] = ((BigInt(pis0[0]) + 1n) % P).toString();
  out.push({ name: 'public input + 1 (different statement)', public_values: pis0 });
  return out;
}

for (const f of process.argv.slice(2)) {
  const v = JSON.parse(readFileSync(f, 'utf8'));
  v.tampered = cases(v);
  writeFileSync(f, JSON.stringify(v, null, 2));
  console.log(`${f}: ${v.tampered.length} tampered cases`);
}
