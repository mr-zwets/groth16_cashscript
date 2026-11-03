#!/usr/bin/env node
// gen-cases.mjs: builds the S3 agreement set (DESIGN-T8 §8) for every valid vector. Writes one file per vector
// into OUTDIR: a copy of the vector whose `tampered` list is replaced by the extended case list, so the Rust
// `check --verdicts` and the JS verifier run exactly the same cases. Every case has a `family` and an
// expected verdict (`expect`, default false = reject).
//
// Families (Track 5's, extended to the p3b-v1 fields):
//   cap        every Merkle cap digest (input rounds, FRI rounds): byte 0 flipped; byte 31 of each cap's first digest
//   terminal   every LogUp terminal: coefficient 0 + 1, coefficient 2 + 1
//   ood        every opened value at zeta / zeta*g (trace, preprocessed, quotient chunks, random, permutation): coeff 0 + 1
//   random     every opened random-codeword value (ZK): coeff 0 + 1
//   pow        every PoW witness present in the bytes: + 1
//   final      final-polynomial coefficients 0, 8, 16, ... and the last: coeff 0 + 1
//   row        per PCS round and matrix (injected short-table matrices included): query 0 col 0, last query last col, + 1
//   salt       per PCS round and matrix: query 0 salt 0, last query last salt, + 1
//   sibling    per Merkle multiproof (input rounds, FRI rounds): first, middle, last sibling byte 0 flipped
//   count      per multiproof: sibling count + 1 and - 1
//   fri_value  per FRI round: query 0 value 0, last query last value, + 1; FRI salts: query 0 salt 0 + 1
//   truncate   length - 1, - 8, - 24, - 32, half, 0, end of the ood region, end of the final polynomial
//   extend     + 1 byte, + 8 bytes at the end; one cap digest duplicated; 24 zero bytes after the ood region
//   noncanon   one element of each kind replaced by a non-canonical encoding (p, v + p, 2^64 - 1)
//   statement  each public value + 1, NF - 1, NF + p, a foreign/stale ROOT, a foreign CTX, permuted values, all zero,
//              values moved to another instance
//   other_vk   the proof of another vector of the same AIR under this verifying key (other cap, other set, other
//              setup seed, other statement AIR); a second-seed proof of the same statement (expect accept when
//              the VK is the same)
//   forced     proofs of unsatisfying traces / wrong public values produced by the release prover (S2 forced)
//   vk variant (extra files NAME~vk-TAG.json, s3_valid_expect = false): the stored proof under a VK with one PoW
//              difficulty or the Merkle cap height changed
//
// Usage: node gen-cases.mjs --out OUTDIR [--forced FORCED.json] [--light-prefix PREFIX]... VECTOR.json...
//   --light-prefix  (repeatable) vectors whose path starts with PREFIX get one or two cases per family (extra-seed and S2
//                   batch vectors); all vectors serve as references for the statement and other_vk families
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename } from 'node:path';
import { P, vkFromVector, parse } from './verify-batch.mjs';

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const outDir = opt('--out'); const forcedFile = opt('--forced');
const lightPrefixes = args.filter((a, i) => args[i - 1] === '--light-prefix');
const files = args.filter((a, i) => !a.startsWith('--') && !['--out', '--forced', '--light-prefix'].includes(args[i - 1]));
mkdirSync(outDir, { recursive: true });

const le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b.toString('hex'); };
const rd = (buf, at) => buf.readBigUInt64LE(at);
const inc = (buf, at) => le((rd(buf, at) + 1n) % P); // canonical + 1
const flip = (buf, at) => (buf[at] ^ 0x01).toString(16).padStart(2, '0');

// integers beyond 2^53 (setup_seed, lookup constants) are kept verbatim: the copies must stay byte-exact VK data
const exact = (k, x, ctx) => (typeof x === 'number' && !Number.isSafeInteger(x) ? JSON.rawJSON(ctx.source) : x);
const vecs = files.map((f) => ({ f, v: JSON.parse(readFileSync(f, 'utf8'), exact) }));
const forced = forcedFile ? JSON.parse(readFileSync(forcedFile, 'utf8')).cases : [];
const pvSig = (pv) => JSON.stringify(pv.map((p) => p.length));
const setKey = (v) => `${v.set.name}`;
const caseBase = (c) => c.replace(/@.*/, ''); // m1@leaf@w -> m1

let total = 0;
for (const { f, v } of vecs) {
  const vk = vkFromVector(v); const buf = Buffer.from(v.proof_hex, 'hex'); const L = buf.length;
  const light = lightPrefixes.some((p) => f.startsWith(p));
  const map = []; parse(buf, vk, (r) => map.push(r));
  const by = (pred) => map.filter(pred);
  const cases = [];
  const add = (family, name, t) => cases.push({ family, name: `${family}: ${name}`, ...t });
  const patch = (at, hex) => ({ patch: [{ at, hex }] });

  // ---- byte-level families
  const caps = by((r) => r.kind === 'digest' && r.label.startsWith('cap.'));
  caps.forEach((r, k) => { if (!light || k === 0) add('cap', `${r.label} byte 0`, patch(r.at, flip(buf, r.at))); });
  for (const r of caps.filter((r) => r.label.endsWith('[0]'))) if (!light) add('cap', `${r.label} byte 31`, patch(r.at + 31, flip(buf, r.at + 31)));
  for (const r of by((r) => r.label.startsWith('terminal'))) {
    add('terminal', `${r.label} c0 + 1`, patch(r.at, inc(buf, r.at)));
    if (!light) add('terminal', `${r.label} c2 + 1`, patch(r.at + 16, inc(buf, r.at + 16)));
  }
  const ood = by((r) => r.label.startsWith('ood['));
  ood.forEach((r, k) => { if (!light || k === 0 || k === ood.length - 1) add('ood', `${r.label} c0 + 1`, patch(r.at, inc(buf, r.at))); });
  const rv = by((r) => r.label.startsWith('random_values'));
  rv.forEach((r, k) => { if (!light || k === 0) add('random', `${r.label} c0 + 1`, patch(r.at, inc(buf, r.at))); });
  for (const r of by((r) => r.kind === 'pow')) add('pow', `${r.label} + 1`, patch(r.at, inc(buf, r.at)));
  const fin = by((r) => r.label.startsWith('final_poly'));
  fin.forEach((r, k) => { if (k === fin.length - 1 || (light ? k === 0 : k % 8 === 0)) add('final', `${r.label} c0 + 1`, patch(r.at, inc(buf, r.at))); });
  for (const rs of vk.rounds) {
    rs.matrices.forEach((m, mi) => {
      const what = `${rs.name} matrix ${mi} (instance ${m.inst}, 2^${m.logH}${m.logH < vk.logH ? ', injected' : ''})`;
      const first = map.find((r) => r.label === `row.${rs.name}[q0][m${mi}][0]`);
      const last = map.find((r) => r.label === `row.${rs.name}[q${vk.Q - 1}][m${mi}][${m.width - 1}]`);
      if (!light || mi === 0) add('row', `${what} q0 col 0 + 1`, patch(first.at, inc(buf, first.at)));
      if (!light) add('row', `${what} q${vk.Q - 1} col ${m.width - 1} + 1`, patch(last.at, inc(buf, last.at)));
      if (vk.zk) {
        const s0 = map.find((r) => r.label === `salt.${rs.name}[q0][m${mi}][0]`);
        const s1 = map.find((r) => r.label === `salt.${rs.name}[q${vk.Q - 1}][m${mi}][${vk.salt - 1}]`);
        if (!light || mi === 0) add('salt', `${what} q0 salt 0 + 1`, patch(s0.at, inc(buf, s0.at)));
        if (!light) add('salt', `${what} q${vk.Q - 1} salt ${vk.salt - 1} + 1`, patch(s1.at, inc(buf, s1.at)));
      }
    });
  }
  const sibLists = [...vk.rounds.map((r) => `sib.${r.name}`), ...vk.logArities.map((_, r) => `fri[${r}].sib`)];
  for (const sl of sibLists) {
    const sibs = by((r) => r.kind === 'digest' && r.label.startsWith(`${sl}[`));
    const cnt = map.find((r) => r.label === `${sl}.count`);
    const picks = sibs.length ? [...new Set([0, sibs.length >> 1, sibs.length - 1])] : [];
    for (const k of light ? picks.slice(0, 1) : picks) add('sibling', `${sl}[${k}] byte 0`, patch(sibs[k].at, flip(buf, sibs[k].at)));
    const c = buf.readUInt16LE(cnt.at); const h16 = (x) => { const b = Buffer.alloc(2); b.writeUInt16LE(x); return b.toString('hex'); };
    add('count', `${sl} count + 1`, patch(cnt.at, h16(c + 1)));
    if (!light && c > 0) add('count', `${sl} count - 1`, patch(cnt.at, h16(c - 1)));
  }
  vk.logArities.forEach((la, r) => {
    const a = map.find((x) => x.label === `fri[${r}].value[q0][0]`);
    const b = map.find((x) => x.label === `fri[${r}].value[q${vk.Q - 1}][${2 ** la - 2}]`);
    add('fri_value', `fri[${r}] q0 value 0 c0 + 1`, patch(a.at, inc(buf, a.at)));
    if (!light) add('fri_value', `fri[${r}] q${vk.Q - 1} last value c0 + 1`, patch(b.at, inc(buf, b.at)));
    if (vk.zk) { const s = map.find((x) => x.label === `fri[${r}].salt[q0][0]`); add('fri_value', `fri[${r}] q0 salt 0 + 1`, patch(s.at, inc(buf, s.at))); }
  });
  const oodEnd = ood[ood.length - 1].at + 24; const finEnd = fin[fin.length - 1].at + 24;
  const truncs = light ? [[L - 1, 'length - 1']] : [[L - 1, 'length - 1'], [L - 8, 'length - 8'], [L - 24, 'length - 24'], [L - 32, 'length - 32'],
    [L >> 1, 'half'], [0, 'empty'], [oodEnd, 'end of the ood region'], [finEnd, 'end of the final polynomial']];
  for (const [n, what] of truncs) add('truncate', what, { truncate: n });
  add('extend', '1 byte at the end', { insert: { at: L, hex: '00' } });
  if (!light) {
    add('extend', '8 bytes at the end', { insert: { at: L, hex: '00'.repeat(8) } });
    add('extend', 'first cap digest duplicated', { insert: { at: 32, hex: buf.subarray(0, 32).toString('hex') } });
    add('extend', '24 zero bytes after the ood region', { insert: { at: oodEnd, hex: '00'.repeat(24) } });
  }
  // non-canonical encodings: p, v + p when it fits in 64 bits, else 2^64 - 1
  const nc = (r, off = 0) => { const x = rd(buf, r.at + off); return x + P < 2n ** 64n ? le(x + P) : 'ff'.repeat(8); };
  const kinds = [
    ['ood value', ood[0], 0, () => le(P)], ['final coefficient', fin[0], 8, null], ['pow witness', by((r) => r.kind === 'pow')[0], 0, () => le(P)],
    ['terminal', by((r) => r.label.startsWith('terminal'))[0], 0, null], ['random value', rv[0], 0, null],
    ['row element', map.find((r) => r.label.startsWith('row.') && r.kind === 'base'), 0, null],
    ['salt', map.find((r) => r.label.startsWith('salt.')), 0, () => le(P)], ['fri value', map.find((r) => r.label.startsWith('fri[') && r.kind === 'ext'), 16, null],
  ];
  for (const [what, r, off, fn] of kinds) if (r && (!light || what === 'ood value')) add('noncanon', `${what} ${r.label} = ${fn ? 'p' : 'v + p (or 2^64 - 1)'}`, patch(r.at + off, fn ? fn() : nc(r, off)));

  // ---- statement families (public values come from the statement layer, never from the proof)
  const pvs = v.public_values; const pi = pvs.findIndex((p) => p.length > 0);
  const withPv = (fn) => { const c = pvs.map((p) => [...p]); fn(c); return c; };
  if (pi >= 0) {
    const stmt = /^m[12]@/.test(v.case); const n = pvs[pi].length;
    for (let j = 0; j < n; j++) if (!light || j === 0 || j === 4 || j === 8) {
      const nm = stmt ? `${['ROOT', 'NF', 'CTX'][j >> 2]}[${j & 3}]` : `pv[${j}]`;
      add('statement', `${nm} + 1`, { public_values: withPv((c) => { c[pi][j] = ((BigInt(c[pi][j]) + 1n) % P).toString(); }) });
    }
    add('statement', 'all public values zero', { public_values: withPv((c) => { c[pi] = c[pi].map(() => '0'); }) });
    add('statement', 'first two public values swapped', { public_values: withPv((c) => { [c[pi][0], c[pi][1]] = [c[pi][1], c[pi][0]]; }) });
    if (pvs.length > 1) add('statement', `public values moved to instance ${pi === 0 ? 1 : 0}`, { public_values: withPv((c) => { c[pi === 0 ? 1 : 0] = c[pi]; c[pi] = []; }) });
    if (stmt) {
      add('statement', 'NF[0] - 1', { public_values: withPv((c) => { c[pi][4] = ((BigInt(c[pi][4]) + P - 1n) % P).toString(); }) });
      add('statement', 'NF[0] + p (non-canonical, same residue)', { public_values: withPv((c) => { c[pi][4] = (BigInt(c[pi][4]) + P).toString(); }) });
      add('statement', 'ROOT and NF swapped', { public_values: withPv((c) => { const r = c[pi].slice(0, 4); c[pi].splice(0, 4, ...c[pi].slice(4, 8)); c[pi].splice(4, 4, ...r); }) });
      add('statement', 'rotated (NF, CTX, ROOT)', { public_values: withPv((c) => { c[pi] = [...c[pi].slice(4), ...c[pi].slice(0, 4)]; }) });
      add('statement', 'CTX[3] xor 1 (changed outputs)', { public_values: withPv((c) => { c[pi][11] = (BigInt(c[pi][11]) ^ 1n).toString(); }) });
      // foreign/stale ROOT and foreign CTX: taken from another statement of the same AIR
      const other = vecs.find((o) => o.v !== v && caseBase(o.v.case) === caseBase(v.case) && o.v.case !== v.case);
      if (other) {
        const op = other.v.public_values[pi];
        add('statement', `ROOT of another tree (foreign/stale; from ${basename(other.f)})`, { public_values: withPv((c) => { c[pi].splice(0, 4, ...op.slice(0, 4)); }) });
        add('statement', `CTX of another transaction (from ${basename(other.f)})`, { public_values: withPv((c) => { c[pi].splice(8, 4, ...op.slice(8, 12)); }) });
        add('statement', `NF of another note (from ${basename(other.f)})`, { public_values: withPv((c) => { c[pi].splice(4, 4, ...op.slice(4, 8)); }) });
      }
    }
  }

  // ---- other verifying keys / alternative valid proofs
  for (const { f: of, v: ov } of vecs) {
    if (ov === v) continue;
    const sameCase = ov.case === v.case; const sameAirFamily = caseBase(ov.case) === caseBase(v.case);
    // M1 <-> M2: the other statement AIR's proof of the same leaf
    const m1m2 = /^m[12]@/.test(v.case) && /^m[12]@/.test(ov.case) && caseBase(ov.case) !== caseBase(v.case) && ov.case.split('@')[1] === v.case.split('@')[1];
    if (!sameCase && !m1m2) continue;
    const sameVk = sameCase && setKey(ov) === setKey(v) && JSON.stringify(ov.preprocessed_commitment) === JSON.stringify(v.preprocessed_commitment)
      && ov.shift === v.shift && JSON.stringify(ov.shape) === JSON.stringify(v.shape);
    if (sameVk && ov.proof_hex === v.proof_hex) continue;
    if (light && !sameVk && !m1m2) continue;
    // public values: the other proof's own statement, mapped onto this VK's instance layout
    const opv = ov.public_values.find((p) => p.length) ?? [];
    const pv = pvs.map((p) => (p.length ? (opv.length === p.length ? opv : p) : []));
    if (m1m2 && !sameAirFamily) {
      add('other_vk', `${basename(of)} (other statement AIR) under this VK`, { replace: ov.proof_hex, public_values: pv });
    } else if (sameVk) {
      add('other_vk', `${basename(of)} (same statement and VK, other ZK seed): valid`, { replace: ov.proof_hex, public_values: ov.public_values, expect: true });
    } else {
      add('other_vk', `${basename(of)} (${ov.set.name}, shift ${ov.shift}, seed ${ov.seed}) under this VK (${v.set.name}, shift ${v.shift}, seed ${v.seed})`,
        { replace: ov.proof_hex, public_values: pvSig(ov.public_values) === pvSig(pvs) ? ov.public_values : pvs });
    }
  }

  // ---- forced unsatisfying traces (S2), replayed under this VK when it is the one they were proved for
  for (const c of forced) {
    if (!c.proof_hex || c.case !== v.case || c.set !== v.set.name || v.seed !== 1) continue;
    add('forced', `${c.name} (${c.what})`, { replace: c.proof_hex, public_values: c.public_values });
  }

  for (const c of cases) { for (const p of c.patch ?? []) if (p.at + p.hex.length / 2 > L) throw new Error(`patch out of range: ${c.name}`); }
  total += cases.length;
  writeFileSync(`${outDir}/${basename(f)}`, JSON.stringify({ ...v, tampered: cases, s3_source: f }));
  console.log(`${basename(f)}: ${cases.length} cases`);
}

// ---- verifying-key variants: the stored proof under a VK whose parameters differ (expected reject). One file
// per variant; the vector's set and shape are changed together so both verifiers build the variant VK.
const VARIANTS = [
  ['bpow-1', (s) => { s.batch_pow_bits -= 1; }], ['qpow-1', (s) => { s.query_pow_bits -= 1; }], ['cpow+1', (s) => { s.commit_pow_bits += 1; }],
  ['lpow-1', (s) => { s.lookup_pow_bits -= 1; }, (v) => v.shape.has_lookups && v.set.lookup_pow_bits > 1],
  ['opow=1', (s) => { s.ood_pow_bits = 1; }, (v) => v.set.ood_pow_bits === 0],
  // a cap change also changes a preprocessed commitment, which only the Rust setup can recompute: VKs without one
  ['cap+1', (s) => { s.cap_height += 1; }, (v) => !v.preprocessed_commitment],
];
let nv = 0;
for (const { f, v } of vecs) {
  if (!(f.includes('/vectors/S2/m1-0-') || f.includes('/vectors/S2/m2-0-') || f.endsWith('three_instances_mixed_sizes-Z128g.json') || f.endsWith('both_lookups_zk-Z128.json'))) continue;
  for (const [tag, edit, when] of VARIANTS) {
    if (when && !when(v)) continue;
    const set = { ...v.set, name: `${v.set.name}~${tag}` }; edit(set);
    const sh = JSON.parse(JSON.stringify(v.shape));
    const cl = (logMin) => 2 ** Math.min(set.cap_height, logMin);
    for (const r of sh.rounds) r.cap_len = cl(Math.min(...r.matrices.map((m) => m.log_height)));
    { let h = Math.max(...sh.instances.map((i) => i.log_lde)); sh.fri_cap_lens = sh.log_arities.map((la) => { h -= la; return cl(h); }); }
    Object.assign(sh, { cap_height: set.cap_height, lookup_pow: sh.has_lookups && set.lookup_pow_bits > 0, ood_pow: set.ood_pow_bits > 0,
      batch_pow: set.batch_pow_bits > 0, commit_pow: set.commit_pow_bits > 0, query_pow: set.query_pow_bits > 0 });
    const out = `${outDir}/${basename(f, '.json')}~vk-${tag}.json`;
    writeFileSync(out, JSON.stringify({ ...v, set, shape: sh, tampered: [], s3_valid_expect: false, s3_source: f, s3_vk_variant: tag }));
    nv++;
  }
}
console.log(`gen-cases: ${files.length} vectors, ${total} cases; ${nv} VK-variant files`);
