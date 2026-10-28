#!/usr/bin/env node
// Independent JavaScript (BigInt) verifier for the pq-hash canonical proof, written from SERIALIZATION.md.
// It shares no code with the Python prover/verifier; agreement on every vector cross-checks the byte contract.
// Usage: node verify.mjs vectors/*.json      (exit code 1 on any unexpected result)
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const P = (1n << 64n) - (1n << 32n) + 1n;
const W = 7n;
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest();
const mod = (a) => ((a % P) + P) % P;
const powp = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
const invp = (a) => { if (mod(a) === 0n) throw new Error('inv0'); return powp(a, P - 2n); };
const rou = (k) => powp(7n, (P - 1n) / BigInt(k));
const le = (buf) => { let v = 0n; for (let i = buf.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]); return v; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(mod(v)); return b; };
const u8 = (v) => Buffer.from([v]);
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };

function ext(e) {
  const F = {
    e,
    zero: Array(e).fill(0n),
    one: [1n, ...Array(e - 1).fill(0n)],
    lift: (a) => [mod(a), ...Array(e - 1).fill(0n)],
    add: (a, b) => a.map((x, i) => mod(x + b[i])),
    sub: (a, b) => a.map((x, i) => mod(x - b[i])),
    smul: (a, k) => a.map((x) => mod(x * k)),
    mul: (a, b) => e === 2
      ? [mod(a[0] * b[0] + W * a[1] * b[1]), mod(a[0] * b[1] + a[1] * b[0])]
      : [mod(a[0] * b[0] + W * (a[1] * b[2] + a[2] * b[1])), mod(a[0] * b[1] + a[1] * b[0] + W * a[2] * b[2]),
        mod(a[0] * b[2] + a[1] * b[1] + a[2] * b[0])],
    eq: (a, b) => a.every((x, i) => mod(x - b[i]) === 0n),
    inv: (a) => {
      if (e === 2) { const n = mod(a[0] * a[0] - W * a[1] * a[1]); const ni = invp(n); return [mod(a[0] * ni), mod(-a[1] * ni)]; }
      const [a0, a1, a2] = a;
      const b0 = mod(a0 * a0 - W * a1 * a2), b1 = mod(W * a2 * a2 - a0 * a1), b2 = mod(a1 * a1 - a0 * a2);
      const ni = invp(mod(a0 * b0 + W * (a2 * b1 + a1 * b2)));
      return [b0, b1, b2].map((x) => mod(x * ni));
    },
    dec: (buf, o) => Array.from({ length: e }, (_, i) => mod(le(buf.subarray(o + 8 * i, o + 8 * i + 8)))),
    fromDigest: (d) => { let v = le(d); const out = []; for (let i = 0; i < e; i++) { out.push(v % P); v /= P; } return out; },
  };
  F.pow = (a, k) => { let r = F.one; let b = a; k = BigInt(k); while (k > 0n) { if (k & 1n) r = F.mul(r, b); b = F.mul(b, b); k >>= 1n; } return r; };
  return F;
}

function params(pj) {
  const fold = pj.arities;
  const sizes = pj.layer_sizes.map(Number);
  return { ...pj, sizes, fold, r: fold.length, D: pj.final_coeffs };
}

function roundConstants() {
  return Array.from({ length: 8 }, (_, j) => le(sha(Buffer.from('verifier.cash/pq-hash/rc'), u8(j))) % P);
}
function periodicPoly(C) {
  const w8i = invp(rou(8)), i8 = invp(8n);
  return Array.from({ length: 8 }, (_, k) => mod(C.reduce((s, c, j) => s + c * powp(w8i, BigInt(j * k)), 0n) * i8));
}
function tag(p) {
  const C = roundConstants(), Pc = periodicPoly(C);
  const K = Buffer.concat([...C.map(u64), ...Pc.map(u64), u64(rou(p.n)), u64(rou(p.N)),
    Buffer.from([p.e, 7, Math.log2(p.n), Math.log2(p.N), p.r, ...p.fold, p.log_final_degree]), u16(p.queries),
    Buffer.from([p.grinding_bits, p.digest_bytes, p.m])]);
  return Buffer.concat([Buffer.from('verifier.cash/pq-hash/v1'), u8(p.pid), sha(K)]);
}

class Reject extends Error {}

export function verify(pj, proof, want) {
  const p = params(pj), E = ext(p.e), e8 = 8 * p.e, h = p.digest_bytes;
  const trees = pj.trees;
  // PT layout in transcript order
  let o = 0; const f = {};
  const take = (name, len) => { f[name] = proof.subarray(o, o + len); o += len; };
  take('x_in', 8); take('y_out', 8); take('root_trace', h); take('root_comp', h); take('ood', 5 * e8);
  for (let i = 1; i < p.r; i++) take(`root_fri${i}`, h);
  take('final', p.D * e8); take('nonce', 8);
  const leafTotal = trees.reduce((s, t) => s + t.leaf_bytes, 0);
  if (proof.length < o + p.queries * leafTotal) throw new Reject('parse');
  const xin = le(f.x_in), yout = le(f.y_out);
  if (xin >= P || yout >= P) throw new Reject('statement');
  if (want && (want[0] !== xin || want[1] !== yout)) throw new Reject('statement');
  let t = sha(tag(p), f.x_in, f.y_out);
  t = sha(t, f.root_trace);
  const alpha = [1, 2, 3, 4].map((j) => E.fromDigest(sha(t, Buffer.from('a'), u8(j))));
  t = sha(t, f.root_comp);
  const z = E.fromDigest(sha(t, Buffer.from('z')));
  if (z.slice(1).every((c) => c === 0n)) throw new Reject('z-in-base-field');
  const [Xz, Yz, Xwz, H0z, H1z] = [0, 1, 2, 3, 4].map((i) => E.dec(f.ood, i * e8));
  t = sha(t, f.ood);
  const gamma = [1, 2, 3, 4, 5].map((j) => E.fromDigest(sha(t, Buffer.from('g'), u8(j))));
  const beta = [E.fromDigest(sha(t, Buffer.from('b')))];
  for (let i = 1; i < p.r; i++) { t = sha(t, f[`root_fri${i}`]); beta.push(E.fromDigest(sha(t, Buffer.from('b')))); }
  const fin = Array.from({ length: p.D }, (_, k) => E.dec(f.final, k * e8));
  t = sha(t, f.final);
  const G = sha(t, f.nonce);
  // AIR at z
  const n = BigInt(p.n), wn = rou(p.n), wlast = powp(wn, n - 1n);
  const zn = E.pow(z, n), zm = E.sub(z, E.lift(wlast)), z1 = E.sub(z, E.one), zn1 = E.sub(zn, E.one);
  const Pc = periodicPoly(roundConstants());
  const zp = E.pow(z, n / 8n);
  let cz = E.zero; for (let k = 7; k >= 0; k--) cz = E.add(E.mul(cz, zp), E.lift(Pc[k]));
  const s = E.add(Xz, cz);
  const C1 = E.sub(Yz, E.mul(E.mul(s, s), s)), C2 = E.sub(Xwz, E.mul(E.mul(Yz, Yz), s));
  const lhs = E.mul(E.mul(E.mul(E.add(H0z, E.mul(zn, H1z)), zn1), z1), zm);
  let rhs = E.mul(E.mul(E.add(E.mul(alpha[0], C1), E.mul(alpha[1], C2)), E.mul(zm, zm)), z1);
  rhs = E.add(rhs, E.mul(E.mul(E.mul(alpha[2], E.sub(Xz, E.lift(xin))), zn1), zm));
  rhs = E.add(rhs, E.mul(E.mul(E.mul(alpha[3], E.sub(Xz, E.lift(yout))), zn1), z1));
  if (!E.eq(lhs, rhs)) throw new Reject('air');
  const g = p.grinding_bits;
  for (let b = 0; b < g; b++) if ((G[b >> 3] >> (7 - (b & 7))) & 1) throw new Reject('grinding');
  const idx = Array.from({ length: p.queries }, (_, q) => Number(le(sha(G, u16(q))) % BigInt(p.sizes[1])));
  // leaves
  const leaves = [];
  for (let q = 0; q < p.queries; q++) { const row = []; for (const tr of trees) { row.push(proof.subarray(o, o + tr.leaf_bytes)); o += tr.leaf_bytes; } leaves.push(row); }
  const pos = idx.map((v) => { const a = [v]; for (let i = 0; i < p.r; i++) a.push(a[i] % p.sizes[i + 1]); return a; });
  const roots = [f.root_trace, f.root_comp, ...Array.from({ length: p.r - 1 }, (_, i) => f[`root_fri${i + 1}`])];
  const node = (a, b) => sha(a, b).subarray(0, h);
  trees.forEach((tr, ti) => {
    const layer = ti < 2 ? 0 : ti - 1;
    let cur = new Map();
    for (let q = 0; q < p.queries; q++) {
      const k = pos[q][layer + 1], lh = sha(u8(tr.tag), leaves[q][ti]).subarray(0, h);
      if (cur.has(k) && !cur.get(k).equals(lh)) throw new Reject('merkle');
      cur.set(k, lh);
    }
    for (let l = 0; l < tr.depth; l++) {
      const keys = [...cur.keys()].sort((a, b) => a - b), nxt = new Map();
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (k % 2 === 0 && keys[i + 1] === k + 1) { nxt.set(k >> 1, node(cur.get(k), cur.get(k + 1))); i++; continue; }
        if (o + h > proof.length) throw new Reject('parse');
        const sib = proof.subarray(o, o + h); o += h;
        nxt.set(k >> 1, k % 2 === 0 ? node(cur.get(k), sib) : node(sib, cur.get(k)));
      }
      cur = nxt;
    }
    if (!cur.get(0).equals(roots[ti])) throw new Reject('merkle');
  });
  if (o !== proof.length) throw new Reject('parse');
  // queries
  const shift = [7n]; for (const a of p.fold) shift.push(powp(shift[shift.length - 1], BigInt(a)));
  const wN = p.sizes.map((sz) => rou(sz));
  const wz = E.mul(E.lift(wn), z);
  const K = E.add(E.add(E.mul(gamma[0], Xz), E.mul(gamma[1], Yz)), E.add(E.mul(gamma[3], H0z), E.mul(gamma[4], H1z)));
  const gXwz = E.mul(gamma[2], Xwz);
  const fold = (vals, b, x0, a) => {
    const wai = invp(rou(a));
    const V = Array.from({ length: a }, (_, tt) => vals.reduce((acc, v, j) => E.add(acc, E.smul(v, powp(wai, BigInt(j * tt)))), E.zero));
    const y = E.smul(b, invp(x0));
    let acc = E.zero; for (let tt = a - 1; tt >= 0; tt--) acc = E.add(E.mul(acc, y), V[tt]);
    return E.smul(acc, invp(BigInt(a)));
  };
  for (let q = 0; q < p.queries; q++) {
    const a0 = p.fold[0], tl = leaves[q][0], cl = leaves[q][1];
    let x0 = shift[0] * powp(wN[0], BigInt(pos[q][1])) % P;
    const wa = rou(a0), vals = [];
    for (let j = 0; j < a0; j++) {
      const x = x0 * powp(wa, BigInt(j)) % P;
      const Xx = mod(le(tl.subarray(16 * j, 16 * j + 8))), Yx = mod(le(tl.subarray(16 * j + 8, 16 * j + 16)));
      const H0x = E.dec(cl, 2 * e8 * j), H1x = E.dec(cl, 2 * e8 * j + e8);
      let num = E.add(E.add(E.smul(gamma[0], Xx), E.smul(gamma[1], Yx)), E.add(E.mul(gamma[3], H0x), E.mul(gamma[4], H1x)));
      num = E.sub(num, K);
      vals.push(E.add(E.mul(num, E.inv(E.sub(E.lift(x), z))), E.mul(E.sub(E.smul(gamma[2], Xx), gXwz), E.inv(E.sub(E.lift(x), wz)))));
    }
    let cur = fold(vals, beta[0], x0, a0);
    for (let i = 1; i < p.r; i++) {
      const a = p.fold[i], leaf = leaves[q][i + 1], slot = Math.floor(pos[q][i] / p.sizes[i + 1]);
      if (!E.eq(E.dec(leaf, slot * e8), cur)) throw new Reject('fri: layer');
      x0 = shift[i] * powp(wN[i], BigInt(pos[q][i + 1])) % P;
      cur = fold(Array.from({ length: a }, (_, j) => E.dec(leaf, j * e8)), beta[i], x0, a);
    }
    const y = shift[p.r] * powp(wN[p.r], BigInt(pos[q][p.r])) % P;
    let ev = E.zero; for (let k = p.D - 1; k >= 0; k--) ev = E.add(E.smul(ev, y), fin[k]);
    if (!E.eq(ev, cur)) throw new Reject('fri: final');
  }
  return { G: G.toString('hex'), indices: idx };
}

function applyTamper(proof, tc) {
  if (tc.proof_hex) return Buffer.from(tc.proof_hex, 'hex');
  let b = Buffer.from(proof);
  for (const pa of tc.patches ?? []) {
    if (pa.xor) Buffer.from(pa.xor, 'hex').forEach((x, i) => { b[pa.offset + i] ^= x; });
    else Buffer.from(pa.bytes, 'hex').copy(b, pa.offset);
  }
  if (tc.truncate !== undefined) b = b.subarray(0, tc.truncate);
  if (tc.append) b = Buffer.concat([b, Buffer.from(tc.append, 'hex')]);
  return b;
}

const run = (fn) => { try { return [true, fn()]; } catch (err) { if (err instanceof Reject) return [false, err.message]; throw err; } };

if (import.meta.url === `file://${process.argv[1]}`) {
  let bad = 0;
  for (const path of process.argv.slice(2)) {
    const v = JSON.parse(readFileSync(path, 'utf8'));
    const proof = Buffer.from(v.proof, 'hex');
    const st = [BigInt(v.statement.x_in), BigInt(v.statement.y_out)];
    const [ok, res] = run(() => verify(v.params, proof, st));
    const same = ok && res.G === v.derived.G && res.indices.every((x, i) => x === v.derived.indices[i]);
    console.log(`${path}: ${ok ? 'ACCEPT' : 'REJECT ' + res}${ok ? (same ? ' (G and indices match Python)' : ' (MISMATCH with Python derived values)') : ''}`);
    bad += !(ok && same);
    for (const tc of v.tampered ?? []) {
      const want = tc.want_statement ? tc.want_statement.map(BigInt) : null;
      const [ok2, why] = run(() => verify(v.params, applyTamper(proof, tc), want));
      const coarse = tc.expect_reason_prefix.split(/[: ]/)[0];
      const good = !ok2 && why.startsWith(coarse === 'fri' ? tc.expect_reason_prefix.slice(0, 9) : coarse);
      console.log(`   tamper ${tc.name.padEnd(28)} ${ok2 ? 'ACCEPT' : 'REJECT'}: ${ok2 ? '' : why} [${good ? 'ok' : 'UNEXPECTED'}]`);
      bad += !good;
    }
  }
  console.log(bad ? `${bad} unexpected results` : 'all as expected');
  process.exit(bad ? 1 : 0);
}
