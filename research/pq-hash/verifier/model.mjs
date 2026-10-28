// Reference model of the on-chain verifier and the prover-side encoder of its unlocking data.
//
// encodeB(prm, proofBytes) turns a canonical proof (SERIALIZATION.md section 4) into the layout (b) witness:
//   - PT items (statement, roots, OOD, final polynomial, nonce) as separate pushes;
//   - per query q a leaf blob L_q = trace ‖ comp ‖ fri1 ‖ ... ‖ T_q (8 B), where T_q is the inverse of the product of
//     the query's DEEP norms and x0 (a hint; the script checks prod * T == 1);
//   - per tree, one record blob per query in sorted leaf order: R = sigma (1 B) ‖ program, where sigma is the query
//     number and the program is a sequence of Merkle ops (fresh runs carry their siblings inline).
// The Merkle hints (sigma order, op stream) are derived from the proof's own multiproof, so a tampered proof is encoded
// the same way an honest prover would encode it; the script then decides.
//
// verifyModel(prm, proofBytes, statement) mirrors the script's checks (same order of phases) and returns
// {ok, reason, derived}. It is an independent reimplementation of the verifier semantics (cross-checked against the
// vectors' derived values and verdicts in test-model.mjs).
import {P, md, powp, invp, rou, sha, leNum, le8, u16, cat, Ext} from './field.mjs';

export const OPS = {F1: 1, F2: 2, F4: 3, F8: 4, F16: 5, MERGE: 6, DUPM: 7, PARK: 8, ROOT: 9};
export const FRESH_RUNS = [[16, OPS.F16], [8, OPS.F8], [4, OPS.F4], [2, OPS.F2], [1, OPS.F1]];

export class Reject extends Error {}

export function parsePT(prm, proof) {
  const {e, h, r, D} = prm, e8 = 8 * e;
  let o = 0; const f = {};
  const take = (name, len) => { f[name] = proof.subarray(o, o + len); o += len; };
  take('st', 16); take('rT', h); take('rC', h); take('ood', 5 * e8);
  for (let i = 1; i < r; i++) take('rF' + i, h);
  take('fin', D * e8); take('nonce', 8);
  f.end = o;
  return f;
}

export function transcript(prm, f) {
  const F = prm.F, r = prm.r;
  const E = (d) => F.fromDigest(d);
  const ts = {};
  let t = sha(prm.TAG, f.st); ts.t0 = t;
  t = sha(t, f.rT); ts.t1 = t;
  const alpha = [1, 2, 3, 4].map((j) => E(sha(t, Uint8Array.of(0x61, j))));
  t = sha(t, f.rC); ts.t2 = t;
  const z = E(sha(t, Uint8Array.of(0x7a)));
  t = sha(t, f.ood); ts.t3 = t;
  const gamma = [1, 2, 3, 4, 5].map((j) => E(sha(t, Uint8Array.of(0x67, j))));
  const beta = [E(sha(t, Uint8Array.of(0x62)))];
  for (let i = 1; i < r; i++) { t = sha(t, f['rF' + i]); beta.push(E(sha(t, Uint8Array.of(0x62)))); }
  t = sha(t, f.fin);
  const G = sha(t, f.nonce);
  const idx = Array.from({length: prm.s}, (_, q) => Number(leNum(sha(G, u16(q)).subarray(0, 4)) % BigInt(prm.sizes[1])));
  return {alpha, z, gamma, beta, G, idx, ts};
}

export const grindingOk = (G, g) => { for (let b = 0; b < g; b++) if ((G[b >> 3] >> (7 - (b & 7))) & 1) return false; return true; };

export function airCheck(prm, f, tr, xin, yout) {
  const F = prm.F, e = prm.e, e8 = 8 * e;
  const [Xz, Yz, Xwz, H0z, H1z] = [0, 1, 2, 3, 4].map((i) => F.red(F.dec(f.ood, i * e8)));
  const z = tr.z, n = BigInt(prm.n), wl = powp(prm.wn, n - 1n);
  const zn = F.pow(z, n), zp = F.pow(z, n / 8n);
  let cz = F.zero; for (let k = 7; k >= 0; k--) cz = F.add(F.mul(cz, zp), F.lift(prm.Pc[k]));
  const s = F.add(Xz, cz);
  const C1 = F.sub(Yz, F.mul(F.mul(s, s), s)), C2 = F.sub(Xwz, F.mul(F.mul(Yz, Yz), s));
  const zm = F.sub(z, F.lift(wl)), z1 = F.sub(z, F.one), zn1 = F.sub(zn, F.one);
  const lhs = F.mul(F.mul(F.mul(F.add(H0z, F.mul(zn, H1z)), zn1), z1), zm);
  let rhs = F.mul(F.mul(F.add(F.mul(tr.alpha[0], C1), F.mul(tr.alpha[1], C2)), F.mul(zm, zm)), z1);
  rhs = F.add(rhs, F.mul(F.mul(F.mul(tr.alpha[2], F.sub(Xz, F.lift(xin))), zn1), zm));
  rhs = F.add(rhs, F.mul(F.mul(F.mul(tr.alpha[3], F.sub(Xz, F.lift(yout))), zn1), z1));
  return {ok: F.eq(lhs, rhs), Xz, Yz, Xwz, H0z, H1z};
}

// positions of query idx: pos[0] = idx (coset index in L_1) ... ; leaf index of tree for layer i = pos[i+1]
export function positions(prm, idx) {
  const pos = [idx]; for (let i = 0; i < prm.r; i++) pos.push(pos[i] % prm.sizes[i + 1]);
  return pos;
}

// ---- Merkle: canonical multiproof -> node map, then sorted LIFO op programs ----
const node = (h) => (a, b) => sha(a, b).subarray(0, h);
// run the canonical multiproof of SERIALIZATION.md 4.3 for one tree; returns {map, root, used, ok}
export function canonicalTree(prm, tree, leafHashes, sibBytes, o0) {
  const h = prm.h, H = node(h), d = tree.depth;
  const map = new Map(); // `${level}:${index}` -> digest
  let o = o0, ok = true;
  let cur = new Map();
  for (const [k, lh] of leafHashes) {
    if (cur.has(k) && Buffer.compare(Buffer.from(cur.get(k)), Buffer.from(lh)) !== 0) ok = false;
    cur.set(k, lh); map.set(`0:${k}`, lh);
  }
  for (let l = 0; l < d; l++) {
    const keys = [...cur.keys()].sort((x, y) => x - y), nxt = new Map();
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (k % 2 === 0 && keys[i + 1] === k + 1) { nxt.set(k >> 1, H(cur.get(k), cur.get(k + 1))); i++; continue; }
      let sib = sibBytes.subarray(o, o + h); o += h;
      if (sib.length < h) { ok = false; sib = cat(sib, new Uint8Array(h - sib.length)); }
      map.set(`${l}:${k ^ 1}`, sib);
      nxt.set(k >> 1, k % 2 === 0 ? H(cur.get(k), sib) : H(sib, cur.get(k)));
    }
    for (const [k, v] of nxt) map.set(`${l + 1}:${k}`, v);
    cur = nxt;
  }
  return {map, root: cur.get(0), end: o, ok};
}

// sorted LIFO program for one tree. recs: [{q, leaf, digest}] ; returns {order, programs[], siblings}
export function lifoPrograms(prm, tree, recs, map) {
  const h = prm.h, H = node(h), d = tree.depth;
  const sorted = [...recs].sort((x, y) => x.leaf - y.leaf || x.q - y.q);
  const parked = [];
  const programs = [];
  let siblings = 0;
  for (let i = 0; i < sorted.length; i++) {
    const rc = sorted[i], next = sorted[i + 1];
    let k = (1 << d) + rc.leaf, cur = rc.digest, level = 0;
    const prog = [Uint8Array.of(rc.q)];
    let run = [];
    const flush = () => {
      let m = run.length, at = 0;
      for (const [len, id] of FRESH_RUNS) while (m >= len) { prog.push(Uint8Array.of(id), ...run.slice(at, at + len)); at += len; m -= len; }
      run = [];
    };
    if (i > 0 && sorted[i - 1].leaf === rc.leaf) {
      flush(); prog.push(Uint8Array.of(OPS.DUPM));
      const [pk, pd] = parked.pop(); if (pk !== k) throw new Error('dup park mismatch'); void pd;
    }
    for (;;) {
      const nk = next ? ((1 << d) + next.leaf) >> level : -1;
      const top = parked[parked.length - 1];
      if (k === 1) { flush(); prog.push(Uint8Array.of(OPS.ROOT)); break; }
      if (next && (nk === k || nk === (k ^ 1))) { flush(); prog.push(Uint8Array.of(OPS.PARK)); parked.push([k, cur]); break; }
      if (top && top[0] === (k ^ 1)) {
        flush(); prog.push(Uint8Array.of(OPS.MERGE)); parked.pop();
        cur = k & 1 ? H(top[1], cur) : H(cur, top[1]);
      } else {
        const sib = map.get(`${level}:${(k ^ 1) - (1 << (d - level))}`) ?? new Uint8Array(h);
        run.push(sib); siblings++;
        cur = k & 1 ? H(sib, cur) : H(cur, sib);
      }
      k >>= 1; level++;
    }
    programs.push({q: rc.q, bytes: cat(...prog)});
  }
  if (parked.length) throw new Error('parked items left');
  return {order: sorted.map((x) => x.q), programs, siblings};
}

// DEEP/fold constants that depend on z (per proof), used by both the model and the script generator
export function deepConsts(prm, z) {
  const e = prm.e, wn = prm.wn;
  const zs = [z, z.map((c) => md(c * wn))]; // z and w_n z
  return zs.map((zz) => {
    if (e === 3) {
      const [z0, z1, z2] = zz;
      return {z0, z1, z2, K0: md(-7n * z1 * z2), K1: md(7n * z2 * z2), K2: md(z1 * z1),
        cA: md(-21n * z1 * z2), cB: md(-(49n * z2 * z2 % P * z2 + 7n * z1 * z1 % P * z1))};
    }
    const [z0, z1] = zz;
    return {z0, z1, cN: md(-7n * z1 * z1)};
  });
}
// norm and adjugate of (x - zz) for x in F_p, as the script computes them
export function normAdj(prm, x, dc) {
  const w = md(x - dc.z0);
  if (prm.e === 3) {
    const w2 = w * w;
    return {N: md(w * md(w2 + dc.cA) + dc.cB), adj: [md(w2 + dc.K0), md(w * dc.z1 + dc.K1), md(w * dc.z2 + dc.K2)]};
  }
  return {N: md(w * w + dc.cN), adj: [w, dc.z1]};
}

export function queryPoints(prm, idx) {
  const pos = positions(prm, idx), a = prm.a;
  const x0 = md(prm.shift[0] * powp(prm.wN[0], pos[1]));
  return {pos, x0};
}

// ---- full model ----
export function verifyModel(prm, proof, statement, opts = {}) {
  const F = prm.F, e = prm.e, e8 = 8 * e, h = prm.h, s = prm.s, r = prm.r, a = prm.a;
  const out = {derived: {}};
  try {
    const f = parsePT(prm, proof);
    if (proof.length < f.end + s * prm.leafBytes) throw new Reject('parse: proof shorter than PT + leaves');
    const xin = leNum(f.st.subarray(0, 8)), yout = leNum(f.st.subarray(8, 16));
    if (statement && (statement[0] !== xin || statement[1] !== yout)) throw new Reject('statement: proof is for a different statement');
    if (xin >= P || yout >= P) throw new Reject('statement: non-canonical public input');
    const tr = transcript(prm, f); out.derived.tr = tr;
    if (tr.z.slice(1).every((c) => c === 0n)) throw new Reject('z-in-base-field');
    const air = airCheck(prm, f, tr, xin, yout); out.derived.air = air;
    if (!air.ok) throw new Reject('air: composition identity at z fails');
    if (!grindingOk(tr.G, prm.g)) throw new Reject('grinding: proof-of-work check fails');
    // leaves
    let o = f.end;
    const leaves = [];
    for (let q = 0; q < s; q++) { leaves.push(proof.subarray(o, o + prm.leafBytes)); o += prm.leafBytes; }
    const pos = tr.idx.map((v) => positions(prm, v));
    const roots = [f.rT, f.rC, ...Array.from({length: r - 1}, (_, i) => f['rF' + (i + 1)])];
    // Merkle per tree: canonical multiproof (as the prover wrote it), then the LIFO programs the script runs
    const programs = [];
    for (const [ti, tree] of prm.trees.entries()) {
      const recs = tr.idx.map((_, q) => {
        const leaf = pos[q][tree.layer + 1];
        const bytes = leaves[q].subarray(tree.off, tree.off + tree.leaf_bytes);
        return {q, leaf, digest: sha(Uint8Array.of(tree.tag), bytes).subarray(0, h)};
      });
      const can = canonicalTree(prm, tree, recs.map((x) => [x.leaf, x.digest]), proof, o);
      o = can.end;
      const lp = lifoPrograms(prm, tree, recs, can.map);
      programs.push(lp);
      // the script's verdict: every record's leaf must agree for equal positions, and the LIFO root must match
      for (let i = 1; i < recs.length; i++) void i;
      const lifoRoot = lifoRun(prm, tree, recs, lp);
      if (!lifoRoot.ok) throw new Reject(`merkle: ${lifoRoot.why} in ${tree.name}`);
      if (Buffer.compare(Buffer.from(lifoRoot.root), Buffer.from(roots[ti])) !== 0) throw new Reject(`merkle: root mismatch in ${tree.name}`);
    }
    out.programs = programs;
    if (o !== proof.length) throw new Reject(o > proof.length ? 'parse: proof truncated inside multiproof' : 'parse: trailing bytes after multiproofs');
    // queries
    const dc = deepConsts(prm, tr.z);
    const [Xz, Yz, Xwz, H0z, H1z] = [air.Xz, air.Yz, air.Xwz, air.H0z, air.H1z];
    const C1 = F.add(F.add(F.mul(tr.gamma[0], Xz), F.mul(tr.gamma[1], Yz)), F.add(F.mul(tr.gamma[3], H0z), F.mul(tr.gamma[4], H1z)));
    const C2 = F.mul(tr.gamma[2], Xwz);
    const k0 = a[0], w0 = rou(k0);
    out.T = [];
    for (let q = 0; q < s; q++) {
      const L = leaves[q];
      const {x0} = queryPoints(prm, tr.idx[q]);
      const xs = Array.from({length: k0}, (_, j) => md(x0 * powp(w0, j)));
      const nas = xs.map((x) => [normAdj(prm, x, dc[0]), normAdj(prm, x, dc[1])]);
      const elems = [...nas.flatMap(([u, v]) => [u.N, v.N]), x0];
      const prod = elems.reduce((acc, x) => md(acc * x), 1n);
      const T = invp(prod); out.T.push(T);
      const vals = xs.map((x, j) => {
        const tl = L.subarray(0, 16 * k0), cl = L.subarray(16 * k0, 16 * k0 + 2 * e8 * k0);
        const Xx = leNum(tl.subarray(16 * j, 16 * j + 8)), Yx = leNum(tl.subarray(16 * j + 8, 16 * j + 16));
        const H0x = F.dec(cl, 2 * e8 * j), H1x = F.dec(cl, 2 * e8 * j + e8);
        const n1 = F.sub(F.add(F.add(F.smul(tr.gamma[0], Xx), F.smul(tr.gamma[1], Yx)), F.add(F.mul(tr.gamma[3], F.red(H0x)), F.mul(tr.gamma[4], F.red(H1x)))), C1);
        const m1 = F.sub(F.smul(tr.gamma[2], Xx), C2);
        const inv1 = F.smul(nas[j][0].adj, invp(nas[j][0].N)), inv2 = F.smul(nas[j][1].adj, invp(nas[j][1].N));
        return F.add(F.mul(n1, inv1), F.mul(m1, inv2));
      });
      let cur = fold(prm, vals, tr.beta[0], x0, k0);
      let off = 16 * k0 + 2 * e8 * k0;
      let xb = x0;
      for (let i = 1; i < r; i++) {
        const leaf = L.subarray(off, off + a[i] * e8); off += a[i] * e8;
        const slot = Math.floor(pos[q][i] / prm.sizes[i + 1]);
        if (!F.eq(F.red(F.dec(leaf, slot * e8)), cur)) throw new Reject(`fri: layer ${i} value does not match fold of layer ${i - 1} (query ${q})`);
        xb = md(prm.shift[i] * powp(prm.wN[i], pos[q][i + 1]));
        cur = fold(prm, Array.from({length: a[i]}, (_, j) => F.red(F.dec(leaf, j * e8))), tr.beta[i], xb, a[i]);
      }
      const y = md(prm.shift[r] * powp(prm.wN[r], pos[q][r]));
      let ev = F.zero;
      for (let k = prm.D - 1; k >= 0; k--) ev = F.add(F.smul(ev, y), F.red(F.dec(f.fin, k * e8)));
      if (!F.eq(ev, cur)) throw new Reject(`fri: final polynomial does not match last fold (query ${q})`);
    }
    out.ok = true;
  } catch (err) {
    if (!(err instanceof Reject)) throw err;
    out.ok = false; out.reason = err.message;
  }
  return out;
}

export function fold(prm, vals, b, x0, a) {
  const F = prm.F, wai = invp(rou(a));
  const V = Array.from({length: a}, (_, t) => vals.reduce((acc, v, j) => F.add(acc, F.smul(v, powp(wai, j * t))), F.zero));
  const y = F.smul(b, invp(x0));
  let acc = F.zero; for (let t = a - 1; t >= 0; t--) acc = F.add(F.mul(acc, y), V[t]);
  return F.smul(acc, invp(BigInt(a)));
}

// execute the LIFO programs exactly as the script does (independent of how they were produced)
export function lifoRun(prm, tree, recs, lp) {
  const h = prm.h, H = node(h), d = tree.depth;
  const byQ = new Map(recs.map((x) => [x.q, x]));
  const parked = [];
  let acc = 0n, root = null;
  for (const {bytes} of lp.programs) {
    let o = 0;
    const q = bytes[o++];
    acc += 1n << BigInt(q);
    const rc = byQ.get(q); if (!rc) return {ok: false, why: 'bad sigma'};
    let k = (1 << d) + rc.leaf, cur = rc.digest, done = false;
    while (!done) {
      if (o >= bytes.length) return {ok: false, why: 'program ends early'};
      const op = bytes[o++];
      const fresh = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}[op];
      if (fresh) {
        for (let i = 0; i < fresh; i++) {
          const sib = bytes.subarray(o, o + h); o += h;
          if (sib.length < h) return {ok: false, why: 'short sibling'};
          cur = k & 1 ? H(sib, cur) : H(cur, sib); k >>= 1;
        }
      } else if (op === 6) {
        const [pk, pd] = parked.pop() ?? [];
        if (pk === undefined || pk + k !== 4 * (k >> 1) + 1) return {ok: false, why: 'bad merge'};
        cur = k & 1 ? H(pd, cur) : H(cur, pd); k >>= 1;
      } else if (op === 7) {
        const [pk, pd] = parked.pop() ?? [];
        if (pk !== k || Buffer.compare(Buffer.from(pd), Buffer.from(cur)) !== 0) return {ok: false, why: 'duplicate leaf mismatch'};
      } else if (op === 8) { parked.push([k, cur]); done = true; }
      else if (op === 9) { if (k !== 1) return {ok: false, why: 'root at wrong level'}; root = cur; done = true; }
      else return {ok: false, why: 'bad op'};
    }
    if (o !== bytes.length) return {ok: false, why: 'trailing program bytes'};
  }
  if (parked.length) return {ok: false, why: 'parked left'};
  if (acc !== (1n << BigInt(prm.s)) - 1n) return {ok: false, why: 'sigma not a permutation'};
  return {ok: true, root};
}

// ---- layout (b) witness ----
export function encodeB(prm, proof) {
  const m = verifyModel(prm, proof, null, {});
  // the encoding needs the programs and T values even for rejected proofs: recompute what can be computed
  const f = parsePT(prm, proof);
  const tr = transcript(prm, f);
  const s = prm.s, e8 = 8 * prm.e, r = prm.r;
  let o = f.end;
  const leaves = [];
  for (let q = 0; q < s; q++) { const L = proof.subarray(o, o + prm.leafBytes); leaves.push(cat(L, new Uint8Array(prm.leafBytes - L.length))); o += prm.leafBytes; }
  const pos = tr.idx.map((v) => positions(prm, v));
  const programs = [];
  for (const tree of prm.trees) {
    const recs = tr.idx.map((_, q) => ({q, leaf: pos[q][tree.layer + 1], digest: sha(Uint8Array.of(tree.tag), leaves[q].subarray(tree.off, tree.off + tree.leaf_bytes)).subarray(0, prm.h)}));
    const can = canonicalTree(prm, tree, recs.map((x) => [x.leaf, x.digest]), proof, o);
    o = can.end;
    programs.push(lifoPrograms(prm, tree, recs, can.map));
  }
  const dc = deepConsts(prm, tr.z);
  const k0 = prm.a[0], w0 = rou(k0);
  const T = tr.idx.map((idx) => {
    const {x0} = queryPoints(prm, idx);
    const xs = Array.from({length: k0}, (_, j) => md(x0 * powp(w0, j)));
    const prod = xs.reduce((acc, x) => md(acc * normAdj(prm, x, dc[0]).N * normAdj(prm, x, dc[1]).N), 1n) * x0 % P;
    return prod === 0n ? 0n : invp(prod);
  });
  const pt = [f.st, f.rT, f.rC, f.ood, ...Array.from({length: r - 1}, (_, i) => f['rF' + (i + 1)]), f.fin, f.nonce];
  const records = programs.map((p) => p.programs.map((x) => x.bytes));
  // bytes after the last multiproof (a malformed proof) ride at the end of the last record: the script rejects them
  if (o < proof.length) { const lr = records[records.length - 1]; lr[lr.length - 1] = cat(lr[lr.length - 1], proof.subarray(o)); }
  return {
    model: m, tr, pt, leafBlobs: leaves.map((L, q) => cat(L, le8(T[q]))), records,
    siblings: programs.map((p) => p.siblings), trailing: proof.length - o,
  };
}

// ---- layout (a) witness: per query the leaf blob (leaves ‖ T) and the full authentication paths of the four trees ----
// Paths are read from the node map of the proof's own canonical multiproof (so a tampered proof is encoded as an honest
// prover would encode it; missing nodes become zero bytes).
export function encodeA(prm, proof) {
  const enc = encodeB(prm, proof);
  const f = parsePT(prm, proof);
  const tr = enc.tr;
  let o = f.end + prm.s * prm.leafBytes;
  const pos = tr.idx.map((v) => positions(prm, v));
  const paths = tr.idx.map(() => []);
  for (const tree of prm.trees) {
    const leaves = tr.idx.map((_, q) => {
      const L = enc.leafBlobs[q];
      return [pos[q][tree.layer + 1], sha(Uint8Array.of(tree.tag), L.subarray(tree.off, tree.off + tree.leaf_bytes)).subarray(0, prm.h)];
    });
    const can = canonicalTree(prm, tree, leaves, proof, o);
    o = can.end;
    tr.idx.forEach((_, q) => {
      let k = pos[q][tree.layer + 1];
      for (let l = 0; l < tree.depth; l++, k >>= 1) paths[q].push(can.map.get(`${l}:${k ^ 1}`) ?? new Uint8Array(prm.h));
    });
  }
  return {...enc, paths: paths.map((p) => cat(...p))};
}
