// Track 8 S7: reference model and witness encoder of layout a' (today's standard rules, DESIGN-T8 §5 a'), M1 with
// Merkle cap 5 (one table, one height). The on-chain algorithm is the S5 one (modeln.mjs) with two differences:
// - Merkle: every query carries its full path below the cap (depth - capH siblings per tree; no multiproof sharing),
//   and the node reached at the cap layer must equal the cap entry (k - 2^capH) of the committed cap.
// - Published constants: inputs exchange values only through their own (checked) pushes, read by the others with
//   OP_INPUTBYTECODE:
//     ACC_j  (CODE input j)  the partial constraint accumulator of constraint range j (24 B), checked by CODE j;
//                            HEAD combines them: sum_j ACC_j alpha^(C - hi_j) = q(zeta) Z_H(zeta) Dd^maxScale
//     TBL    (FIN input)     query indices, alpha', beta_r, the DEEP point constants and the A sums, checked by FIN;
//                            the QRY inputs use it instead of re-deriving the transcript and the constants
import {vkxN, lenientParseN, transcriptN, proofConstsN, hintsN, queryBlob, runQueryN, P, Reject, le8, sha, leNum, md, inv} from './modeln.mjs';
import {canonicalTree, normAdj} from '../../pq-stark/verifier/model.mjs';

export {P, Reject, le8, sha};
const D = 3, H32 = 32, E8 = 24;

// extended verifying key for layout a' (M1 shape: one instance, one height, ZK, no lookups / preprocessed columns)
export function vkxA(v) {
  const vk = vkxN(v, {stmt: 'pool', allowCap: true});
  if (vk.inst.length !== 1 || vk.heights.length !== 1 || vk.hasLookups || vk.hasPre || !vk.zk) throw new Error("layout a': M1 shape only (one table, one height, ZK)");
  if (vk.trees.some((t) => t.B !== 0)) throw new Error("layout a': no injection");
  if (vk.stmt !== 'pool' || vk.nPub !== 12) throw new Error("layout a': the M1 statement (12 public values: ROOT, NF, CTX)");
  vk.pathB = vk.trees.reduce((s, t) => s + (t.depth - t.capH) * H32, 0);
  vk.idxB = Math.ceil((vk.logH + 1) / 8);
  vk.tblLayout = tblLayout(vk);
  vk.tblB = vk.tblLayout.reduce((s, [, n, w]) => s + n * w, 0);
  vk.C = vk.inst[0].dag.constraints.length;
  return vk;
}

// TBL: [name, count, width] in order; numbers are u64 LE (width 8) or idx (width idxB, LE)
export function tblLayout(vk) {
  const L = [['idx', vk.Q, vk.idxB], ['ap', D, 8]];
  vk.logArities.forEach((_, r) => L.push([`be${r}_`, D, 8]));
  vk.points.forEach((_, pi) => L.push([`nt${pi}`, 1, 8], [`nc${pi}`, 1, 8], [`nd${pi}`, 1, 8], [`nB${pi}_`, D, 8], [`nC${pi}_`, D, 8]));
  for (const hh of vk.heights) vk.hp[hh].forEach((_, p) => L.push([`nA${hh}_${p}_`, D, 8]));
  return L;
}
const uLE = (x, w) => { const b = Buffer.alloc(w); let v = BigInt(x); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
export function tblBytes(vk, t, c) {
  const val = {idx: t.idx.map(BigInt), ap: t.alphaP};
  vk.logArities.forEach((_, r) => { val[`be${r}_`] = t.betas[r]; });
  vk.points.forEach((_, pi) => {
    const na = c.na[pi];
    Object.assign(val, {[`nt${pi}`]: [na.t], [`nc${pi}`]: [na.c], [`nd${pi}`]: [na.d], [`nB${pi}_`]: na.B, [`nC${pi}_`]: na.C});
  });
  for (const hh of vk.heights) vk.hp[hh].forEach((_, p) => { val[`nA${hh}_${p}_`] = c.A[hh][p]; });
  return Buffer.concat(vk.tblLayout.flatMap(([nm, n, w]) => { if (val[nm].length !== n) throw new Error('tbl ' + nm); return val[nm].map((x) => uLE(md(BigInt(x)), w)); }));
}

// constraint ranges [lo, hi) of the CODE inputs (balanced by DAG node count reachable from each range's constraints)
export function partsOf(vk, n) {
  const I = vk.inst[0], C = I.dag.constraints.length;
  if (n === 1) return [[0, C]];
  const cost = I.dag.constraints.map((cn) => { const seen = new Set(); const st = [cn.node]; while (st.length) { const k = st.pop(); if (seen.has(k)) continue; seen.add(k); const nd = I.dag.nodes[k]; if (nd.a !== undefined) st.push(nd.a); if (nd.b !== undefined) st.push(nd.b); } return seen.size; });
  const tot = cost.reduce((a, b) => a + b, 0), parts = []; let lo = 0, acc = 0;
  for (let i = 0; i < C && parts.length < n - 1; i++) { acc += cost[i]; if (acc >= tot * (parts.length + 1) / n) { parts.push([lo, i + 1]); lo = i + 1; } }
  parts.push([lo, C]);
  return parts;
}

// the AIR at zeta split into constraint ranges: acc_j = sum_{i in [lo, hi)} up(c_i) alpha^(hi - 1 - i) (as the script's
// multiplied-through DAG); the whole: sum_j acc_j alpha^(C - hi_j) = q zh Dd^maxScale
export function airPartsN(vk, pr, c, t, pis, parts) {
  const F = vk.F, I = vk.inst[0];
  const zN = F.pow(c.zeta, I.n), zh = F.sub(zN, F.one());
  const D1 = F.sub(c.zeta, F.one()), D2 = F.sub(c.zeta, F.lift(inv(I.gN))), Dd = F.mul(D1, D2);
  const selW = {is_first_row: F.mul(zh, D2), is_last_row: F.mul(zh, D1), is_transition: F.mul(Dd, D2)};
  const valAt = (k) => Array.from({length: D}, (_, j) => leNum(pr.OOD.subarray(k * E8 + 8 * j, k * E8 + 8 * j + 8)));
  const per = I.periodic.map(({lm, coef}) => {
    const y = F.pow(c.zeta, 1n << BigInt(I.logN - lm));
    let acc = F.zero(); for (let k = coef.length - 1; k >= 0; k--) acc = F.add(F.mul(acc, y), F.lift(coef[k]));
    return acc;
  });
  const s = I.scale, val = [];
  const up = (x, k) => { for (let j = 0; j < k; j++) x = F.mul(x, Dd); return x; };
  I.dag.nodes.forEach((nd, k) => {
    switch (nd.op) {
      case 'main': val[k] = valAt((nd.row === 0 ? I.ov.tl : I.ov.tn) + nd.col); break;
      case 'periodic': val[k] = per[nd.col]; break;
      case 'public': val[k] = F.lift(pis[I.pubOff + nd.col]); break;
      case 'const': val[k] = F.lift(BigInt(nd.v)); break;
      case 'is_first_row': case 'is_last_row': case 'is_transition': val[k] = selW[nd.op]; break;
      case 'add': val[k] = F.add(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
      case 'sub': val[k] = F.sub(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
      case 'mul': val[k] = F.mul(val[nd.a], val[nd.b]); break;
      case 'neg': val[k] = F.neg(val[nd.a]); break;
      default: throw new Error('airPartsN: DAG op ' + nd.op);
    }
  });
  return parts.map(([lo, hi]) => {
    let acc = F.zero();
    for (let i = lo; i < hi; i++) { const cn = I.dag.constraints[i]; acc = F.add(F.mul(acc, t.alpha), up(val[cn.node], I.maxScale - s[cn.node])); }
    return acc;
  });
}

// full paths below the cap, from the proof's pruned multiproofs (Plonky3 order; missing siblings read as zero)
function pathMaps(vk, pr, idx, dig) {
  return vk.trees.map((tr, ti) => {
    const levels = tr.depth - tr.capH;
    let leaves, sibs;
    if (tr.kind === 'in') {
      const r = vk.rounds[tr.b];
      const rowsOf = (q) => Buffer.concat(r.matrices.map((_, mi) => Buffer.concat([pr.inputs[tr.b].rows[q][mi], pr.inputs[tr.b].salts[q][mi]])));
      leaves = idx.map((i, q) => [i >>> tr.shift, sha(rowsOf(q))]);
      sibs = pr.inputs[tr.b].sibs;
    } else {
      leaves = idx.map((i, q) => [i >>> tr.shift, dig[q]?.[ti] ?? Buffer.alloc(H32)]);
      sibs = pr.fri[tr.r].sibs;
    }
    const can = canonicalTree(H32, levels, leaves, sibs);
    return {map: can.map, levels, leftover: can.leftover};
  });
}

// witness of layout a' for one proof (lenient: a malformed proof still yields items; the script rejects them)
export function encodeA(vk, buf, pis, parts) {
  const pr = lenientParseN(buf, vk);
  const out = {pr, malformed: pr.short ? 'truncated' : pr.trailing.length ? 'trailing bytes' : null};
  let t = null;
  try { t = transcriptN(vk, pr, pis); } catch (e) { if (!(e instanceof Reject)) throw e; out.reject = e.message; }
  out.t = t;
  const c = t ? proofConstsN(vk, pr, t) : null; out.c = c;
  const idx = t ? t.idx : Array(vk.Q).fill(0);
  out.idx = idx;
  out.T = idx.map((i) => (c ? hintsN(vk, c, i) : vk.heights.map(() => 0n)));
  const bottom = vk.trees.filter((tr) => tr.kind === 'in').map(() => []);
  out.L = idx.map((_, q) => queryBlob(vk, pr, q, bottom, out.T[q]));
  const dig = idx.map(() => null);
  if (t) for (let q = 0; q < vk.Q; q++) {
    try { dig[q] = runQueryN(vk, pr, t, c, q, out.T[q], bottom).digests; } catch (e) { if (!(e instanceof Reject)) throw e; out.reject ??= e.message; }
  }
  out.dig = dig;
  const maps = pathMaps(vk, pr, idx, dig);
  // leftover multiproof siblings / trailing bytes: the full paths never contain them, so the script sees the valid
  // proof inside; a production encoder refuses such a byte string (counted as an encoder-only rejection)
  out.leftover = maps.reduce((s, m) => s + m.leftover.length, 0);
  if (out.leftover && !out.malformed) out.malformed = 'leftover multiproof siblings';
  out.PTH = idx.map((i) => Buffer.concat(vk.trees.flatMap((tr, ti) => {
    const leaf = i >>> tr.shift;
    return Array.from({length: maps[ti].levels}, (_, l) => maps[ti].map.get(`${l}:${(leaf >>> l) ^ 1}`) ?? Buffer.alloc(H32));
  })));
  out.PT = Object.fromEntries(vk.ptItems.map(([k]) => [k, pr[k]]));
  out.TBL = t ? tblBytes(vk, t, c) : Buffer.alloc(vk.tblB);
  out.ACC = t && parts ? airPartsN(vk, pr, c, t, pis, parts).map((a) => Buffer.concat(a.map(le8))) : (parts ?? []).map(() => Buffer.alloc(E8));
  out.G = t ? t.G : Buffer.alloc(32);
  return out;
}

// model verdict of layout a' (every check the inputs make): transcript, AIR (combined parts), queries, full paths
export function verifyModelA(vk, buf, pis, parts) {
  if (pis.length !== vk.nPub) return {ok: false, reason: 'public value count'};
  if (pis.some((x) => x < 0n || x >= P)) return {ok: false, reason: 'non-canonical public value'};
  const enc = encodeA(vk, buf, pis, parts);
  try {
    if (enc.pr.short) throw new Reject('truncated proof');
    if (enc.reject) throw new Reject(enc.reject);
    const F = vk.F, I = vk.inst[0], {t, c, pr} = enc;
    const zN = F.pow(c.zeta, I.n), zh = F.sub(zN, F.one());
    if (F.isZero(zh) || F.isZero(F.add(zN, F.one()))) throw new Reject('zeta in trace domain');
    const accs = airPartsN(vk, pr, c, t, pis, parts);
    let lhs = F.zero(); parts.forEach(([, hi], j) => { lhs = F.add(lhs, F.mul(accs[j], F.pow(t.alpha, BigInt(I.dag.constraints.length - hi)))); });
    let q = F.zero();
    const recomp = (vals) => vals.reduce((acc, v, k) => F.add(acc, F.mul(v, F.basis(k))), F.zero());
    const valAt = (k) => Array.from({length: D}, (_, j) => leNum(pr.OOD.subarray(k * E8 + 8 * j, k * E8 + 8 * j + 8)));
    for (let k = 0; k < I.C; k++) {
      let zp = F.lift(I.zpConst[k]);
      for (let j = 0; j < I.C; j++) if (j !== k) zp = F.mul(zp, F.sub(F.smul(zN, I.kc[j]), F.one()));
      q = F.add(q, F.mul(zp, recomp([0, 1, 2].map((m) => valAt(I.ov.ch[k] + m)))));
    }
    const D1 = F.sub(c.zeta, F.one()), D2 = F.sub(c.zeta, F.lift(inv(I.gN))), Dd = F.mul(D1, D2);
    let rhs = F.mul(q, zh); for (let k = 0; k < I.maxScale; k++) rhs = F.mul(rhs, Dd);
    if (!F.eq(lhs, rhs)) throw new Reject('OOD constraint mismatch');
    // full paths: climb from the leaf digest to the cap layer and compare with the cap entry
    const caps = vk.trees.map((tr) => (tr.kind === 'fri' ? pr.FROOTS.subarray(vk.friOff[tr.r], vk.friOff[tr.r] + vk.friB[tr.r]) : pr.ROOTS.subarray(vk.capOff[tr.name], vk.capOff[tr.name] + vk.capB[tr.name])));
    for (let qq = 0; qq < vk.Q; qq++) {
      if (!enc.dig[qq]) throw new Reject('query ' + qq);
      let o = 0;
      vk.trees.forEach((tr, ti) => {
        let k = (1 << tr.depth) + (t.idx[qq] >>> tr.shift), cur = enc.dig[qq][ti];
        if (tr.kind === 'in') {
          const r = vk.rounds[tr.b];
          cur = sha(Buffer.concat(r.matrices.map((_, mi) => Buffer.concat([pr.inputs[tr.b].rows[qq][mi], pr.inputs[tr.b].salts[qq][mi]]))));
        }
        for (let l = 0; l < tr.depth - tr.capH; l++) { const s = enc.PTH[qq].subarray(o, o + H32); o += H32; cur = k & 1 ? sha(s, cur) : sha(cur, s); k >>>= 1; }
        const ci = k - (1 << tr.capH);
        if (!cur.equals(caps[ti].subarray(ci * H32, ci * H32 + H32))) throw new Reject(`query ${qq} tree ${ti}: cap mismatch`);
      });
    }
    return {ok: true, enc};
  } catch (e) { if (!(e instanceof Reject)) throw e; return {ok: false, reason: e.message, enc}; }
}
export {normAdj};
