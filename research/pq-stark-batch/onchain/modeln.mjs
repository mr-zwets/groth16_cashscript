// Reference model of the generalized CashVM verifier (Track 8 S5/S6) for Plonky3 p3-batch-stark proofs in p3b-v1
// (../prover/FORMAT.md): N tables, several LDE heights (mixed-height Merkle injection, one DEEP alpha' ladder per
// height, FRI roll-ins), preprocessed columns, periodic columns, LogUp (lookup PoW, bus challenges, permutation
// columns, terminals summing to zero), ZK or not, Merkle cap 0. It follows the on-chain algorithm of genn.mjs step
// by step so that model-agree-n.mjs can check it against the independent reference ../verifier/verify-batch.mjs.
// model.mjs (S4, one table and one height) is left as it was.
//
// On-chain structure (differences from S4):
// - Transcript: batch prefix (domain seed, every instance's degree_bits) ‖ main cap ‖ public values ‖ [preprocessed
//   cap, a VK constant]; [lookup PoW, lookup alpha/beta, permutation cap ‖ terminals]; alpha; quotient cap ‖ [random
//   cap]; zeta; PCS seed ‖ opened values; [batch PoW]; alpha'; FRI as in S4.
// - AIR: per instance (its own n, selectors, periodic columns, quotient chunks) the exported constraint DAG; LogUp
//   values (permutation columns recomposed from their base-flattened openings, bus challenges, terminals) are DAG
//   leaves. The terminals must sum to zero.
// - Opening points: zeta and zeta * g_i for every distinct trace height n_i opened at the next row. Per LDE height h
//   the DEEP quotient uses only that height's claims, its own alpha' ladder and x_h = 7 xo^(2^(logH - h)).
//   One inverse hint per height per query: T_top = 1 / (s0 prod N_pt(x)), T_h = 1 / prod N_pt(x_h).
// - Mixed-height Merkle trees: the bottom B levels (B = the deepest injection level of the round) are walked per
//   query inside the query function (B siblings per query in its blob; node = H(H(l ‖ r) ‖ H(injected rows))). The
//   level-B node is the leaf of the LIFO record tree of depth top - B. Bottom levels essentially never share nodes
//   between queries (24 of 2^20 leaves), so this costs no proof bytes; queries that do share a level-B node must
//   produce the same digest (DUPM), which also enforces consistent injected rows.
// - FRI: after the fold that lands on height h, folded += beta^(arity) * ro_h.
// - Layout b2: the Q queries are split between two inputs; each input authenticates its own queries' paths with its
//   own record programs against the same roots.
import {extField} from '../../pq-stark/prover/verify.mjs';
import {Reject, md, pw, inv, g2, rev, le8, sha, leNum, normAdj, canonicalTree, lifoPrograms, lifoRun, OPS} from '../../pq-stark/verifier/model.mjs';
import {P, vkFromVector, batchSeparator, pcsSeparator, friSeparator, applyTamper} from '../verifier/verify-batch.mjs';

export {P, Reject, md, pw, inv, g2, rev, le8, sha, leNum, OPS, applyTamper};
const D = 3, H32 = 32, E8 = 24;
const seedObs = (b) => { const out = [le8(b.length)]; for (let o = 0; o < b.length; o += 7) out.push(le8(leNum(b.subarray(o, Math.min(o + 7, b.length))))); return Buffer.concat(out); };

// ---------------------------------------------------------------- extended verifying key
// stmt: 'pool' (M1/M2 statement: ROOT a script constant, NF a witness item, CTX from the transaction or a witness item)
//       or 'witness' (every public value is a witness item, each lane < p: the generic harness for the Plonky3 AIRs)
export function vkxN(v, {stmt} = {}) {
  const b = vkFromVector(v);
  if (b.capHeight !== 0) throw new Error('generator: Merkle cap 0 (layouts b and b2)');
  if (b.opow !== 0) throw new Error('generator: ood PoW 0');
  const F = extField(D);
  const nPub = b.inst.reduce((s, I) => s + I.numPublic, 0);
  stmt ??= nPub === 12 && b.inst.some((I) => I.numPublic === 12) && /^m[12]/.test(String(v.case ?? '')) ? 'pool' : 'witness';
  // VK-time checks the per-proof verifier relies on (DESIGN-T8 §2.3, §2.4, §6.5)
  for (const I of b.inst) if (!(I.logLde > b.logFinal)) throw new Error('VK: strict FRI height rule');
  if (b.zk) for (const r of b.rounds) for (const m of r.matrices) if (2 ** b.inst[m.inst].logN < 2 * (D * m.points + b.Q)) throw new Error('VK: hiding budget');
  if (b.hasLookups) {
    const w = b.inst.reduce((s, I) => s + BigInt((I.dag.lookups ?? []).reduce((a, l) => a + Number(l.count_weight ?? 1), 0)) * (1n << BigInt(I.logN)), 0n);
    if (w >= P) throw new Error('VK: multiplicity height bound (sum w h >= p)');
  }
  // instances: AIR constants
  const inst = b.inst.map((I, i) => {
    const C = I.numChunks, logC = Math.log2(C);
    const logQD = I.degreeBits + logC - (b.zk ? 1 : 0), chunkLog = logQD - logC;
    if (chunkLog !== I.logN) throw new Error('chunk size differs from n');
    const gQ = g2(logQD);
    const shifts = Array.from({length: C}, (_, k) => 7n * pw(gQ, k) % P);
    const kc = shifts.map((s) => inv(pw(s, 1n << BigInt(chunkLog))));
    const zpConst = shifts.map((si, k) => shifts.reduce((acc, _, j) => (j === k ? acc : acc * inv(md(pw(si, 1n << BigInt(chunkLog)) * kc[j] - 1n)) % P), 1n));
    const periodic = I.periodic.map((col) => {
      const m = col.length, lm = Math.log2(m), wi = inv(g2(lm)), mi = inv(BigInt(m));
      if (!Number.isInteger(lm) || lm > I.logN) throw new Error('VK: periodic column period');
      return {lm, coef: Array.from({length: m}, (_, k) => md(col.reduce((s, c, j) => s + c * pw(wi, BigInt(j * k)), 0n) * mi))};
    });
    const dag = I.dag, scale = [];
    dag.nodes.forEach((nd, k) => {
      switch (nd.op) {
        case 'is_first_row': case 'is_last_row': case 'is_transition': scale[k] = 1; break;
        case 'add': case 'sub': scale[k] = Math.max(scale[nd.a], scale[nd.b]); break;
        case 'mul': scale[k] = scale[nd.a] + scale[nd.b]; break;
        case 'neg': scale[k] = scale[nd.a]; break;
        case 'main': case 'pre': case 'periodic': case 'public': case 'const': case 'ext_const': case 'perm': case 'challenge': case 'perm_value': scale[k] = 0; break;
        default: throw new Error('generator: DAG op ' + nd.op);
      }
    });
    const maxScale = Math.max(0, ...dag.constraints.map((c) => scale[c.node]));
    const pubOff = b.inst.slice(0, i).reduce((s, J) => s + J.numPublic, 0);
    return {
      i, logN: I.logN, n: 1 << I.logN, gN: g2(I.logN), degreeBits: I.degreeBits, logLde: I.logLde, width: I.width, opensNext: I.opensNext,
      numPublic: I.numPublic, pubOff, preWidth: I.preWidth, preNext: I.preNext, C, numLookups: I.numLookups, permWidth: I.permWidth,
      shifts, kc, zpConst, periodic, dag, scale, maxScale,
    };
  });
  // claims in observation order (round, matrix, point); points: 'z' (zeta) or 'n<logN>' (zeta g_logN)
  const pointKeys = []; const pointOf = (key) => { let k = pointKeys.indexOf(key); if (k < 0) { pointKeys.push(key); k = pointKeys.length - 1; } return k; };
  pointOf('z');
  const claims = []; let nv = 0;
  b.rounds.forEach((r, ri) => {
    const seen = new Map();
    r.matrices.forEach((m, mi) => {
      const k = seen.get(m.inst) ?? 0; seen.set(m.inst, k + 1);
      for (let p = 0; p < m.points; p++) {
        claims.push({ri, mi, p, round: r.name, inst: m.inst, chunk: r.name === 'quotient' ? k : 0, logH: m.logH, width: m.width, rc: r.rc,
          pt: pointOf(p === 0 ? 'z' : 'n' + inst[m.inst].logN), v0: nv});
        nv += m.width;
      }
    });
  });
  const points = pointKeys.map((k) => (k === 'z' ? {key: k, logN: null} : {key: k, logN: +k.slice(1)}));
  const heights = [...new Set(claims.map((c) => c.logH))].sort((x, y) => y - x);
  if (heights[0] !== b.logH) throw new Error('top height');
  // per height: its points (local index) and the ladder offsets
  const hp = {}; const ladder = {};
  for (const h of heights) { hp[h] = []; ladder[h] = 0; }
  for (const c of claims) {
    if (!hp[c.logH].includes(c.pt)) hp[c.logH].push(c.pt);
    c.ptl = hp[c.logH].indexOf(c.pt); c.off = ladder[c.logH]; ladder[c.logH] += c.width;
  }
  const maxLadder = Math.max(...Object.values(ladder));
  // per instance: value indices of its openings
  const ovOf = (i, round, p, chunk = 0) => { const c = claims.find((x) => x.inst === i && x.round === round && x.p === p && x.chunk === chunk); return c ? c.v0 : null; };
  inst.forEach((I) => {
    I.ov = {
      tl: ovOf(I.i, 'trace', 0), tn: I.opensNext ? ovOf(I.i, 'trace', 1) : null,
      pl: I.preWidth ? ovOf(I.i, 'preprocessed', 0) : null, pn: I.preWidth && I.preNext ? ovOf(I.i, 'preprocessed', 1) : null,
      ch: Array.from({length: I.C}, (_, k) => ovOf(I.i, 'quotient', 0, k)),
      ml: I.numLookups ? ovOf(I.i, 'permutation', 0) : null, mn: I.numLookups ? ovOf(I.i, 'permutation', 1) : null,
    };
  });
  // Merkle trees: input rounds (bottom levels walked per query), then FRI rounds
  const trees = [];
  b.rounds.forEach((r, bi) => {
    const hs = r.matrices.map((m) => m.logH), top = Math.max(...hs);
    const gh = [...new Set(hs)].sort((x, y) => y - x);
    const groups = gh.map((x) => ({logH: x, mats: r.matrices.map((m, mi) => (m.logH === x ? mi : -1)).filter((mi) => mi >= 0)}));
    const B = top - gh[gh.length - 1];
    trees.push({kind: 'in', b: bi, name: r.name, top, B, groups, depth: top - B, shift: b.logH - top + B, matW: r.matrices.map((m) => m.width)});
  });
  { let sh = 0; b.logArities.forEach((la, r) => { sh += la; trees.push({kind: 'fri', r, B: 0, depth: b.logH - sh, shift: sh}); }); }
  // separators (constants the challenger observes)
  const counts = b.rounds.map((r) => r.matrices.map((m) => Array.from({length: m.points}, () => m.width)));
  const sepB = batchSeparator(b), sepP = pcsSeparator(b, counts), sepF = friSeparator(b);
  const SO = {batch: Buffer.concat([seedObs(sepB.seed), ...inst.flatMap((I) => [le8(I.degreeBits), le8(0), le8(0)])]), pcs: seedObs(sepP.seed), fri: seedObs(sepF.seed)};
  // FRI rounds, roll-ins
  const fr = b.logArities.map((la) => { const a = 1 << la, ga = g2(la); return {la, a, W: Array.from({length: a}, (_, j) => pw(ga, rev(j, la))), ainv: inv(BigInt(a))}; });
  const rollIn = []; { let hh = b.logH; b.logArities.forEach((la, r) => { hh -= la; rollIn[r] = heights.includes(hh) ? hh : null; }); if (hh !== b.logFinal) throw new Error('final height'); }
  if (heights.some((x) => x !== b.logH && !rollIn.includes(x))) throw new Error('VK: a height is not on the fold grid');
  // byte layouts
  const blob = {
    trees: trees.filter((t) => t.kind === 'in').map((t) => ({groups: t.groups.map((g) => g.mats.reduce((s, mi) => s + 8 * (t.matW[mi] + (b.zk ? b.salt : 0)), 0)), sibs: t.B * H32})),
    fri: b.logArities.map((la) => ((1 << la) - 1) * E8 + 8 * (b.zk ? b.salt : 0)),
    hints: heights.length * 8,
  };
  blob.total = blob.trees.reduce((s, t) => s + t.groups.reduce((a, x) => a + x, 0) + t.sibs, 0) + blob.fri.reduce((s, x) => s + x, 0) + blob.hints;
  const nCaps = 2 + (b.hasLookups ? 1 : 0) + (b.zk ? 1 : 0);
  const termInst = inst.filter((I) => I.numLookups > 0).map((I) => I.i);
  const ptItems = [
    ['ROOTS', nCaps * H32], ...(b.hasLookups ? [['TERM', termInst.length * E8]] : []), ...(b.hasLookups && b.lpow ? [['LPOW', 8]] : []),
    ['OOD', nv * E8], ...(b.bpow ? [['BPOW', 8]] : []), ['FROOTS', b.logArities.length * H32], ...(b.cpow ? [['CPOW', 8 * b.logArities.length]] : []),
    ['FIN', b.L * E8], ...(b.qpow ? [['QPOW', 8]] : []),
  ];
  const capOff = {trace: 0, permutation: b.hasLookups ? H32 : null, quotient: (b.hasLookups ? 2 : 1) * H32, random: b.zk ? (nCaps - 1) * H32 : null};
  return {
    D, h: H32, e8: E8, F, Q: b.Q, zk: b.zk, rc: b.rc, salt: b.zk ? b.salt : 0, logH: b.logH, logFinal: b.logFinal, logArities: b.logArities, L: b.L,
    S: b.logArities.reduce((s, x) => s + x, 0), bpow: b.bpow, cpow: b.cpow, qpow: b.qpow, lpow: b.hasLookups ? b.lpow : 0, opow: 0,
    inst, rounds: b.rounds, claims, points, heights, hp, ladder, maxLadder, numVals: nv, trees, SO, fr, rollIn, blob, ptItems, nCaps, capOff,
    hasPre: b.hasPre, pre: b.pre, preCap: b.hasPre ? Buffer.concat(b.pre) : null, hasLookups: b.hasLookups, lookups: b.lookups, termInst,
    nPub, stmt, gH: g2(b.logH), base: b,
  };
}

// ---------------------------------------------------------------- lenient parse (proof order; missing bytes read as zero)
export function lenientParseN(buf, vk) {
  let o = 0, short = false;
  const take = (n) => { const b = Buffer.alloc(n); const end = Math.min(o + n, buf.length); if (end - o < n) short = true; if (end > o) buf.copy(b, 0, o, end); o += n; return b; };
  const takeN = (n) => Array.from({length: n}, () => take(E8));
  const pr = {};
  pr.mainCap = take(H32); pr.permCap = vk.hasLookups ? take(H32) : null; pr.quotCap = take(H32); pr.randCap = vk.zk ? take(H32) : null;
  pr.terminals = vk.inst.map((I) => (I.numLookups ? take(E8) : null));
  pr.ood = vk.inst.map((I) => ({
    tl: takeN(I.width), tn: I.opensNext ? takeN(I.width) : null, pl: I.preWidth ? takeN(I.preWidth) : null, pn: I.preWidth && I.preNext ? takeN(I.preWidth) : null,
    ch: Array.from({length: I.C}, () => takeN(D)), rnd: vk.zk ? takeN(D) : null, ml: takeN(I.permWidth), mn: takeN(I.permWidth),
  }));
  pr.LPOW = vk.hasLookups && vk.lpow ? take(8) : null;
  pr.randVals = vk.zk ? vk.rounds.map((r) => r.matrices.map((m) => Array.from({length: m.points}, () => takeN(r.rc)))) : null;
  pr.BPOW = vk.bpow ? take(8) : null;
  pr.FROOTS = take(vk.logArities.length * H32);
  pr.CPOW = vk.cpow ? take(8 * vk.logArities.length) : null;
  pr.FIN = take(vk.L * E8);
  pr.QPOW = vk.qpow ? take(8) : null;
  const sibList = () => { const n = take(2).readUInt16LE(); return Array.from({length: n}, () => take(H32)); };
  pr.inputs = vk.rounds.map((r) => {
    const rows = Array.from({length: vk.Q}, () => r.matrices.map((m) => take(8 * m.width)));
    const salts = vk.zk ? Array.from({length: vk.Q}, () => r.matrices.map(() => take(8 * vk.salt))) : null;
    return {rows, salts, sibs: sibList()};
  });
  pr.fri = vk.logArities.map((la) => {
    const sib = Array.from({length: vk.Q}, () => take(((1 << la) - 1) * E8));
    const salts = vk.zk ? Array.from({length: vk.Q}, () => take(8 * vk.salt)) : null;
    return {sib, salts, sibs: sibList()};
  });
  pr.trailing = o < buf.length ? buf.subarray(o) : Buffer.alloc(0);
  pr.short = short;
  // witness items
  pr.ROOTS = Buffer.concat([pr.mainCap, ...(pr.permCap ? [pr.permCap] : []), pr.quotCap, ...(pr.randCap ? [pr.randCap] : [])]);
  pr.TERM = vk.hasLookups ? Buffer.concat(pr.terminals.filter(Boolean)) : null;
  const src = (c) => {
    const x = pr.ood[c.inst];
    const vals = {random: x.rnd, trace: c.p ? x.tn : x.tl, quotient: x.ch[c.chunk], preprocessed: c.p ? x.pn : x.pl, permutation: c.p ? x.mn : x.ml}[c.round];
    return [...vals, ...(vk.zk ? pr.randVals[c.ri][c.mi][c.p] : [])];
  };
  const oodVals = vk.claims.flatMap(src);
  if (oodVals.length !== vk.numVals) throw new Error('ood layout');
  pr.OOD = Buffer.concat(oodVals);
  return pr;
}
const valAt = (pr, k) => Array.from({length: D}, (_, c) => leNum(pr.OOD.subarray(k * E8 + 8 * c, k * E8 + 8 * c + 8)));

// public values: the bytes the transcript observes (u64 LE each, in instance order)
export const pisBytes = (pis) => Buffer.concat(pis.map(le8));

// ---------------------------------------------------------------- transcript (digest chain, as the script)
class Pop {
  constructor(d, log) { this.d = d; this.pos = 32; this.log = log; }
  slice8() { if (this.pos === 0) { this.log?.push(this.d.toString('hex')); this.d = sha(this.d); this.pos = 32; } this.pos -= 8; return this.d.subarray(this.pos, this.pos + 8); }
  u64() { const s = this.slice8(); let v = 0n; for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(s[i]); return v; }
  base() { const v = this.u64(); if (v >= P) throw new Reject('sample >= p'); return v; }
  ext() { return Array.from({length: D}, () => this.base()); }
  low(bits) { return Number(this.u64() & ((1n << BigInt(bits)) - 1n)); }
}
export function transcriptN(vk, pr, pis) {
  const t = {hashes: []};
  const H = (...p) => { const d = sha(...p); t.hashes.push(Buffer.concat(p.map((x) => Buffer.from(x))).toString('hex')); return d; };
  const pow = (dd, w, bits) => { const x = H(dd, w); const pp = new Pop(x, t.hashes); if (pp.low(bits) !== 0) throw new Reject('PoW'); return pp; };
  let pp = new Pop(H(vk.SO.batch, pr.mainCap, pisBytes(pis), ...(vk.hasPre ? [vk.preCap] : [])), t.hashes);
  if (vk.hasLookups) {
    if (vk.lpow) pp = pow(pp.d, pr.LPOW, vk.lpow);
    t.la = pp.ext(); t.lb = pp.ext();
    pp = new Pop(H(pp.d, pr.permCap, pr.TERM), t.hashes);
  }
  t.alpha = pp.ext();
  pp = new Pop(H(pp.d, pr.quotCap, ...(vk.zk ? [pr.randCap] : [])), t.hashes);
  t.zeta = pp.ext();
  const dp = H(pp.d, vk.SO.pcs, pr.OOD);
  pp = vk.bpow ? pow(dp, pr.BPOW, vk.bpow) : new Pop(dp, t.hashes);
  t.alphaP = pp.ext();
  t.betas = [];
  vk.logArities.forEach((_, r) => {
    const x = H(pp.d, r === 0 ? vk.SO.fri : Buffer.alloc(0), pr.FROOTS.subarray(r * H32, r * H32 + H32));
    pp = vk.cpow ? pow(x, pr.CPOW.subarray(8 * r, 8 * r + 8), vk.cpow) : new Pop(x, t.hashes);
    t.betas.push(pp.ext());
  });
  const f = H(pp.d, pr.FIN);
  pp = vk.qpow ? pow(f, pr.QPOW, vk.qpow) : new Pop(f, t.hashes);
  t.idx = Array.from({length: vk.Q}, () => pp.low(vk.logH));
  t.G = pp.d;
  return t;
}

// ---------------------------------------------------------------- per-proof constants
export function proofConstsN(vk, pr, t) {
  const F = vk.F;
  const c = {zeta: t.zeta};
  c.pts = vk.points.map((p) => (p.logN === null ? t.zeta : F.smul(t.zeta, g2(p.logN))));
  c.na = c.pts.map((z) => normAdj(F, z));
  c.apow = [F.one()]; for (let k = 1; k < vk.maxLadder; k++) c.apow.push(F.mul(c.apow[k - 1], t.alphaP));
  // A_{h, point} = sum over that height's claims at the point of sum_k apow[off + k] v_k
  c.A = {}; for (const h of vk.heights) c.A[h] = vk.hp[h].map(() => F.zero());
  for (const cl of vk.claims) for (let k = 0; k < cl.width; k++) c.A[cl.logH][cl.ptl] = F.add(c.A[cl.logH][cl.ptl], F.mul(c.apow[cl.off + k], valAt(pr, cl.v0 + k)));
  // fold: beta^(arity) for the roll-in rounds
  c.bpa = vk.logArities.map((la, r) => F.pow(t.betas[r], 1n << BigInt(la)));
  // LogUp challenges: gamma = beta^maxW, prefix_k = alpha + (k + 1) gamma; per instance [prefix_bus, beta] per lookup
  if (vk.hasLookups) {
    const gamma = F.pow(t.lb, vk.lookups.maxW); const prefix = []; let pf = t.la;
    for (let k = 0; k < vk.lookups.numBuses; k++) { pf = F.add(pf, gamma); prefix.push(pf); }
    c.challenges = vk.lookups.busIds.map((ids) => ids.flatMap((bb) => [prefix[bb], t.lb]));
  } else c.challenges = vk.inst.map(() => []);
  return c;
}

// ---------------------------------------------------------------- AIR at zeta, per instance (multiplied through by Dd^scale)
export function airCheckN(vk, pr, c, t, pis) {
  const F = vk.F;
  const recomp = (vals) => vals.reduce((acc, v, k) => F.add(acc, F.mul(v, F.basis(k))), F.zero());
  for (const I of vk.inst) {
    const zN = F.pow(c.zeta, I.n), zh = F.sub(zN, F.one());
    if (F.isZero(zh)) throw new Reject('zeta in trace domain');
    if (vk.zk && F.isZero(F.add(zN, F.one()))) throw new Reject('zeta in ext trace domain');
    const D1 = F.sub(c.zeta, F.one()), D2 = F.sub(c.zeta, F.lift(inv(I.gN))), Dd = F.mul(D1, D2);
    const selW = {is_first_row: F.mul(zh, D2), is_last_row: F.mul(zh, D1), is_transition: F.mul(Dd, D2)};
    const per = I.periodic.map(({lm, coef}) => {
      const y = F.pow(c.zeta, 1n << BigInt(I.logN - lm));
      let acc = F.zero(); for (let k = coef.length - 1; k >= 0; k--) acc = F.add(F.mul(acc, y), F.lift(coef[k]));
      return acc;
    });
    const ov = (base, col) => valAt(pr, base + col);
    const permRec = (base, col) => recomp([0, 1, 2].map((k) => valAt(pr, base + D * col + k)));
    const s = I.scale, val = [];
    const up = (x, k) => { for (let j = 0; j < k; j++) x = F.mul(x, Dd); return x; };
    I.dag.nodes.forEach((nd, k) => {
      switch (nd.op) {
        case 'main': val[k] = ov(nd.row === 0 ? I.ov.tl : I.ov.tn, nd.col); break;
        case 'pre': val[k] = ov(nd.row === 0 ? I.ov.pl : I.ov.pn, nd.col); break;
        case 'periodic': val[k] = per[nd.col]; break;
        case 'public': val[k] = F.lift(pis[I.pubOff + nd.col]); break;
        case 'const': val[k] = F.lift(BigInt(nd.v)); break;
        case 'ext_const': val[k] = nd.v.map((x) => md(BigInt(x))); break;
        case 'perm': val[k] = permRec(nd.row === 0 ? I.ov.ml : I.ov.mn, nd.col); break;
        case 'challenge': val[k] = c.challenges[I.i][nd.col]; break;
        case 'perm_value': val[k] = Array.from({length: D}, (_, j) => leNum(pr.terminals[I.i].subarray(8 * j, 8 * j + 8))); break;
        case 'is_first_row': case 'is_last_row': case 'is_transition': val[k] = selW[nd.op]; break;
        case 'add': val[k] = F.add(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
        case 'sub': val[k] = F.sub(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
        case 'mul': val[k] = F.mul(val[nd.a], val[nd.b]); break;
        case 'neg': val[k] = F.neg(val[nd.a]); break;
      }
      if (val[k] === undefined) throw new Error(`DAG node ${k} (${nd.op}): no value`);
    });
    let acc = F.zero();
    for (const cn of I.dag.constraints) acc = F.add(F.mul(acc, t.alpha), up(val[cn.node], I.maxScale - s[cn.node]));
    let q = F.zero();
    for (let k = 0; k < I.C; k++) {
      let zp = F.lift(I.zpConst[k]);
      for (let j = 0; j < I.C; j++) if (j !== k) zp = F.mul(zp, F.sub(F.smul(zN, I.kc[j]), F.one()));
      q = F.add(q, F.mul(zp, recomp([0, 1, 2].map((m) => valAt(pr, I.ov.ch[k] + m)))));
    }
    if (!F.eq(acc, up(F.mul(q, zh), I.maxScale))) throw new Reject(`OOD constraint mismatch (instance ${I.i})`);
  }
  if (vk.hasLookups) {
    let s = F.zero(); for (const i of vk.termInst) s = F.add(s, Array.from({length: D}, (_, j) => leNum(pr.terminals[i].subarray(8 * j, 8 * j + 8))));
    if (!F.isZero(s)) throw new Reject('LogUp terminal sum non-zero');
  }
}

// ---------------------------------------------------------------- queries
const xoOf = (vk, idx) => {
  const la0 = vk.logArities[0];
  const s0 = pw(vk.gH, rev(idx >>> la0, vk.logH - la0));
  return {s0, xo: s0 * vk.fr[0].W[idx % vk.fr[0].a] % P};
};
const xoAt = (vk, xo, h) => { let x = xo; for (let i = 0; i < vk.logH - h; i++) x = x * x % P; return x; };
// hints: one per height (top first): T_top = 1 / (s0 prod N(x)), T_h = 1 / prod N(x_h); 0 when the product is 0
export function hintsN(vk, c, idx) {
  const {s0, xo} = xoOf(vk, idx);
  return vk.heights.map((h, hi) => {
    const x = 7n * xoAt(vk, xo, h) % P;
    let prod = hi === 0 ? s0 : 1n;
    for (const pt of vk.hp[h]) prod = prod * c.na[pt].N(x) % P;
    return prod === 0n ? 0n : inv(prod);
  });
}
// the row bytes of tree ti's matrix mi for query q: row ‖ salt
const rowBytes = (vk, pr, b, q, mi) => Buffer.concat([pr.inputs[b].rows[q][mi], ...(vk.zk ? [pr.inputs[b].salts[q][mi]] : [])]);
// query blob: per input tree: group preimages (tallest first), bottom siblings; FRI blocks; hints
export function queryBlob(vk, pr, q, bottom, T) {
  return Buffer.concat([
    ...vk.trees.filter((t) => t.kind === 'in').flatMap((t, ti) => [...t.groups.map((g) => Buffer.concat(g.mats.map((mi) => rowBytes(vk, pr, t.b, q, mi)))), ...bottom[ti]]),
    ...pr.fri.map((f) => Buffer.concat([f.sib[q], ...(vk.zk ? [f.salts[q]] : [])])),
    ...T.map((x) => le8(x)),
  ]);
}
// one query as the script computes it from its blob: returns the leaf digests (input trees: the level-B node)
export function runQueryN(vk, pr, t, c, q, T, bottom) {
  const F = vk.F;
  const idx = t.idx[q];
  const digests = [];
  // input trees: tallest-group digest, then B levels with the bottom siblings and injections
  vk.trees.filter((tr) => tr.kind === 'in').forEach((tr, ti) => {
    const pre = tr.groups.map((g) => Buffer.concat(g.mats.map((mi) => rowBytes(vk, pr, tr.b, q, mi))));
    let d = sha(pre[0]);
    const leaf = idx >>> (vk.logH - tr.top);
    for (let l = 1; l <= tr.B; l++) {
      const sib = bottom[ti][l - 1];
      d = (leaf >>> (l - 1)) & 1 ? sha(sib, d) : sha(d, sib);
      const gi = tr.groups.findIndex((g) => g.logH === tr.top - l);
      if (gi > 0) d = sha(d, sha(pre[gi]));
    }
    digests.push(d);
  });
  // DEEP per height
  const {s0, xo} = xoOf(vk, idx);
  const rows = vk.rounds.map((r, b) => r.matrices.map((m, mi) => Array.from({length: m.width}, (_, j) => leNum(pr.inputs[b].rows[q][mi].subarray(8 * j, 8 * j + 8)))));
  const ro = {}; let sinv = null;
  vk.heights.forEach((h, hi) => {
    const x = 7n * xoAt(vk, xo, h) % P;
    const Ns = vk.hp[h].map((pt) => c.na[pt].N(x));
    const prodN = Ns.reduce((a, y) => a * y % P, 1n);
    if (hi === 0) { if (prodN * s0 % P * T[0] % P !== 1n) throw new Reject('hint T'); sinv = T[0] * prodN % P; }
    else if (prodN * T[hi] % P !== 1n) throw new Reject('hint T_h');
    const num = vk.hp[h].map(() => F.zero());
    for (const cl of vk.claims) if (cl.logH === h) rows[cl.ri][cl.mi].forEach((v, j) => { num[cl.ptl] = F.add(num[cl.ptl], F.smul(c.apow[cl.off + j], v)); });
    let acc = F.zero();
    vk.hp[h].forEach((pt, k) => {
      let term = F.mul(F.sub(c.A[h][k], num[k]), c.na[pt].adj(x));
      Ns.forEach((Nj, j) => { if (j !== k) term = F.smul(term, Nj); });
      acc = F.add(acc, term);
    });
    ro[h] = F.smul(acc, hi === 0 ? T[0] * s0 % P : T[hi]);
  });
  // folds with roll-ins
  let folded = ro[vk.logH], di = idx;
  vk.fr.forEach((rd, r) => {
    const pos = di % rd.a;
    const sib = pr.fri[r].sib[q];
    const vals = []; let s = 0;
    for (let j = 0; j < rd.a; j++) { vals.push(j === pos ? folded : Array.from({length: D}, (_, k) => leNum(sib.subarray((s * D + k) * 8, (s * D + k) * 8 + 8)))); if (j !== pos) s++; }
    const leaf = Buffer.concat([...vals.flatMap((e) => e.map(le8)), ...(vk.zk ? [pr.fri[r].salts[q]] : [])]);
    digests.push(sha(leaf));
    let cur = vals, si = sinv;
    const ga = g2(rd.la);
    for (let l = 0; l < rd.la; l++) {
      const be = F.pow(t.betas[r], 1n << BigInt(l));
      const half = cur.length / 2, gl = inv(pw(ga, 1n << BigInt(l)));
      const nxt = [];
      for (let m = 0; m < half; m++) {
        const xi = si * pw(gl, rev(m, rd.la - 1 - l)) % P;
        const u = cur[2 * m], v = cur[2 * m + 1];
        nxt.push(F.add(F.add(u, v), F.smul(F.mul(be, F.sub(u, v)), xi)));
      }
      cur = nxt; si = si * si % P;
    }
    folded = F.smul(cur[0], rd.ainv);
    if (vk.rollIn[r] !== null) folded = F.add(folded, F.mul(c.bpa[r], ro[vk.rollIn[r]]));
    di = Math.floor(di / rd.a);
    if (r + 1 < vk.fr.length) { const nr = vk.fr[r + 1]; sinv = si * nr.W[di % nr.a] % P; }
  });
  const xf = pw(xo, 1n << BigInt(vk.S));
  const fin = Array.from({length: vk.L}, (_, i) => Array.from({length: D}, (_, k) => leNum(pr.FIN.subarray((i * D + k) * 8, (i * D + k) * 8 + 8))));
  let e = F.zero(); for (let i = fin.length - 1; i >= 0; i--) e = F.add(F.smul(e, xf), fin[i]);
  if (!F.eq(e, folded)) throw new Reject(`FRI final polynomial mismatch (query ${q})`);
  return {digests};
}

// ---------------------------------------------------------------- Merkle: lenient walk of a mixed-height multiproof
// As verify-batch.mjs merkleVerify (cap 0): node map `${level}:${index}` (post-injection digests, and siblings at their
// own level), siblings consumed in walk order; a missing sibling reads as zero.
function walkTree(vk, pr, tr, idx) {
  const top = tr.top, hs = vk.rounds[tr.b].matrices.map((m) => m.logH);
  const leafOf = (q) => idx[q] >>> (vk.logH - top);
  const byH = (x) => hs.map((y, m) => (y === x ? m : -1)).filter((m) => m >= 0);
  const hashRows = (q, ms) => sha(Buffer.concat(ms.map((mi) => rowBytes(vk, pr, tr.b, q, mi))));
  const sibs = pr.inputs[tr.b].sibs; let cur = 0;
  const map = new Map();
  const rep = new Map(); idx.forEach((_, q) => { if (!rep.has(leafOf(q))) rep.set(leafOf(q), q); });
  let nodes = [...rep.keys()].sort((a, b) => a - b).map((i) => ({i, d: hashRows(rep.get(i), byH(top)), lead: rep.get(i)}));
  for (const n of nodes) map.set(`0:${n.i}`, n.d);
  for (let level = 1; level <= top; level++) {
    const next = [];
    for (let k = 0; k < nodes.length;) {
      const parent = Math.floor(nodes[k].i / 2), inp = []; let lead = null;
      for (let pos = 0; pos < 2; pos++) {
        if (k < nodes.length && nodes[k].i === 2 * parent + pos) { inp.push(nodes[k].d); lead ??= nodes[k].lead; k++; }
        else { const s = sibs[cur++] ?? Buffer.alloc(H32); map.set(`${level - 1}:${2 * parent + pos}`, s); inp.push(s); }
      }
      let d = sha(...inp);
      const inj = byH(top - level);
      if (inj.length) d = sha(d, hashRows(lead, inj));
      next.push({i: parent, d, lead}); map.set(`${level}:${parent}`, d);
    }
    nodes = next;
  }
  return {map, used: cur, leftover: sibs.slice(cur)};
}

// ---------------------------------------------------------------- encoder: witness of the given query parts
// parts: arrays of query numbers, one per input (layout b: [[0..Q-1]]; b2: [[0..QA-1], [QA..Q-1]])
export function encodeN(vk, buf, pis, parts = [Array.from({length: vk.Q}, (_, q) => q)]) {
  const pr = lenientParseN(buf, vk);
  const out = {pr};
  let t; try { t = transcriptN(vk, pr, pis); } catch (e) { if (!(e instanceof Reject)) throw e; out.reject = e.message; t = null; }
  out.t = t;
  const c = t ? proofConstsN(vk, pr, t) : null; out.c = c;
  const idx = t ? t.idx : Array(vk.Q).fill(0);
  out.T = idx.map((i) => (c ? hintsN(vk, c, i) : vk.heights.map(() => 0n)));
  // input trees: walk, bottom siblings per query, upper maps
  const inTrees = vk.trees.filter((tr) => tr.kind === 'in');
  const walks = inTrees.map((tr) => walkTree(vk, pr, tr, idx));
  out.bottom = idx.map((i) => inTrees.map((tr, ti) => Array.from({length: tr.B}, (_, l) => {
    const leaf = i >>> (vk.logH - tr.top);
    return walks[ti].map.get(`${l}:${(leaf >>> l) ^ 1}`) ?? Buffer.alloc(H32);
  })));
  out.L = idx.map((_, q) => queryBlob(vk, pr, q, out.bottom[q], out.T[q]));
  const dig = idx.map(() => null);
  if (t) for (let q = 0; q < vk.Q; q++) {
    try { dig[q] = runQueryN(vk, pr, t, c, q, out.T[q], out.bottom[q]).digests; } catch (e) { if (!(e instanceof Reject)) throw e; out.reject ??= e.message; }
  }
  out.dig = dig;
  // per tree: node map for the record tree (relative levels) and leftover siblings
  const recMaps = vk.trees.map((tr, ti) => {
    if (tr.kind === 'in') {
      const w = walks[ti], m = new Map();
      for (const [k, d] of w.map) { const [l, i] = k.split(':').map(Number); if (l >= tr.B) m.set(`${l - tr.B}:${i}`, d); }
      return {map: m, leftover: w.leftover};
    }
    const recs = idx.map((i, q) => [i >>> tr.shift, dig[q]?.[ti] ?? Buffer.alloc(H32)]);
    const can = canonicalTree(H32, tr.depth, recs, pr.fri[tr.r].sibs);
    return {map: can.map, leftover: can.leftover};
  });
  out.records = parts.map((qs) => vk.trees.map((tr, ti) => {
    const recs = qs.map((q, j) => ({q: j, leaf: idx[q] >>> tr.shift, digest: dig[q]?.[ti] ?? Buffer.alloc(H32)}));
    return lifoPrograms(H32, tr.depth, recs, recMaps[ti].map).programs.map((p) => p.bytes);
  }));
  // leftover siblings and trailing proof bytes go to the last record program (the script rejects them)
  const lastPart = out.records[out.records.length - 1];
  const extra = Buffer.concat([...recMaps.flatMap((x) => x.leftover), pr.trailing]);
  if (extra.length) { const lr = lastPart[lastPart.length - 1]; lr[lr.length - 1] = Buffer.concat([lr[lr.length - 1], extra]); out.leftover = extra.length; }
  out.roots = vk.trees.map((tr) => (tr.kind === 'fri' ? pr.FROOTS.subarray(tr.r * H32, tr.r * H32 + H32)
    : tr.name === 'preprocessed' ? vk.preCap : pr.ROOTS.subarray(vk.capOff[tr.name], vk.capOff[tr.name] + H32)));
  out.PT = Object.fromEntries(vk.ptItems.map(([k]) => [k, pr[k]]));
  out.parts = parts;
  return out;
}

// model verdict: every check the script makes (statement, transcript, AIR, queries, Merkle per part)
export function verifyModelN(vk, buf, pis, parts) {
  if (pis.length !== vk.nPub) return {ok: false, reason: 'public value count'};
  if (pis.some((x) => x < 0n || x >= P)) return {ok: false, reason: 'non-canonical public value'};
  const enc = encodeN(vk, buf, pis, parts);
  try {
    if (enc.pr.short) throw new Reject('truncated proof');
    if (enc.reject) throw new Reject(enc.reject);
    const {t, c, pr} = enc;
    airCheckN(vk, pr, c, t, pis);
    enc.parts.forEach((qs, pi) => vk.trees.forEach((tr, ti) => {
      const why = lifoRun(H32, tr.depth, qs.length, (j) => enc.dig[qs[j]][ti], (j) => t.idx[qs[j]] >>> tr.shift, enc.records[pi][ti], enc.roots[ti]);
      if (why) throw new Reject(`part ${pi} tree ${ti}: ${why}`);
    }));
    return {ok: true, enc};
  } catch (e) { if (!(e instanceof Reject)) throw e; return {ok: false, reason: e.message, enc}; }
}
