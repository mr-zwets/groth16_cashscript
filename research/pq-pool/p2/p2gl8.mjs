// Track 9 S0: Poseidon2-Gl-8 (Plonky3 p3-goldilocks width 8, stock constants) as CashVM (BCH 2026) script.
//
// Reference: permRef() below is a transcription of air8_ref.py perm() (bench research/pq-stark/design-t8), same constants
// file (poseidon2-gl8-constants.json, copied from there; Plonky3 0d803737 goldilocks/src/poseidon2.rs). Round order:
//   x = ME(x); 4 x [x = ME(sbox(x + rcE))]; 22 x [x0 = sbox(x0 + rcI); x = MI(x)]; 4 x [x = ME(sbox(x + rcF))]
// with ME = [[2 M4, M4], [M4, 2 M4]], M4 = circ-like [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]], MI = 1 + diag(DG).
//
// Script arithmetic (all VM numbers, lazy reduction):
//   - lanes are unreduced integers (possibly negative inside the partial rounds); a VM MOD (truncated remainder) keeps
//     the residue, so every intermediate is congruent to the field value;
//   - S-box: DUP DUP MUL OVER MUL DUP MUL MUL (x^7, 4 multiplications) then <p> MOD;
//   - ME: per pair (a_i, b_i = x_i, x_{i+4}): g_i = 2a_i + b_i, h_i = a_i + 2b_i; then, with G = sum g, H = sum h,
//     y_i = G + g_i + 2 g_{i+1}, y_{4+i} = H + h_i + 2 h_{i+1} (indices mod 4). (M4 x = sum(x) + x_i + 2 x_{i+1}.)
//   - MI: y_i = S + d_i x_i with d = [-2, 1, 2, 1/2, 3, -1/2, -3, -4]; the two +-1/2 lanes are reduced every round
//     (multiplication by a 63-bit constant), lane 0 is reduced by the S-box, the others grow by < 4 bits per round.
//   - The final outputs are canonical (in [0, p)): every lane entering the last 4 full rounds is made non-negative
//     (<p> MOD, then + p + rc), all later values are non-negative, and the last ME outputs get <p> MOD.
import fs from 'fs';
import {asm, Stk} from './lib/asm.mjs';

const HERE = new URL('.', import.meta.url).pathname;
// integers are quoted before JSON.parse so that 64-bit constants keep full precision
export const K = JSON.parse(fs.readFileSync(HERE + 'poseidon2-gl8-constants.json', 'utf8').replace(/([\[\s,:])(\d{10,})(?=[\s,\]}])/g, '$1"$2"'));
export const P = 2n ** 64n - 2n ** 32n + 1n;
const big = (a) => a.map((x) => BigInt(x));
export const EI = K.external_initial.map(big), EF = K.external_final.map(big), RI = big(K.internal), DG = big(K.matrix_diag_8);
export const md = (x) => ((x % P) + P) % P;

// ---------------------------------------------------------------- reference (air8_ref.py perm)
const M4 = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
const ME = [...Array(8)].map((_, i) => [...Array(8)].map((_, j) => BigInt(M4[i % 4][j % 4] * (Math.floor(i / 4) === Math.floor(j / 4) ? 2 : 1))));
const MI = [...Array(8)].map((_, i) => [...Array(8)].map((_, j) => md((i === j ? DG[i] : 0n) + 1n)));
const mv = (M, x) => M.map((row) => md(row.reduce((s, c, j) => s + c * x[j], 0n)));
const pow7 = (x) => { const x2 = x * x % P, x3 = x2 * x % P; return x3 * x3 % P * x % P; };
export function permRef(x0) {
  let x = mv(ME, x0.map(BigInt));
  for (let r = 0; r < 4; r++) x = mv(ME, x.map((v, i) => pow7(md(v + EI[r][i]))));
  for (let r = 0; r < 22; r++) { x = [...x]; x[0] = pow7(md(x[0] + RI[r])); x = mv(MI, x); }
  for (let r = 0; r < 4; r++) x = mv(ME, x.map((v, i) => pow7(md(v + EF[r][i]))));
  return x;
}

// ---------------------------------------------------------------- script generator
// small signed representative of a field constant, or null if it is not small
const small = (c) => (c < 256n ? c : (P - c < 256n ? -(P - c) : null));
// S-box x -> x^7 mod p. 'plain': x^7 from 4 multiplications, then one MOD; 'mid' (default): x^3 is reduced before it
// is squared, which costs two instructions but shrinks the operands of the last two multiplications and of the MOD.
const SBOX = {
  plain: ['DUP', 'DUP', 'MUL', 'OVER', 'MUL', 'DUP', 'MUL', 'MUL', P, 'MOD'],
  mid: ['DUP', 'DUP', 'MUL', 'OVER', 'MUL', P, 'MOD', 'DUP', 'MUL', 'MUL', P, 'MOD'],
};
let OPT = {sbox: 'mid', m4: 'chain', psum: '3dup'};
export const setOptions = (o) => { OPT = {...OPT, ...o}; return OPT; };

// x on top -> (x + rc)^7 mod p (rc = 0n: no add)
function sbox(st, rc, pre = []) { st.emit(pre); if (rc !== 0n) st.emit(rc, 'ADD'); st.emit(SBOX[OPT.sbox]); }

let nid = 0;
const nm = (b) => `${b}.${nid++}`;

// ME on lanes x[0..7] (names, consumed). outOrder: the order the 8 (or 4) outputs are produced; after each output is
// on top, onOut(j, name) may transform it in place (one item in, one item out).
function me(st, x, outOrder, onOut) {
  const want = new Set(outOrder);
  const needH = outOrder.some((j) => j >= 4);
  const g = [], h = [];
  // pair phase: shallowest pair first
  const todo = [0, 1, 2, 3];
  while (todo.length) {
    todo.sort((i, j) => Math.max(st.depth(x[i]), st.depth(x[i + 4])) - Math.max(st.depth(x[j]), st.depth(x[j + 4])));
    const i = todo.shift();
    st.roll(x[i]); st.roll(x[i + 4]);
    if (needH) {   // [a b] 2DUP ADD ROT OVER ADD ROT ROT ADD -> [g h]
      st.raw(['2DUP', 'ADD', 'ROT', 'OVER', 'ADD', 'ROT', 'ROT', 'ADD'], 2, [g[i] = nm('g'), h[i] = nm('h')]);
    } else {       // [a b] OVER ADD ADD -> [2a + b]
      st.raw(['OVER', 'ADD', 'ADD'], 2, [g[i] = nm('g')]);
    }
  }
  // uses: remaining uses of each item (the current one included); the last use rolls instead of picking
  const uses = new Map();
  const use = (n) => uses.set(n, (uses.get(n) ?? 0) + 1);
  const get = (n) => { const u = uses.get(n) - 1; uses.set(n, u); st.get(n, u > 0); };
  // out = a + k*b (k = 1 or 2); operands already on top are consumed in place on their last use
  const add = (a, b, k, out) => {
    const onTop = (n) => st.top() === n, on1 = (n) => st.top(1) === n, lastUse = (n) => uses.get(n) === 1;
    if (k === 1 && lastUse(a) && lastUse(b) && ((onTop(a) && on1(b)) || (onTop(b) && on1(a)))) {
      uses.set(a, 0); uses.set(b, 0); st.op('ADD', 2, out); return out;
    }
    if (k === 1 && lastUse(a) && onTop(a)) { uses.set(a, 0); get(b); st.op('ADD', 2, out); return out; }
    if (k === 1 && lastUse(b) && onTop(b)) { uses.set(b, 0); get(a); st.op('ADD', 2, out); return out; }
    get(b); if (k === 2) st.op(['DUP', 'ADD'], 1, nm('t2'));
    get(a); st.op('ADD', 2, out); return out;
  };
  const outs = [];
  const blocks = [[g, 0, outOrder.some((j) => j < 4)], [h, 4, needH]].filter((x) => x[2]);
  if (OPT.m4 === 'sum') {
    // y_i = V + v_i + 2 v_{i+1}, V = sum v (copies)
    const sums = {};
    for (const [v, off] of blocks) {
      st.pick(v[0]); for (let i = 1; i < 4; i++) { st.pick(v[i]); st.op('ADD', 2, nm('acc')); }
      st.rename(st.top(), sums[off] = nm('V'));
    }
    for (const j of outOrder) { const v = j < 4 ? g : h, i = j % 4; use(v[i]); use(v[(i + 1) % 4]); use(sums[j - i]); }
    for (const j of outOrder) {
      const v = j < 4 ? g : h, i = j % 4;
      get(v[(i + 1) % 4]); st.op(['DUP', 'ADD'], 1, nm('t'));
      get(v[i]); st.op('ADD', 2, nm('t'));
      get(sums[j - i]); st.op('ADD', 2, nm('y'));
      onOut(j, st.top()); outs[j] = st.top();
    }
  } else {
    // Plonky3's M4 chain (10 additions): t01, t23, t0123 = t01 + t23, t01123 = t0123 + v1, t01233 = t0123 + v3;
    // y0 = t01123 + t01, y1 = t01123 + 2 v2, y2 = t01233 + t23, y3 = t01233 + 2 v0
    const plan = [], T = {};
    for (const [v, off] of blocks) {
      const q = T[off] = Object.fromEntries(['t01', 't23', 't0123', 't01123', 't01233'].map((k) => [k, nm(k)]));
      plan.push([q.t01, v[0], v[1], 1], [q.t23, v[2], v[3], 1], [q.t0123, q.t01, q.t23, 1], [q.t01123, q.t0123, v[1], 1], [q.t01233, q.t0123, v[3], 1]);
    }
    const outPlan = (j) => { const q = T[j - (j % 4)], v = j < 4 ? g : h; return [[q.t01123, q.t01, 1], [q.t01123, v[2], 2], [q.t01233, q.t23, 1], [q.t01233, v[0], 2]][j % 4]; };
    for (const [, a, b] of plan) { use(a); use(b); }
    for (const j of outOrder) { const [a, b] = outPlan(j); use(a); use(b); }
    for (const [o, a, b, k] of plan) add(a, b, k, o);
    for (const j of outOrder) { const [a, b, k] = outPlan(j); const y = add(a, b, k, nm('y')); onOut(j, y); outs[j] = y; }
  }
  // anything not consumed (only when fewer outputs than inputs were asked for)
  for (const n of [...st.st]) if (/^(g|h|V|t01|t23|t0123|t01123|t01233)\./.test(n) && !outs.includes(n)) st.drop(n);
  void want;
  return outs;
}

// Emit one permutation. The 8 input lanes x[0..7] (names on st, any position, canonical or at least non-negative
// and < 2^70) are consumed; returns the output names (8 or the first `out` = 4), left on top in order 0..out-1
// (lane 0 deepest), each canonical.
export function genPerm(st, x, {out = 8} = {}) {
  const pairOrder = [0, 4, 1, 5, 2, 6, 3, 7];
  // initial ME; its outputs get round 0 (rc + S-box)
  let lanes = me(st, x, pairOrder, (j) => sbox(st, EI[0][j]));
  for (let r = 0; r < 4; r++) {
    const last = r === 3;
    // after the last initial ME: lane 0 gets partial round 0's S-box, lanes 1..7 are left as they are; lane 0 on top
    lanes = me(st, lanes, last ? [1, 2, 3, 4, 5, 6, 7, 0] : pairOrder, (j) => {
      if (!last) sbox(st, EI[r + 1][j]);
      else if (j === 0) sbox(st, RI[0]);
    });
  }
  // partial rounds: stack [x1..x7 z0], z0 = lane 0 after its S-box
  for (let r = 0; r < 22; r++) {
    if (r > 0) { st.roll(lanes[0]); sbox(st, RI[r], [P, 'MOD']); }    // x0 is unreduced (S + d0 z0): reduce first
    // S = sum of the 8 lanes
    if (OPT.psum === '3dup') {   // [.. x6 x7 z0] 3DUP ADD ADD, then the other five lanes
      st.raw(['3DUP', 'ADD', 'ADD'], 0, [nm('acc')]);
      for (let i = 5; i >= 1; i--) { st.pick(lanes[i]); st.op('ADD', 2, nm('acc')); }
    } else {
      st.pick(lanes[0]);
      for (let i = 7; i >= 1; i--) { st.pick(lanes[i]); st.op('ADD', 2, nm('acc')); }
    }
    const S = nm('S'); st.rename(st.top(), S);
    const ny = [];
    for (const i of [1, 2, 3, 4, 5, 6, 7, 0]) {
      st.roll(lanes[i]);
      const c = small(DG[i]);
      if (c === null) st.emit(DG[i], 'MUL', P, 'MOD');
      else if (c !== 1n) st.emit(c, 'MUL');
      st.pick(S); st.op('ADD', 2, ny[i] = nm('x'));
    }
    st.drop(S);
    lanes = ny;
  }
  // final full rounds; entering lanes may be negative and large: <p> MOD, + p + rc -> positive
  for (const j of pairOrder) { st.roll(lanes[j]); sbox(st, EF[0][j] + P, [P, 'MOD']); }
  for (let r = 0; r < 4; r++) {
    const last = r === 3;
    const order = last ? [...Array(out).keys()] : pairOrder;
    lanes = me(st, lanes, order, (j) => (last ? st.emit(P, 'MOD') : sbox(st, EF[r + 1][j])));
  }
  return lanes.slice(0, out);
}

// standalone permutation bytecode: expects the 8 inputs on the stack (lane 0 deepest), leaves the outputs (lane 0
// deepest)
export function permCode({out = 8} = {}) {
  const x = [...Array(8)].map((_, i) => `in${i}`);
  const st = new Stk(x);
  const o = genPerm(st, x, {out});
  if (st.st.length !== out || o.some((n, i) => st.st[i] !== n)) throw new Error('perm: bad final stack ' + st.st.join(','));
  return st.bytes();
}
export {asm};
