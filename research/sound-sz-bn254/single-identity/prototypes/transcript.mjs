// Transcript, witness parsing and terminal kernels, measured on bch-spec (standard).
//  - fixed-width encodings (reviewer fix 1): every state is one 192-byte push (6 x 32-byte LE words),
//    Q is pushed as blobs of 32-byte LE words, nibble strings are 65 bytes; lengths are checked.
//  - h0 = hash chain over fixed-width items; rho = SHA256(h0||"rho") || 0x00 -> BIN2NUM -> mod p (reviewer fix 4)
//  - z = SHA256(h0 || rho || Q-blob-chain) likewise; z != 0.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {Asm} from './asm.mjs';
import {OP, P, pushNum, runBody, Kernel, measureKernel} from './dsl.mjs';
import {encodeDataPush} from '@bitauth/libauth';
const md = (x) => ((x % P) + P) % P;
let ctr = 0; const rnd = () => BigInt('0x' + createHash('sha256').update('tr:' + ctr++).digest('hex')) % P;
const le32 = (x) => { const b = Buffer.alloc(32); let v = x; for (let i = 0; i < 32; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
const sha = (b) => createHash('sha256').update(b).digest();
const out = {};

// (1) absorb pass: h <- SHA256(h || blob_i) for 33 state blobs (each 192 B, length-checked), blobs stay on the stack
{
  const NS = 33; const blobs = Array.from({length: NS}, () => Buffer.concat(Array.from({length: 6}, () => le32(rnd()))));
  const names = [...blobs.map((_, i) => `S${NS - 1 - i}`), 'h']; // S0 on top (used first)
  const vals = [...blobs.slice().reverse(), sha(Buffer.from('tag'))];
  const a = new Asm(names);
  for (let i = 0; i < NS; i++) { a.pick(`S${i}`, 'x').op(OP.SIZE, 1, 'x', 'sz').push(192n).op(OP.NUMEQUALVERIFY, 2); a.roll('h').roll('x').bin(OP.CAT, 'hx').op(OP.SHA256, 1, 'h'); }
  // SIZE leaves item + size: fix symbolic stack (x, sz) -> handled by rename above; verify by run
  let h = vals.at(-1); for (let i = 0; i < NS; i++) h = sha(Buffer.concat([h, blobs[i]]));
  a.roll('h'); // on top
  const code = Uint8Array.from([...a.code, ...encodeDataPush(h), OP.EQUALVERIFY]);
  const op = runBody(code, vals, [], {remain: NS});
  out.absorbStates = {opCost: op, perState: Math.round(op / NS), bytes: a.code.length};
  console.log('absorb 33 state blobs (size check + hash chain):', op, 'op, per state', Math.round(op / NS), ';', a.code.length, 'B unrolled (loopable)');
}
// (2) parse one state blob into 6 numbers (5 SPLIT + 6 BIN2NUM), in the order the state kernel wants
{
  const words = Array.from({length: 6}, rnd); const blob = Buffer.concat(words.map(le32));
  const a = new Asm(['S']);
  for (let j = 0; j < 5; j++) { a.push(32n).op(OP.SPLIT, 2, `w${j}`, 'rest').roll(`w${j}`).op(OP.BIN2NUM, 1, `s${j}`).roll('rest'); }
  a.op(OP.BIN2NUM, 1, 's5');
  const op = runBody(a.bytes(), [blob], words, {exact: true});
  out.parseState = {opCost: op, bytes: a.code.length};
  console.log('parse 192-B state blob -> 6 numbers:', op, 'op', a.code.length, 'B');
}
// (3) Q: n words in blobs of W words (high coefficient first), each blob size-checked and absorbed into
// z's hash chain, then split word by word into a Horner x4 accumulator (unrolled here; a loop in the script).
for (const W of [4, 8, 52]) {
  const n = 104; const q = Array.from({length: n}, rnd);
  const blobs = []; for (let i = 0; i < n; i += W) blobs.push(Buffer.concat(q.slice(i, i + W).map(le32)));
  const z2 = rnd(), z4 = md(z2 * z2), z6 = md(z4 * z2), z8 = md(z4 * z4);
  const names = ['p', 'z2', 'z4', 'z6', 'z8', ...blobs.map((_, i) => `Q${blobs.length - 1 - i}`), 'h'];
  const a = new Asm(names);
  a.push(0n, 'acc');
  let w = 0;
  for (let b = 0; b < blobs.length; b++) {
    a.roll(`Q${b}`).op(OP.SIZE, 1, `Q${b}`, 'sz').push(BigInt(32 * W)).op(OP.NUMEQUALVERIFY, 2);
    a.pick(`Q${b}`, 'x').roll('h').roll('x').bin(OP.CAT, 'hx').op(OP.SHA256, 1, 'h');
    for (let it = 0; it < W / 4; it++) {
      for (let j = 0; j < 4; j++) {
        if (j === 3 && it === W / 4 - 1) { a.roll(`Q${b}`).op(OP.BIN2NUM, 1, `q${j}`); continue; }
        a.roll(`Q${b}`).push(32n).op(OP.SPLIT, 2, `w${j}`, `Q${b}`).roll(`w${j}`).op(OP.BIN2NUM, 1, `q${j}`);
      }
      a.roll('acc').pick('z8').bin(OP.MUL, 't').roll('q0').pick('z6').bin(OP.MUL, 'u').bin(OP.ADD, 't').roll('q1').pick('z4').bin(OP.MUL, 'u').bin(OP.ADD, 't')
        .roll('q2').pick('z2').bin(OP.MUL, 'u').bin(OP.ADD, 't').roll('q3').bin(OP.ADD, 't').pick('p').bin(OP.MOD, 'acc');
    }
  }
  let acc = 0n; for (const c of q) acc = md(acc * z2 + c);
  let h = sha(Buffer.from('x')); for (const bl of blobs) h = sha(Buffer.concat([h, bl]));
  a.roll('h'); a.emit(...encodeDataPush(h), OP.EQUALVERIFY); a.st.pop();
  a.arrange(['acc']);
  const op = runBody(a.bytes(), [P, z2, z4, z6, z8, ...blobs.slice().reverse(), sha(Buffer.from('x'))], [acc], {remain: 5});
  out['quotient_W' + W] = {opCost: op, words: n, perWord: Math.round(op / n), blobs: blobs.length, pushOverheadBytes: blobs.length * (32 * W > 255 ? 3 : 2)};
  console.log(`Q: ${n} words in blobs of ${W}: absorb+parse+Horner`, op, 'op, per word', Math.round(op / n), ', push headers', blobs.length * (32 * W > 255 ? 3 : 2), 'B');
}
// (4) challenge derivation: rho = BIN2NUM(SHA256(h0 || "rho") || 0x00) mod p
{
  const a = new Asm(['p', 'h0']);
  a.pick('h0').pushBytes(Buffer.from('rho'), 'tag', (b) => [...encodeDataPush(b)]).bin(OP.CAT).op(OP.SHA256, 1, 'd')
    .pushBytes(Buffer.from([0]), 'z', (b) => [...encodeDataPush(b)]).bin(OP.CAT).op(OP.BIN2NUM, 1, 'n').pick('p').bin(OP.MOD, 'rho');
  const h0 = sha(Buffer.from('h0'));
  const d = sha(Buffer.concat([h0, Buffer.from('rho')])); let v = 0n; for (let i = 31; i >= 0; i--) v = v * 256n + BigInt(d[i]);
  const op = runBody(a.bytes(), [P, h0], [v % P], {exact: true, remain: 2});
  out.challenge = {opCost: op, bytes: a.code.length};
  console.log('challenge derivation (unsigned):', op, 'op', a.code.length, 'B');
}
// (5) terminal: Frob(S_c) evaluated at +-x (x = z and x = eta z): Fr1(x) = (s0 + 18 - x^6) + sum_j s_j (alpha_j x^j + beta_j x^{j+6})
{
  const k = new Kernel(['p', 'x', 'x2', 'x3', 'x4', 'x5', 'x6', 'a1', 'a2', 'a3', 'a4', 'a5', 'b1', 'b2', 'b3', 'b4', 'b5'], ['s0', 's1', 's2', 's3', 's4', 's5']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k), m = k.mod.bind(k), add = k.add.bind(k);
  const kap = (j) => m(mul(E(j === 1 ? 'x' : 'x' + j), add(E('a' + j), mul(E('b' + j), E('x6'))))); // x^j (alpha_j + beta_j x^6)
  const ev = m(k.sum(I('s0'), k.c(18n), k.neg(E('x6')), mul(I('s2'), kap(2)), mul(I('s4'), kap(4))));
  const od = m(k.sum(mul(I('s1'), kap(1)), mul(I('s3'), kap(3)), mul(I('s5'), kap(5))));
  k.output([k.add(ev, od), k.sub(ev, od)]);
  const mm = measureKernel(k, [P, ...Array.from({length: 16}, rnd)], Array.from({length: 6}, rnd), {iters: 4000, label: 'Frob(S_c) at +-x'});
  out.frobSc = {opCost: mm.opCost, bytes: mm.bytes, uses: 2};
  console.log(mm.label, mm.opCost, 'op', mm.bytes, 'B (x2: x = z, eta z)');
}
// (6) Fp2 constant multiplication (psi maps, endpoint) and Fp2 mul (endpoint cross-multiplication)
{
  const k = new Kernel(['p', 'k0', 'k1'], ['a0', 'a1']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k), m = k.mod.bind(k);
  k.output([m(k.sub(mul(I('a0'), E('k0')), mul(I('a1'), E('k1')))), m(k.add(mul(I('a0'), E('k1')), mul(I('a1'), E('k0'))))]);
  const mm = measureKernel(k, [P, rnd(), rnd()], [rnd(), rnd()], {iters: 2000, label: 'Fp2 x const'});
  out.fp2Const = {opCost: mm.opCost, bytes: mm.bytes};
  console.log(mm.label, mm.opCost, 'op', mm.bytes, 'B');
}
writeFileSync(new URL('./transcript.json', import.meta.url), JSON.stringify(out, null, 1));
