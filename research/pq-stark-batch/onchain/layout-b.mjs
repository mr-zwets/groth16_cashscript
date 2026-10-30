// Layout (b): one P2SH32 input whose redeem is the whole verifier (functions via OP_DEFINE); unlocking = the witness
// of model.mjs encodeB in the push order of gen.mjs `init`, then the redeem. The spending transaction's outputs fix
// CTX (ctx.mjs); in the harness variant (opts.ctx = 'witness') CTX is a witness item instead.
import {readFileSync} from 'node:fs';
import {vkxFromVector, encodeB, applyTamper, le8} from './model.mjs';
import {build, redeemOf} from './gen.mjs';
import {p2sh32, pushes, spendProgram} from './vm.mjs';

const exact = (k, x, ctx) => (typeof x === 'number' && !Number.isSafeInteger(x) ? JSON.rawJSON(ctx.source) : x);
export const readVector = (path) => JSON.parse(readFileSync(path, 'utf8'), exact);
export function loadVector(path) {
  const v = readVector(path);
  return {v, vk: vkxFromVector(v), proof: Buffer.from(v.proof_hex, 'hex'), pis: v.public_values.flat().map(BigInt)};
}
export const stmtOf = (pis) => ({root: pis.slice(0, 4), nf: pis.slice(4, 8), ctx: pis.slice(8, 12)});

const cache = new Map();
// the script: verifying key + statement constant ROOT (+ the CTX source)
export function program(vk, root, opts = {}) {
  const {pad, ...o} = opts; void pad;
  const key = JSON.stringify([vk.SO.batch.toString('hex'), vk.Q, vk.logArities, vk.L, vk.bpow, vk.cpow, vk.qpow, vk.zk, root.map(String), o]);
  if (!cache.has(key)) {
    if (root.length !== 4 || root.some((x) => x < 0n || x >= 0xffffffff00000001n)) throw new Error('generator: ROOT must be 4 canonical elements');
    const built = build(vk, {root}, o);
    const redeem = redeemOf(built);
    cache.set(key, {built, redeem, locking: p2sh32(redeem)});
  }
  return cache.get(key);
}

// witness items in push order (bottom first), matching gen.mjs `init`
export function witnessItems(vk, enc, nf, ctxw, opts = {}) {
  const RG = opts.recGroup ?? 2;
  const L = []; for (let q = vk.Q - 1; q >= 0; q--) L.push(enc.L[q]);
  const groups = enc.records.flatMap((recs) => Array.from({length: Math.ceil(vk.Q / RG)}, (_, g) => Buffer.concat(recs.slice(g * RG, g * RG + RG))));
  const pt = enc.PT;
  return [...L, ...groups, pt.ROOTS, pt.OOD, ...(vk.bpow ? [pt.BPOW] : []), pt.FROOTS, ...(vk.cpow ? [pt.CPOW] : []), pt.FIN, ...(vk.qpow ? [pt.QPOW] : []),
    Buffer.concat(nf.map((x) => le8(x & ((1n << 64n) - 1n)))), ...(opts.ctx === 'witness' ? [ctxw] : [])];
}

// spend: script for `root`; witness from `proof` with the prover-side statement `pisProof` (12 values: what the
// encoder uses for the transcript; NF from it is pushed); `outputs` of the spending transaction
export function spendB(vk, root, proof, pisProof, outputs, opts = {}, mutate) {
  const pg = program(vk, root, opts);
  const enc = encodeB(vk, proof, pisProof.map((x) => ((x % (1n << 64n)) + (1n << 64n)) % (1n << 64n)));
  const ctxw = Buffer.concat(pisProof.slice(8, 12).map((x) => le8(x & ((1n << 64n) - 1n))));
  let items = witnessItems(vk, enc, pisProof.slice(4, 8), ctxw, opts);
  if (opts.padSlot) items.push(Buffer.alloc(opts.pad ?? 0));
  if (mutate) items = mutate(items, enc);
  const unlocking = pushes([...items, pg.redeem]);
  return {...pg, enc, items, unlocking, prog: spendProgram(pg.locking, unlocking, outputs)};
}
export {applyTamper};
