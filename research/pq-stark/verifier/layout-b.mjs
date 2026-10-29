// Layout (b): one P2SH32 input whose redeem is the whole verifier (functions via OP_DEFINE); unlocking = the witness
// of model.mjs encodeB in the push order of gen.mjs `init`, then the redeem.
import {readFileSync} from 'node:fs';
import {vkxFromVector, encodeB, applyTamper} from './model.mjs';
import {build, redeemOf} from './gen.mjs';
import {p2sh32, pushes} from './vm.mjs';

export function loadVector(path) {
  const v = JSON.parse(readFileSync(path, 'utf8'));
  return {v, vk: vkxFromVector(v), proof: Buffer.from(v.proof_hex, 'hex'), pis: v.public_values.map(BigInt)};
}
export const casesOf = (v) => [{name: 'valid', proof: Buffer.from(v.proof_hex, 'hex'), pis: v.public_values.map(BigInt), expect: true},
  ...(v.tampered ?? []).map((t) => ({name: t.name, proof: Buffer.from(applyTamper(v.proof_hex, t), 'hex'), pis: (t.public_values ?? v.public_values).map(BigInt), expect: false}))];

const cache = new Map();
export function program(vk, pis, opts = {}) {
  const {pad, ...o} = opts; void pad;
  const key = JSON.stringify([vk.air, vk.logN, vk.Q, vk.logBlowup, vk.logArities, vk.L, vk.h, vk.zk, vk.D, vk.bpow, vk.cpow, vk.qpow, vk.rc, vk.salt, pis.map(String), o]);
  if (!cache.has(key)) {
    const built = build(vk, pis, o);
    const redeem = redeemOf(built);
    cache.set(key, {built, redeem, locking: p2sh32(redeem)});
  }
  return cache.get(key);
}

// witness items in push order (bottom first), matching gen.mjs `init`
export function witnessItems(vk, enc, opts = {}) {
  const RG = opts.recGroup ?? 2;
  const L = []; for (let q = vk.Q - 1; q >= 0; q--) L.push(enc.L[q]);
  const groups = enc.records.flatMap((recs) => Array.from({length: Math.ceil(vk.Q / RG)}, (_, g) => Buffer.concat(recs.slice(g * RG, g * RG + RG))));
  const pt = enc.PT;
  return [...L, ...groups, pt.ROOTS, pt.OOD, ...(vk.bpow ? [pt.BPOW] : []), pt.FROOTS, ...(vk.cpow ? [pt.CPOW] : []), pt.FIN, ...(vk.qpow ? [pt.QPOW] : [])];
}

export function spendB(vk, pisProgram, proof, pisProof, opts = {}, mutate) {
  const pg = program(vk, pisProgram, opts);
  const enc = encodeB(vk, proof, pisProof);
  let items = witnessItems(vk, enc, opts);
  if (opts.padSlot) items.push(Buffer.alloc(opts.pad ?? 0));
  if (mutate) items = mutate(items, enc);
  const unlocking = pushes([...items, pg.redeem]);
  return {...pg, enc, items, unlocking};
}
