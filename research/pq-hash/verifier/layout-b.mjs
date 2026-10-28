// Layout (b): one P2SH32 input whose redeem is the whole verifier (functions via OP_DEFINE), unlocking = the
// witness of model.mjs encodeB in the push order of gen.mjs.
import {readFileSync} from 'node:fs';
import {makeParams} from './params.mjs';
import {encodeB} from './model.mjs';
import {buildB, redeemB} from './gen.mjs';
import {p2sh32, pushes} from './vm.mjs';

export function loadVector(path) {
  const v = JSON.parse(readFileSync(path, 'utf8'));
  return {v, prm: makeParams(v.params), proof: Buffer.from(v.proof, 'hex')};
}

const cache = new Map();
export function program(prm, statement, opts = {}) {
  const {pad, ...o} = opts; void pad;
  const key = prm.name + Buffer.from(statement).toString('hex') + JSON.stringify(o);
  if (!cache.has(key)) {
    const built = buildB(prm, statement, o);
    const redeem = redeemB(built);
    cache.set(key, {built, redeem, locking: p2sh32(redeem)});
  }
  return cache.get(key);
}

// witness items in push order (bottom first), matching gen.mjs `init`
export function witnessItems(prm, enc) {
  return [...enc.records.flat(), ...enc.leafBlobs, ...enc.pt.slice(1)];   // statement baked into the code
}

export function spendB(prm, statement, proof, opts = {}, mutate) {
  const pg = program(prm, statement, opts);
  const enc = encodeB(prm, proof);
  let items = witnessItems(prm, enc);
  if (opts.padSlot) items.push(new Uint8Array(opts.pad ?? 0));
  if (mutate) items = mutate(items, enc);
  const unlocking = pushes([...items, pg.redeem]);
  return {...pg, enc, items, unlocking};
}
