// Honest witness for the single-input script: slope stream, X, WS/WQ (SI), in push order.
import {verifyPlonk, msmWitness, le32, be32} from './plonk.mjs';
import {proveSI, chains} from './si.mjs';
import {nibbles} from './gt.mjs';
import {r, mod} from './math.mjs';
import {SL_PIECE} from './script.mjs';

// nbPatch [byte, value] (test.mjs): value written into the nibble string NB of WS (h0 and the transcript follow), the GT factors keep the honest nibbles
export function witnessFor(vk, proofHex, pubHex, {J = 0, JR = 0, lam, fsDelta, nbPatch} = {}) {
  const V = verifyPlonk(vk, proofHex, pubHex, lam ? {lam} : {});
  if (fsDelta) { const fs = V.gt.fs.slice(); fs[fsDelta[0]] = mod(fs[fsDelta[0]] + fsDelta[1], r); V.gt = {...V.gt, ...nibbles(fs), fs: V.gt.fs}; } // test: nibbles for a wrong scalar
  if (nbPatch) { const NB = Buffer.from(V.gt.NB); NB[nbPatch[0]] = nbPatch[1]; V.gt = {...V.gt, NB}; }
  const w = msmWitness(vk, V, {J, JR});
  const S = proveSI(chains(vk), w.Pleft, w.Pright, V.uRaw, V.gt);
  const sl = w.slopes.map(le32); const pieces = [];
  for (let i = 0; i < sl.length; i += SL_PIECE) pieces.push(Buffer.concat(sl.slice(i, i + SL_PIECE)));
  const X = Buffer.concat([be32(V.lamAff[0]), be32(V.lamAff[1]), le32(V.invProd), ...w.inverses.map(le32)]);
  const PI = Buffer.concat(pubHex.map((h) => Buffer.from(h, 'hex')));
  return {V, w, S, pieces, X, PI, PROOF: Buffer.from(proofHex, 'hex'), WQ: S.WQ, WS: S.WS, accept: V.ok && S.accept && !nbPatch};
}
// pushes bottom -> top (without the redeem)
export const pushesOf = (wt, {pad} = {}) => [...wt.pieces, wt.WQ, wt.WS, wt.X, wt.PI, wt.PROOF, ...(pad !== undefined ? [pad] : [])];
