// Honest witness for the single-input script: slope stream, X, WS/WQ (SI), in push order.
import {verifyPlonk, msmWitness, le32, be32} from './plonk.mjs';
import {proveSI, chains} from './si.mjs';
import {SL_PIECE} from './script.mjs';

export function witnessFor(vk, proofHex, pubHex, {J = 0, JR = 0, lam} = {}) {
  const V = verifyPlonk(vk, proofHex, pubHex, lam ? {lam} : {});
  const w = msmWitness(vk, V, {J, JR});
  const S = proveSI(chains(vk), w.Pleft, w.Pright, V.uRaw);
  const sl = w.slopes.map(le32); const pieces = [];
  for (let i = 0; i < sl.length; i += SL_PIECE) pieces.push(Buffer.concat(sl.slice(i, i + SL_PIECE)));
  const X = Buffer.concat([be32(V.lamAff[0]), be32(V.lamAff[1]), le32(V.invProd), ...w.inverses.map(le32)]);
  const PI = Buffer.concat(pubHex.map((h) => Buffer.from(h, 'hex')));
  return {V, w, S, pieces, X, PI, PROOF: Buffer.from(proofHex, 'hex'), WQ: S.WQ, WS: S.WS, accept: V.ok && S.accept};
}
// pushes bottom -> top (without the redeem)
export const pushesOf = (wt, {pad} = {}) => [...wt.pieces, wt.WQ, wt.WS, wt.X, wt.PI, wt.PROOF, ...(pad !== undefined ? [pad] : [])];
