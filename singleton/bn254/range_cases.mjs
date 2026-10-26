// Non-canonical proof-coordinate cases for the BN254 singleton (groth16.cash spend ABI:
// spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1)). Each case takes a VALID proof and replaces one
// coordinate v by v + P or v - P: the same point mod P, so a verifier without the 0 <= v < P
// range checks accepts it (encoding malleability). groth16.cash must reject every case.
// Shared by build_vectors_groth16.mjs (ships them as `rangeInvalid`) and range_checks_test.mjs.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  bigIntToVmNumber, encodeDataPush, decodeAuthenticationInstructions, vmNumberToBigInt, binToHex, hexToBin,
} from '@bitauth/libauth';

export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const COORDS = ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy'];

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
export const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// inverse of unlockingFor: unlocking hex -> [Ax..Cy, in0, in1]
export const argsFromUnlocking = (hex) => decodeAuthenticationInstructions(hexToBin(hex))
  .map((ins) => {
    if (ins.data !== undefined) return vmNumberToBigInt(ins.data, { requireMinimalEncoding: false });
    if (ins.opcode === 0x00) return 0n;
    if (ins.opcode >= 0x51 && ins.opcode <= 0x60) return BigInt(ins.opcode - 0x50);
    if (ins.opcode === 0x4f) return -1n;
    throw new Error(`unexpected opcode ${ins.opcode}`);
  })
  .reverse();

// committed instance (bench src/checkpoints/pairing-vectors.json) as spend args
export const committedArgs = (benchDir) => {
  const vec = JSON.parse(readFileSync(join(benchDir, 'src/checkpoints/pairing-vectors.json'), 'utf8'));
  const A = vec.proof.a, B = vec.proof.b, C = vec.proof.c;
  return [A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y, ...vec.publicInputs].map(BigInt);
};

const shift = (args, i, d) => args.map((a, j) => (j === i ? a + d : a));

// every coordinate of the committed proof at +P and -P (16 cases), plus two on the
// n0 = n1 = 0 zero-input proof when its vectors are available (A at +P, B at -P)
export const rangeRejectCases = (benchDir) => {
  const base = committedArgs(benchDir);
  const cases = [];
  COORDS.forEach((c, i) => {
    cases.push({ label: `${c} + p`, args: shift(base, i, P) });
    cases.push({ label: `${c} - p`, args: shift(base, i, -P) });
  });
  let zero = null;
  try { zero = JSON.parse(readFileSync(join(benchDir, 'src/bch/groth16-singleton-zero-input-vectors.json'), 'utf8')); } catch { /* absent */ }
  const z = zero?.proofs.find((p) => p.label === 'n0 = n1 = 0');
  if (z) {
    const za = argsFromUnlocking(z.unlocking);
    if (binToHex(unlockingFor(za)) !== z.unlocking) throw new Error('zero-input unlocking round-trip mismatch');
    cases.push({ label: 'zero-input (n0 = n1 = 0) Ay + p', args: shift(za, 1, P) });
    cases.push({ label: 'zero-input (n0 = n1 = 0) Byb - p', args: shift(za, 5, -P) });
  }
  return cases;
};
