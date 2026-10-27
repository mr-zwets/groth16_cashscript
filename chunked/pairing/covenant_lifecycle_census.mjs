// Count token/tx introspection opcodes in every shipped covenant-residue redeem (read-only) and
// check that each redeem P2SH32-hashes to its step's locking. Usage:
//   node chunked/pairing/covenant_lifecycle_census.mjs <zk-verifier-bench>/src/bch/groth16-chunked-covenant-residue-vectors.json
// (or the BLS12-381 file groth16-bls12381-chunked-covenant-residue-vectors.json)
import { readFileSync } from 'node:fs';
import { hexToBin, binToHex, decodeAuthenticationInstructions, hash256, encodeLockingBytecodeP2sh32 } from '@bitauth/libauth';
const file = process.argv[2];
const v = JSON.parse(readFileSync(file, 'utf8'));
const NAMES = { 0xc3: 'INCNT', 0xc4: 'OUTCNT', 0xc0: 'IDX', 0xc1: 'ACTBC', 0xc7: 'UTXOBC', 0xcd: 'OUTBC', 0xce: 'UTXOCAT', 0xcf: 'UTXOCOMMIT', 0xd1: 'OUTCAT', 0xd2: 'OUTCOMMIT', 0xd0: 'UTXOAMT', 0xd3: 'OUTAMT', 0xcc: 'OUTVAL', 0xc6: 'UTXOVAL' };
v.steps.forEach((s, i) => {
  const unl = decodeAuthenticationInstructions(hexToBin(s.unlocking));
  const redeem = unl[unl.length - 1].data;
  const okP2sh = binToHex(encodeLockingBytecodeP2sh32(hash256(redeem))) === s.locking;
  const ins = decodeAuthenticationInstructions(redeem);
  const cnt = {};
  const consts = new Set();
  ins.forEach((x) => { if (NAMES[x.opcode]) cnt[NAMES[x.opcode]] = (cnt[NAMES[x.opcode]] ?? 0) + 1;
    if (x.data && (x.data.length === 33 || x.data.length === 32)) consts.add(binToHex(x.data).slice(0, 8) + '..' + binToHex(x.data).slice(-2) + '/' + x.data.length); });
  console.log(String(i).padStart(2), s.kind.padEnd(8), okP2sh ? 'p2sh-ok' : 'P2SH-MISMATCH', JSON.stringify(cnt), [...consts].join(' '));
});
