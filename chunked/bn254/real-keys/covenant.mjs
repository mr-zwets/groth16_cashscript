// Track 11: covenant binding of the public inputs (one worked example per system).
//
// The plain verifier (bn-native-sound) proves "(A, B, C, n0, n1) satisfies Groth16 for the baked VK" for whatever
// n0, n1 the prover writes into STMT. A covenant that RELEASES value must say which statement it accepts: it must
// derive n0 and n1 itself, from constants in its code and from transaction data, and require that the decoded n0, n1
// equal them. This module adds exactly that to role 2 (the role that owns STMT and runs the binding), via the
// setCovenant hook of ../bn-native-sound/script.mjs, right after STMT is decoded and range-checked (< r):
//
//   SP1 v5     n0 == PROGRAM_VKEY                     (a 32-byte constant in the code, pinned by K_code)
//              n1 == sha256(PV) & (2^253 - 1)         (computed on-chain, SP1VerifierGroth16.hashPublicValues)
//   RISC Zero  (n0, n1) == splitDigest(claimDigest)   claimDigest = ReceiptClaimLib.ok(IMAGE_ID, sha256(PV)).digest()
//                                                      (IMAGE_ID a constant; three SHA256 on-chain)
//
// where PV (the SP1 public values / the RISC Zero journal) is carried by the transaction itself: output 0 must be
// exactly OP_RETURN <push PV> with |PV| = PV_LEN (a build parameter). An application would read PV wherever its
// logic needs it (outputs, another input's data, a token commitment) and also act on its content (e.g. check that a
// payout output pays the amount and address that PV names); the OP_RETURN form is the smallest complete example.
// The rest of the verifier is unchanged: n0, n1 still enter the GT-GLS binding mod r (the vk_x MSM over exactly these
// two inputs), and a proof for any other statement fails there.
import assert from 'node:assert/strict';
import {encodeDataPush} from '@bitauth/libauth';
import {OP} from '../bn-native-sound/asm.mjs';
import {buildProgram, setCovenant} from '../bn-native-sound/script.mjs';
import {setOutputs} from '../bn-native-sound/vm.mjs';
import {sha} from './claims.mjs';

const OUTPUTBYTECODE = 0xcd, REVERSEBYTES = 0xbc;
export const opReturnOf = (pv) => Uint8Array.from([0x6a, ...encodeDataPush(Uint8Array.from(pv))]);
const tag = (s) => sha(Buffer.from(s));

// the application parameters, taken from the key's fixture 0 (the "application" of this example)
export function covenantParams(FIXTURES) {
  const fx = FIXTURES.fixtures[0];
  if (fx.programVKey) return {kind: 'sp1', programVKey: fx.programVKey, pvLen: fx.publicValuesHex.length / 2, app: fx.id};
  return {kind: 'risc0', imageId: fx.imageId, pvLen: fx.journalHex.length / 2, app: fx.id};
}
export const pvOf = (fx) => Buffer.from(fx.publicValuesHex ?? fx.journalHex, 'hex');

export function covenantHook(P) {
  const pre = Buffer.from(opReturnOf(Buffer.alloc(P.pvLen)).subarray(0, -P.pvLen)); // 0x6a ‖ push header of PV_LEN bytes
  assert.ok(pre.length + P.pvLen <= 223, 'PV fits a standard OP_RETURN output');
  // PV from output 0: exact size, exact prefix; leaves 'pv' on top
  const pvFromOutput0 = (a) => {
    a.push(0, 'o0').op(OUTPUTBYTECODE, 1, 'ob').op(OP.SIZE, 1, 'ob', 'os').push(pre.length + P.pvLen).op(OP.NUMEQUALVERIFY, 2);
    a.push(pre.length).op(OP.SPLIT, 2, 'pre', 'pv').roll('pre').pushBytes(pre).op(OP.EQUALVERIFY, 2);
  };
  if (P.kind === 'sp1') return (a) => {
    a.pick('n0', 'k0').push(BigInt(P.programVKey), 'vk').op(OP.NUMEQUALVERIFY, 2);              // n0 == PROGRAM_VKEY
    pvFromOutput0(a);
    a.op(OP.SHA256, 1, 'h').op(REVERSEBYTES, 1, 'hl')                                           // LE(sha256(PV))
      .push(31).op(OP.SPLIT, 2, 'lo', 'hi').pushBytes([0x1f]).op(OP.AND, 2, 'hm').op(OP.CAT, 2, 'v') // & (2^253 - 1)
      .pushBytes([0x00]).op(OP.CAT, 2, 'v0').op(OP.BIN2NUM, 1, 'dg').pick('n1', 'k1').op(OP.NUMEQUALVERIFY, 2); // n1 == digest
  };
  // RISC Zero: claimDigest = SHA256(TAG_CLAIM ‖ 0^32 ‖ IMAGE_ID ‖ SYSTEM_STATE_ZERO ‖ outputDigest ‖ 0^8 ‖ 0x0400),
  // outputDigest = SHA256(TAG_OUTPUT ‖ sha256(PV) ‖ 0^32 ‖ 0x0200); (n0, n1) = (LE(cd[0:16]), LE(cd[16:32]))
  const SYS0 = Buffer.from('a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2', 'hex');
  const PREFIX = Buffer.concat([tag('risc0.ReceiptClaim'), Buffer.alloc(32), Buffer.from(P.imageId, 'hex'), SYS0]);
  return (a) => {
    pvFromOutput0(a);
    a.op(OP.SHA256, 1, 'jd').pushBytes(tag('risc0.Output'), 'to').roll('jd').op(OP.CAT, 2, 'x')
      .pushBytes(Buffer.concat([Buffer.alloc(32), Buffer.from([2, 0])])).op(OP.CAT, 2, 'x').op(OP.SHA256, 1, 'od');
    a.pushBytes(PREFIX, 'pf').roll('od').op(OP.CAT, 2, 'x').pushBytes(Buffer.concat([Buffer.alloc(8), Buffer.from([4, 0])])).op(OP.CAT, 2, 'x').op(OP.SHA256, 1, 'cd');
    a.push(16).op(OP.SPLIT, 2, 'c0', 'c1')
      .pushBytes([0x00]).op(OP.CAT, 2, 'c1x').op(OP.BIN2NUM, 1, 'v1').pick('n1', 'k1').op(OP.NUMEQUALVERIFY, 2)
      .pushBytes([0x00]).op(OP.CAT, 2, 'c0x').op(OP.BIN2NUM, 1, 'v0').pick('n0', 'k0').op(OP.NUMEQUALVERIFY, 2);
  };
}
// build the covenant program and point the runner's output 0 at the application's PV (fixture 0)
export function buildCovenantProgram(FIXTURES) {
  const P = covenantParams(FIXTURES);
  setCovenant(covenantHook(P));
  try { const prog = buildProgram(); prog.covenant = P; return prog; } finally { setCovenant(null); }
}
export const useOutputsFor = (pv) => setOutputs([{lockingBytecode: opReturnOf(pv), valueSatoshis: 0n}]);
