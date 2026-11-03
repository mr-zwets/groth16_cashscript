// Track 12: the program-pinned covenant template on the reviewed BN254 verifier (bn-native-sound, 3 inputs).
//
// The plain verifier proves "(A, B, C, n0, n1) satisfies Groth16 for the baked VK" for whatever n0, n1 the spender
// writes into STMT. This template adds, through bn-native-sound's setCovenant hook (Track 11; role 2, right after STMT
// is decoded and range-checked < r, before every challenge-dependent step, pinned by K_code like all other code):
//
//   1. PV is REBUILT on chain from the spending transaction (pv.mjs layout):
//        PV = TAG ‖ INSTANCE ‖ NUM2BIN(TXOUTPUTCOUNT, 1) ‖ Σ_k NUM2BIN(OUTPUTVALUE k, 8) ‖ NUM2BIN(|b_k|, 2) ‖ b_k
//      with b_k = OUTPUTBYTECODE k, and OUTPUTTOKENCATEGORY k must be empty for every k (no token outputs).
//      Also b_k != UTXOBYTECODE(INPUTINDEX) for every k: no output may pay back to this covenant's own locking, because
//      such "change" would re-fund the same INSTANCE and re-arm the (now public) proof for a replay.
//      TAG and INSTANCE are constants of the code.
//   2. The statement is derived from PV and constants only, and must equal the decoded STMT inputs:
//        SP1 v5     n0 == PROGRAM_VKEY;   n1 == LE(sha256(PV)) & (2^253 - 1)
//        RISC Zero  (n0, n1) == splitDigest(SHA256(TAG_CLAIM ‖ 0^32 ‖ IMAGE_ID ‖ SYSTEM_STATE_ZERO ‖
//                                            SHA256(TAG_OUTPUT ‖ SHA256(PV) ‖ 0^32 ‖ 0x0200) ‖ 0^8 ‖ 0x0400))
//   3. The rest is the reviewed verifier, unchanged: n0, n1 enter the GT-GLS binding of vk_x mod r.
//
// So the only statement a spend can carry is "program PROGRAM_VKEY (image IMAGE_ID) committed exactly this
// transaction's outputs for this INSTANCE". Groth16 proofs are re-randomizable; nothing here depends on proof bytes.
import assert from 'node:assert/strict';
import {OP} from '../bn-native-sound/asm.mjs';
import {buildProgram, setCovenant} from '../bn-native-sound/script.mjs';
import {PV_TAG} from './pv.mjs';
import {sha, SYSTEM_STATE_ZERO} from '../real-keys/claims.mjs';

const I = {INPUTINDEX: 0xc0, UTXOBYTECODE: 0xc7, TXOUTPUTCOUNT: 0xc4, OUTPUTVALUE: 0xcc, OUTPUTBYTECODE: 0xcd, OUTPUTTOKENCATEGORY: 0xd1}, REVERSEBYTES = 0xbc;
const tag = (s) => sha(Buffer.from(s));
const hex32 = (h) => { const b = Buffer.from(String(h).replace(/^0x/, ''), 'hex'); assert.equal(b.length, 32, '32-byte constant'); return b; };

export function checkParams(P) {
  assert.ok(P.system === 'sp1' || P.system === 'risc0', "system: 'sp1' | 'risc0'");
  hex32(P.instanceId);
  if (P.system === 'sp1') { const v = BigInt('0x' + hex32(P.programVKey).toString('hex'));
    assert.ok(v < 21888242871839275222246405745257275088548364400416034343698204186575808495617n, 'programVKey < r'); }
  else hex32(P.imageId);
  return P;
}

// rebuild PV from the transaction's outputs; leaves 'pv' on top
function pvFromOutputs(a, P) {
  a.pushBytes(Buffer.concat([PV_TAG, hex32(P.instanceId)]), 'pv');
  a.op(I.TXOUTPUTCOUNT, 0, 'nout').pick('nout', 'nc').push(1).op(OP.NUM2BIN, 2, 'nb');       // fails if n > 127
  a.roll('pv').roll('nb').op(OP.CAT, 2, 'pv');
  a.op(I.INPUTINDEX, 0, 'ix').op(I.UTXOBYTECODE, 1, 'own');                                 // this covenant's locking
  a.push(0, 'k');
  a.loop((s) => {
    s.pick('k', 'kc').op(I.OUTPUTTOKENCATEGORY, 1, 'tc').push(0, 'empty').op(OP.EQUALVERIFY, 2);  // no token on output k
    s.pick('k', 'kc').op(I.OUTPUTVALUE, 1, 'v').push(8).op(OP.NUM2BIN, 2, 'vb');                 // u64 LE
    s.pick('k', 'kc').op(I.OUTPUTBYTECODE, 1, 'lb').pick('lb', 'lc').pick('own', 'oc').op(OP.EQUAL, 2, 'eq').op(OP.NOT, 1, 'ne').op(OP.VERIFY, 1); // b_k != own locking
    s.op(OP.SIZE, 1, 'lb', 'ls').push(2).op(OP.NUM2BIN, 2, 'lsb'); // u16 LE length
    s.roll('pv').roll('vb').op(OP.CAT, 2, 'pv').roll('lsb').op(OP.CAT, 2, 'pv').roll('lb').op(OP.CAT, 2, 'pv');
    s.roll('k').op(OP.ADD1, 1, 'k').pick('k', 'kc').pick('nout', 'nc').op(OP.NUMEQUAL, 2, 'done');
  });
  a.drop('k').drop('own').drop('nout');
}

export function templateHook(P) {
  checkParams(P);
  if (P.system === 'sp1') return (a) => {
    a.pick('n0', 'k0').push(BigInt('0x' + hex32(P.programVKey).toString('hex')), 'vk').op(OP.NUMEQUALVERIFY, 2); // n0 == PROGRAM_VKEY
    pvFromOutputs(a, P);
    a.op(OP.SHA256, 1, 'h').op(REVERSEBYTES, 1, 'hl')                                                         // LE(sha256(PV))
      .push(31).op(OP.SPLIT, 2, 'lo', 'hi').pushBytes([0x1f]).op(OP.AND, 2, 'hm').op(OP.CAT, 2, 'v')           // & (2^253 - 1)
      .pushBytes([0x00]).op(OP.CAT, 2, 'v0').op(OP.BIN2NUM, 1, 'dg').pick('n1', 'k1').op(OP.NUMEQUALVERIFY, 2); // n1 == digest
  };
  const PREFIX = Buffer.concat([tag('risc0.ReceiptClaim'), Buffer.alloc(32), hex32(P.imageId), SYSTEM_STATE_ZERO]);
  return (a) => {
    pvFromOutputs(a, P);
    a.op(OP.SHA256, 1, 'jd').pushBytes(tag('risc0.Output'), 'to').roll('jd').op(OP.CAT, 2, 'x')
      .pushBytes(Buffer.concat([Buffer.alloc(32), Buffer.from([2, 0])])).op(OP.CAT, 2, 'x').op(OP.SHA256, 1, 'od');
    a.pushBytes(PREFIX, 'pf').roll('od').op(OP.CAT, 2, 'x').pushBytes(Buffer.concat([Buffer.alloc(8), Buffer.from([4, 0])])).op(OP.CAT, 2, 'x').op(OP.SHA256, 1, 'cd');
    a.push(16).op(OP.SPLIT, 2, 'c0', 'c1')
      .pushBytes([0x00]).op(OP.CAT, 2, 'c1x').op(OP.BIN2NUM, 1, 'v1').pick('n1', 'k1').op(OP.NUMEQUALVERIFY, 2)
      .pushBytes([0x00]).op(OP.CAT, 2, 'c0x').op(OP.BIN2NUM, 1, 'v0').pick('n0', 'k0').op(OP.NUMEQUALVERIFY, 2);
  };
}

// build the template program for parameters P (the verifying key is the one ../sound-si-gls/math.mjs loaded)
export function buildPinnedProgram(P) {
  setCovenant(templateHook(P));
  try { const prog = buildProgram(); prog.params = {...P}; return prog; } finally { setCovenant(null); }
}
