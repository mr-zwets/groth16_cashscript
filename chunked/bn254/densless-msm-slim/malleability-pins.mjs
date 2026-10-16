// Slim-only malleability pins (asm). Prepended to the densless half of the TERMINAL carrier only
// (paid once). densless-recovered untouched.
//
// Closes: trailing-byte length holes (header/quot), terminal witness order (10 limbs),
// fixed-table sign bits (all three executors).
import { OpcodesBCH, encodeDataPush, bigIntToVmNumber } from '@bitauth/libauth';

const pushN = (n) => Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(n))));
const op = (...xs) => Buffer.from(xs);
const cat = (...bufs) => Buffer.concat(bufs);
export const redeemPushBytes = (length) => length + (length < 76 ? 1 : length < 256 ? 2 : 3);

/** Sign-check subroutine id — must not collide with densless fragment/loader ids. */
const SIGN_FN = 150;

export function canonicalizeLimbs(buf) {
  const out = Buffer.from(buf);
  for (let i = 31; i < out.length; i += 32) out[i] &= 0x7f;
  return out;
}

/** Sort by unsigned BE value of the limb (matches on-chain order pin). */
export function sortLimbsBE(list) {
  return [...list].sort((a, b) => {
    const aN = BigInt('0x' + Buffer.from(a).reverse().toString('hex'));
    const bN = BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
    return aN < bN ? -1 : aN > bN ? 1 : 0;
  });
}

function skipPush(len) {
  const h = len < 76 ? 1 : len < 256 ? 2 : 3;
  return cat(pushN(h + len), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP));
}

function requirePushData2Len(len) {
  const le = Buffer.alloc(2); le.writeUInt16LE(len);
  return cat(
    op(OpcodesBCH.OP_DUP), pushN(3), op(OpcodesBCH.OP_SPLIT),
    op(OpcodesBCH.OP_SWAP),
    Buffer.from(encodeDataPush(Buffer.concat([Buffer.from([0x4d]), le]))),
    op(OpcodesBCH.OP_EQUALVERIFY),
    op(OpcodesBCH.OP_NIP),
    pushN(len), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
  );
}

function extract32KeepRest() {
  return cat(
    pushN(1), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
    pushN(32), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_SWAP),
  );
}

/** One-limb sign check body: table-rest on stack → consume 32 B, VERIFY bit7 clear. */
function signLimbBody() {
  return cat(
    pushN(32), op(OpcodesBCH.OP_SPLIT),
    op(OpcodesBCH.OP_SWAP),
    pushN(31), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
    encodeDataPush(Uint8Array.of(0x80)), op(OpcodesBCH.OP_AND),
    encodeDataPush(Uint8Array.of(0x00)), op(OpcodesBCH.OP_EQUALVERIFY),
  );
}

function defineSignFn() {
  return cat(
    Buffer.from(encodeDataPush(signLimbBody())),
    pushN(SIGN_FN),
    op(OpcodesBCH.OP_DEFINE),
  );
}

function invokeSignFn() {
  return cat(pushN(SIGN_FN), op(OpcodesBCH.OP_INVOKE));
}

function pinOneExecTable(inputIdx, shared, witness, table, { signs = true, quot = true } = {}) {
  const th = table < 256 ? 2 : 3;
  const parts = [
    pushN(inputIdx), op(OpcodesBCH.OP_INPUTBYTECODE),
    skipPush(296), skipPush(shared), skipPush(witness),
    pushN(th), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
    pushN(table), op(OpcodesBCH.OP_SPLIT),
    op(OpcodesBCH.OP_TOALTSTACK), // rest on alt; table on stack
  ];
  if (signs) {
    const limbs = table / 32;
    for (let i = 0; i < limbs; i++) parts.push(invokeSignFn());
    parts.push(op(OpcodesBCH.OP_DROP));
  } else {
    parts.push(op(OpcodesBCH.OP_DROP)); // drop table unchecked
  }
  parts.push(op(OpcodesBCH.OP_FROMALTSTACK));
  if (quot) {
    parts.push(cat(
      op(OpcodesBCH.OP_DUP), pushN(3), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_SWAP),
      Buffer.from(encodeDataPush(Buffer.from([0x4d, 0xe0, 0x04]))),
      op(OpcodesBCH.OP_EQUALVERIFY),
      op(OpcodesBCH.OP_NIP),
      pushN(1248), op(OpcodesBCH.OP_SPLIT),
      op(OpcodesBCH.OP_DROP),
      op(OpcodesBCH.OP_DROP),
    ));
  } else {
    parts.push(op(OpcodesBCH.OP_DROP));
  }
  return cat(...parts);
}

function pinOwnHeaderQuotAndOrder(ordered) {
  const parts = [
    op(OpcodesBCH.OP_INPUTINDEX), op(OpcodesBCH.OP_INPUTBYTECODE),
    requirePushData2Len(296),
    requirePushData2Len(2336),
  ];
  // Order by unsigned LE value = BIN2NUM(limb) with sign bit clear (canonicalizeLimbs).
  // No REVERSEBYTES/CAT: 33-byte VM numbers break densless on the loosened harness VM.
  parts.push(extract32KeepRest(), op(OpcodesBCH.OP_TOALTSTACK));
  for (let i = 1; i < ordered; i++) {
    parts.push(cat(
      extract32KeepRest(), // [rest][curr]
      op(OpcodesBCH.OP_DUP), op(OpcodesBCH.OP_FROMALTSTACK), // [rest][curr][curr][prev]
      op(OpcodesBCH.OP_BIN2NUM), // [rest][curr][curr][prevNum]
      op(OpcodesBCH.OP_SWAP), // [rest][curr][prevNum][curr]
      op(OpcodesBCH.OP_BIN2NUM), // [rest][curr][prevNum][currNum]
      op(OpcodesBCH.OP_SWAP), // [rest][curr][currNum][prevNum] — need prev<=curr
      op(OpcodesBCH.OP_SWAP), // [rest][curr][prevNum][currNum]
      op(OpcodesBCH.OP_LESSTHANOREQUAL), op(OpcodesBCH.OP_VERIFY),
      op(OpcodesBCH.OP_TOALTSTACK), // curr limb
    ));
  }
  parts.push(op(OpcodesBCH.OP_DROP), op(OpcodesBCH.OP_FROMALTSTACK), op(OpcodesBCH.OP_DROP));
  return cat(...parts);
}

export function compileTerminalPins(layoutExec, ordered = 10) {
  return cat(
    defineSignFn(),
    pinOwnHeaderQuotAndOrder(ordered),
    pinOneExecTable(0, layoutExec[0].shared, layoutExec[0].witness, layoutExec[0].table),
    pinOneExecTable(1, layoutExec[1].shared, layoutExec[1].witness, layoutExec[1].table),
    pinOneExecTable(2, layoutExec[2].shared, layoutExec[2].witness, layoutExec[2].table),
  );
}

export function compileTerminalPinsLite(ordered = 10) {
  return pinOwnHeaderQuotAndOrder(ordered);
}

export function compileTerminalPinsLenOrder(layoutExec, ordered = 10) {
  const parts = [pinOwnHeaderQuotAndOrder(ordered)];
  for (let i = 0; i < 3; i++) {
    const { shared, witness, table } = layoutExec[i];
    parts.push(pinOneExecTable(i, shared, witness, table, { signs: false, quot: true }));
  }
  return cat(...parts);
}

export function compileTerminalPinsLenOnly() {
  return cat(
    op(OpcodesBCH.OP_INPUTINDEX), op(OpcodesBCH.OP_INPUTBYTECODE),
    requirePushData2Len(296),
    requirePushData2Len(2336),
    op(OpcodesBCH.OP_DROP),
  );
}

export function compileTerminalPinsOrderOnly(ordered = 10) {
  return pinOwnHeaderQuotAndOrder(ordered);
}

export function compileTerminalPinsLenSign(layoutExec) {
  return cat(
    defineSignFn(),
    op(OpcodesBCH.OP_INPUTINDEX), op(OpcodesBCH.OP_INPUTBYTECODE),
    requirePushData2Len(296),
    requirePushData2Len(2336),
    op(OpcodesBCH.OP_DROP),
    pinOneExecTable(0, layoutExec[0].shared, layoutExec[0].witness, layoutExec[0].table),
    pinOneExecTable(1, layoutExec[1].shared, layoutExec[1].witness, layoutExec[1].table),
    pinOneExecTable(2, layoutExec[2].shared, layoutExec[2].witness, layoutExec[2].table),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const layout = [
    { shared: 867, witness: 2560, table: 928 },
    { shared: 982, witness: 2304, table: 832 },
    { shared: 559, witness: 2560, table: 928 },
  ];
  console.log('lenonly', compileTerminalPinsLenOnly().length);
  console.log('orderonly', compileTerminalPinsOrderOnly().length);
  console.log('lenorder', compileTerminalPinsLenOrder(layout).length);
  console.log('lensign', compileTerminalPinsLenSign(layout).length);
  console.log('full', compileTerminalPins(layout).length);
}
