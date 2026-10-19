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

/** One owner for malleability-pin namespace selection. Defaults preserve every existing profile. */
export const defaultPinIds = Object.freeze({sign: 150, number: 151});
export const compactPinIds = Object.freeze({sign: 16, number: 12});

export function canonicalizeLimbs(buf) {
  const out = Buffer.from(buf);
  for (let i = 31; i < out.length; i += 32) out[i] &= 0x7f;
  return out;
}

/** Sort nonnegative, minimally encoded LE numbers by value (the on-chain order). */
export function sortLimbsBE(list) {
  return [...list].sort((a, b) => {
    const aN = BigInt('0x' + Buffer.from(a).reverse().toString('hex'));
    const bN = BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
    return aN < bN ? -1 : aN > bN ? 1 : 0;
  });
}

function requirePushData2Len(len) {
  const le = Buffer.alloc(2); le.writeUInt16LE(len);
  return cat(
    pushN(3), op(OpcodesBCH.OP_SPLIT),
    op(OpcodesBCH.OP_SWAP),
    Buffer.from(encodeDataPush(Buffer.concat([Buffer.from([0x4d]), le]))),
    op(OpcodesBCH.OP_EQUALVERIFY),
    pushN(len), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
  );
}

// [unlocking rest] -> [remaining pushes, number]. Nonnegative VM numbers use
// OP_0, OP_1..OP_16, or a direct push of up to 32 bytes; never a fixed width.
function numberBody() {
  return cat(
    pushN(1), op(OpcodesBCH.OP_SPLIT, OpcodesBCH.OP_SWAP),
    encodeDataPush(Uint8Array.of(0)), op(OpcodesBCH.OP_CAT, OpcodesBCH.OP_BIN2NUM),
    op(OpcodesBCH.OP_DUP), pushN(81), op(OpcodesBCH.OP_GREATERTHANOREQUAL, OpcodesBCH.OP_IF),
      op(OpcodesBCH.OP_DUP), pushN(97), op(OpcodesBCH.OP_LESSTHAN, OpcodesBCH.OP_VERIFY),
      pushN(80), op(OpcodesBCH.OP_SUB),
    op(OpcodesBCH.OP_ELSE),
      op(OpcodesBCH.OP_DUP), pushN(33), op(OpcodesBCH.OP_LESSTHAN, OpcodesBCH.OP_VERIFY),
      op(OpcodesBCH.OP_SPLIT, OpcodesBCH.OP_SWAP, OpcodesBCH.OP_BIN2NUM),
    op(OpcodesBCH.OP_ENDIF),
  );
}

function extractNumberKeepRest(ids = defaultPinIds) {
  return cat(pushN(ids.number), op(OpcodesBCH.OP_INVOKE));
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

/** Fixed table → empty: check bit7 of each limb's last byte using a 1024-byte mask. */
function signTableBody() {
  return cat(
    op(OpcodesBCH.OP_0), pushN(31), op(OpcodesBCH.OP_NUM2BIN),
    encodeDataPush(Uint8Array.of(0x80)), op(OpcodesBCH.OP_CAT),
    op(OpcodesBCH.OP_DUP, OpcodesBCH.OP_CAT,
      OpcodesBCH.OP_DUP, OpcodesBCH.OP_CAT,
      OpcodesBCH.OP_DUP, OpcodesBCH.OP_CAT,
      OpcodesBCH.OP_DUP, OpcodesBCH.OP_CAT,
      OpcodesBCH.OP_DUP, OpcodesBCH.OP_CAT),
    op(OpcodesBCH.OP_OVER, OpcodesBCH.OP_SIZE, OpcodesBCH.OP_NIP,
      OpcodesBCH.OP_SPLIT, OpcodesBCH.OP_DROP, OpcodesBCH.OP_AND),
    op(OpcodesBCH.OP_SIZE, OpcodesBCH.OP_0, OpcodesBCH.OP_SWAP,
      OpcodesBCH.OP_NUM2BIN, OpcodesBCH.OP_EQUALVERIFY, OpcodesBCH.OP_0),
  );
}

function defineSignFn(ids = defaultPinIds, batchSigns = false) {
  return cat(
    Buffer.from(encodeDataPush(batchSigns ? signTableBody() : signLimbBody())),
    pushN(ids.sign),
    op(OpcodesBCH.OP_DEFINE),
  );
}

function invokeSignFn(ids = defaultPinIds) {
  return cat(pushN(ids.sign), op(OpcodesBCH.OP_INVOKE));
}

function pinOneExecTable(inputIdx, shared, witness, table, { signs = true, quot = true, ids = defaultPinIds, batchSigns = false } = {}) {
  const th = table < 256 ? 2 : 3;
  const skip = [296, shared, witness].reduce((sum, len) => sum + redeemPushBytes(len), th);
  const parts = [
    pushN(inputIdx), op(OpcodesBCH.OP_INPUTBYTECODE),
    pushN(skip), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_NIP),
    pushN(table), op(OpcodesBCH.OP_SPLIT),
    op(OpcodesBCH.OP_TOALTSTACK), // rest on alt; table on stack
  ];
  if (signs) {
    if (batchSigns) {
      parts.push(invokeSignFn(ids));
    } else {
      const limbs = table / 32;
      for (let i = 0; i < limbs; i++) parts.push(invokeSignFn(ids));
    }
    parts.push(op(OpcodesBCH.OP_DROP));
  } else {
    parts.push(op(OpcodesBCH.OP_DROP)); // drop table unchecked
  }
  parts.push(op(OpcodesBCH.OP_FROMALTSTACK));
  if (quot) {
    parts.push(cat(
      pushN(3), op(OpcodesBCH.OP_SPLIT), op(OpcodesBCH.OP_SWAP),
      Buffer.from(encodeDataPush(Buffer.from([0x4d, 0xe0, 0x04]))),
      op(OpcodesBCH.OP_EQUALVERIFY),
      pushN(1248), op(OpcodesBCH.OP_SPLIT),
      op(OpcodesBCH.OP_DROP),
      op(OpcodesBCH.OP_DROP),
    ));
  } else {
    parts.push(op(OpcodesBCH.OP_DROP));
  }
  return cat(...parts);
}

function pinOwnHeaderQuotAndOrder(ordered, ids = defaultPinIds) {
  const numberChecks = [cat(extractNumberKeepRest(ids), op(OpcodesBCH.OP_TOALTSTACK))];
  for (let i = 1; i < ordered; i++) {
    numberChecks.push(cat(
      extractNumberKeepRest(ids), // [rest][curr]
      op(OpcodesBCH.OP_DUP), op(OpcodesBCH.OP_FROMALTSTACK), // [rest][curr][curr][prev]
      op(OpcodesBCH.OP_SWAP), // [rest][curr][prev][curr]
      op(OpcodesBCH.OP_LESSTHANOREQUAL), op(OpcodesBCH.OP_VERIFY),
      op(OpcodesBCH.OP_TOALTSTACK), // curr limb
    ));
  }
  // Fixed data pushes plus at most33bytes per canonical nonnegative number.
  // The unparsed remainder is discarded after these checks.
  const prefixBytes = 3 + 296 + 3 + 2336 + 33 * numberChecks.length;
  return cat(
    Buffer.from(encodeDataPush(numberBody())), pushN(ids.number), op(OpcodesBCH.OP_DEFINE),
    op(OpcodesBCH.OP_INPUTINDEX), op(OpcodesBCH.OP_INPUTBYTECODE),
    op(OpcodesBCH.OP_SIZE), pushN(prefixBytes),
    op(OpcodesBCH.OP_MIN, OpcodesBCH.OP_SPLIT, OpcodesBCH.OP_DROP),
    requirePushData2Len(296), requirePushData2Len(2336),
    ...numberChecks,
    op(OpcodesBCH.OP_DROP), op(OpcodesBCH.OP_FROMALTSTACK), op(OpcodesBCH.OP_DROP),
  );
}

export function compileTerminalPins(layoutExec, ordered = 10, ids = defaultPinIds, batchSigns = false) {
  return cat(
    defineSignFn(ids, batchSigns),
    pinOwnHeaderQuotAndOrder(ordered, ids),
    pinOneExecTable(0, layoutExec[0].shared, layoutExec[0].witness, layoutExec[0].table, {ids, batchSigns}),
    pinOneExecTable(1, layoutExec[1].shared, layoutExec[1].witness, layoutExec[1].table, {ids, batchSigns}),
    pinOneExecTable(2, layoutExec[2].shared, layoutExec[2].witness, layoutExec[2].table, {ids, batchSigns}),
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
