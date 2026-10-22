import {
  bigIntToVmNumber, encodeDataPush, OpcodesBCH as OP,
} from '@bitauth/libauth';

const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(Buffer.from)));
const pushNumber = value => encodeDataPush(bigIntToVmNumber(BigInt(value)));

// Five fixed-width arguments precede a minimally encoded PUSHDATA2 root redeem.
// This guard stays inline: ACTIVEBYTECODE must refer to the complete root script.
export const rootFrameGuard = argumentBytes => concat(
  Uint8Array.of(OP.OP_0, OP.OP_INPUTBYTECODE, OP.OP_SIZE, OP.OP_NIP,
    OP.OP_ACTIVEBYTECODE, OP.OP_SIZE, OP.OP_NIP),
  pushNumber(argumentBytes + 3), Uint8Array.of(OP.OP_ADD, OP.OP_NUMEQUALVERIFY),
);

// The root guard and fixed argument widths pin this offset independently of code size.
export const rootRedeemLoader = argumentBytes => concat(
  Uint8Array.of(OP.OP_0, OP.OP_INPUTBYTECODE), pushNumber(argumentBytes + 3),
  Uint8Array.of(OP.OP_SPLIT, OP.OP_NIP),
);
