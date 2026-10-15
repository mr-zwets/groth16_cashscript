// The same executor loader serves all three inputs. Its commitment is derived
// from the emitted shared program. Function -1 is a loader-local extraction
// helper; build.mjs emits its declaration before this body. It uses
// OP_1NEGATE as its one-byte encoded key and does not collide with the shared
// module's positive IDs. Function 100
// consumes the assembled shared body.
export const executor = `
  OP_DROP OP_DROP OP_SWAP OP_DROP OP_SWAP
  NUM FRAGMENT_0_BYTES OP_0 CALL fragmentReader
  NUM FRAGMENT_1_BYTES OP_1 CALL fragmentReader
  NUM FRAGMENT_2_BYTES OP_2 CALL fragmentReader
  OP_CAT OP_CAT OP_DUP OP_HASH256 DATA sharedHash256 OP_EQUALVERIFY
  DEFINE_STACK sharedProgram CALL sharedProgram
`;

// Input stack contract: [fragmentLength, inputIndex], with inputIndex on top.
// The helper returns only the selected prefix and leaves the alternate stack
// unchanged. The final DROP discards the suffix, not the retained prefix.
export const fragmentReader = `
  OP_INPUTBYTECODE NUM FRAGMENT_OFFSET OP_SPLIT OP_NIP
  OP_SWAP OP_SPLIT OP_DROP
`;

export const p2sh = 'OP_HASH256 DATA redeemHash256 OP_EQUAL';
