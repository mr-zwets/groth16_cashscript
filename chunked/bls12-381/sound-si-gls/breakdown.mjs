// Byte breakdown of the redeem: data pushes (by kind) vs code, including function bodies (defined in the prologue).
//   node breakdown.mjs
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {redeem} from './transaction.mjs';
const out = {deltaSlopePile: 0, fieldConstants: 0, otherData: 0, code: 0};
const walk = (bytes, top) => {
  const ins = decodeAuthenticationInstructions(bytes);
  ins.forEach((x, i) => {
    const n = encodeAuthenticationInstruction(x).length, d = x.data;
    if (top && d && ins[i + 2]?.opcode === 0x89) { out.code += n - d.length; walk(d, false); return; } // function body
    if (d && d.length === 384) out.deltaSlopePile += n;
    else if (d && d.length >= 47 && d.length <= 49) out.fieldConstants += n;
    else if (d && d.length > 4) out.otherData += n;
    else out.code += n;
  });
};
walk(redeem, true);
console.log(JSON.stringify({redeem: redeem.length, ...out}));
