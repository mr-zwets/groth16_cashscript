// debug: run the redeem up to a STOP label on the committed proof and print named stack values
import {buildPartial} from './script.mjs';
import {bare, encodeUnlocking} from './vm.mjs';
import {vmNumberToBigInt} from '@bitauth/libauth';
import {VEC, mod} from './math.mjs';
import {prove} from './protocol.mjs';
const label = process.argv[2]; const w = prove({proof: VEC.proof, publicInputs: VEC.publicInputs});
const {code, names} = buildPartial(label); const res = bare(code, [w.W]);
console.log('error', res.error, 'op', res.opCost, 'depth', res.stack.length, 'names', names.length);
const want = (process.argv[3] ?? '').split(',').filter(Boolean);
names.forEach((n, i) => { if (!want.length || want.includes(n)) { const v = res.stack[i]; console.log(n.padEnd(8), v ? mod(vmNumberToBigInt(v, {requireMinimalEncoding: false})).toString(16).slice(0, 20) : '?'); } });
console.log('prover V', w.V.x.toString(16).slice(0, 20), w.V.y.toString(16).slice(0, 20));
