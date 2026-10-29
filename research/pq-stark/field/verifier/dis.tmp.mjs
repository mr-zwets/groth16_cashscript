import {disassembleBytecodeBch} from '@bitauth/libauth';
import {loadVector, program} from './layout-b.mjs';
const {prm, proof} = loadVector(process.argv[2]);
const pg = program(prm, proof.subarray(0, 16), JSON.parse(process.argv[4] ?? '{}'));
const f = pg.built.fns.get(process.argv[3]);
console.log(f.body.length, 'B'); console.log(disassembleBytecodeBch(f.body).replace(/OP_/g, '').replace(/0x[0-9a-f]{16,}/g, (m)=>'C'+(m.length/2-1)));
