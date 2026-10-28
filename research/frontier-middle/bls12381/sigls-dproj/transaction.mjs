// The deployed program (redeem.hex, produced by build.mjs) and unlocking construction.
import {readFileSync} from 'node:fs';
import {prove} from './protocol.mjs';
import {p2sh32, unlockingFor} from './vm.mjs';
export const redeem = Buffer.from(readFileSync(new URL('./redeem.hex', import.meta.url), 'utf8').trim(), 'hex');
export const locking = Buffer.from(p2sh32(redeem));
// pushes in unlocking order: [WQ, WS, redeem]
export const pushesFor = (fx, opts) => { const w = prove(fx, opts); return {w, pushes: [w.WQ, w.WS, redeem]}; };
export const unlocking = (fx, opts) => { const w = prove(fx, opts); return {w, unlocking: Buffer.from(unlockingFor(w.WS, w.WQ, redeem))}; };
