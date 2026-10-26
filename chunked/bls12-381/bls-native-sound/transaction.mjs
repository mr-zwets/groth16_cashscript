// The deployed program (redeem.hex = R, program.hex = the blob; produced by build.mjs) and the transaction construction.
import {readFileSync} from 'node:fs';
import {prove, txPushes, ROLES} from './protocol.mjs';
import {p2sh32, txOf, unlockingsFor, encodeUnlocking} from './vm.mjs';
export const R = Buffer.from(readFileSync(new URL('./redeem.hex', import.meta.url), 'utf8').trim(), 'hex');
export const blob = Buffer.from(readFileSync(new URL('./program.hex', import.meta.url), 'utf8').trim(), 'hex');
export const locking = Buffer.from(p2sh32(R));
export const LABELS = ROLES.map((ro, i) => (i === 0 ? `in0: head (transcript, statement, binding, quotient) + Miller events ${ro.e0}-${ro.e1}` : `in${i}: Miller events ${ro.e0}-${ro.e1}${ro.last ? ' + terminal' : ''}`));
export const CHECKPOINTS = ['head', 'miller-1', 'miller-2', 'terminal'];
// pushes per input (before R) for a fixture; unlockings; the evaluation context
export const pushesFor = (fx, opts) => { const w = prove(fx, opts); return {w, pushes: txPushes(w, blob)}; };
export const unlockingsOf = (pushes) => unlockingsFor(pushes, R);
export const ctxOf = (unlockings) => txOf(unlockings, unlockings.map(() => locking));
export const encodeWith = (pushes, redeem = R) => encodeUnlocking([...pushes, redeem]);
