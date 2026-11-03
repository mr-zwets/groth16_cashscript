// Track 12: the example application's fixed parameters (shared by pinned-test.mjs and example.mjs).
import {sha} from './pv.mjs';
const H = (s) => sha(Buffer.from(s)).toString('hex');
// which deployment a proof is for (a constant of the covenant code, committed in PV)
export const INSTANCE = H('verifier.cash/track12/example-instance/v1');
// TEST-key program identities (any field element / any 32 bytes): the real guest's vkey / image id is printed by the
// guest hosts (`vkey` / `imageid`) and was NOT available here (no zkVM toolchain could be installed)
export const TEST_PROGRAM_VKEY = '0x00' + H('verifier.cash/track12/test-program').slice(2);
export const TEST_IMAGE_ID = H('verifier.cash/track12/test-image');
export const P2PKH = (b) => '76a914' + b.repeat(20) + '88ac';
// the example statement: pay 200,000 sat to a P2PKH and add a 0-sat OP_RETURN memo. REGTEST / CHIPNET ONLY: the payout
// hash160 (0x11 x 20) has no known key (the coins are burned) and INSTANCE above is public.
export const OUTS = [{lockingBytecode: P2PKH('11'), valueSatoshis: 200000n}, {lockingBytecode: '6a' + '0b' + Buffer.from('track12 pay').toString('hex'), valueSatoshis: 0n}];
// the example guest's LOCK_HASH preimage (guest/shared/pv.rs): a PUBLIC string, so anyone can prove for any outputs
export const EXAMPLE_SECRET_HEX = Buffer.from('verifier.cash track12 example secret: REPLACE with >=128 random bits').toString('hex');
export const EXAMPLE_LOCK_HASH = '99a364f66b31c63e9f7413d84a752e065825a6befa6d026eed90070c8e7836bf';
