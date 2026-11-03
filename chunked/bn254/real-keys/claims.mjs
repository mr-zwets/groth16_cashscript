// Public-input derivations of the two real systems (pure functions, no VK): how an application turns its claim into
// the 2 field elements n0, n1 that the verifier binds.
import {createHash} from 'node:crypto';

export const sha = (...b) => { const h = createHash('sha256'); for (const x of b) h.update(x); return h.digest(); };
export const le = (b) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));

// SP1 v5 (SP1VerifierGroth16.sol): n0 = uint256(programVKey), n1 = uint256(sha256(publicValues)) & (2^253 - 1)
export const MASK253 = (1n << 253n) - 1n;
export const sp1Digest = (publicValues) => BigInt('0x' + sha(publicValues).toString('hex')) & MASK253;
export const sp1Inputs = (programVKeyHex, publicValues) => [BigInt('0x' + programVKeyHex.replace(/^0x/, '')), sp1Digest(publicValues)];

// RISC Zero (RiscZeroGroth16Verifier.sol, IRiscZeroVerifier.sol): claimDigest = ReceiptClaimLib.ok(imageId, sha256(journal)).digest();
// splitDigest(d) = (LE(d[0:16]), LE(d[16:32])) -- byteswap(d) split into (low, high) 128-bit halves.
const tag = (s) => sha(Buffer.from(s));
export const SYSTEM_STATE_ZERO = Buffer.from('a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2', 'hex');
export const outputDigest = (journalDigest) => sha(tag('risc0.Output'), journalDigest, Buffer.alloc(32), Buffer.from([2, 0]));
export const claimDigest = (imageId, journal) => sha(tag('risc0.ReceiptClaim'), Buffer.alloc(32), imageId, SYSTEM_STATE_ZERO,
  outputDigest(sha(journal)), Buffer.alloc(4), Buffer.alloc(4), Buffer.from([4, 0]));
export const splitDigest = (d) => [le(d.subarray(0, 16)), le(d.subarray(16, 32))];
export const risc0Inputs = (imageIdHex, journal) => splitDigest(claimDigest(Buffer.from(imageIdHex, 'hex'), journal));
