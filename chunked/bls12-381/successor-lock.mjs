import { encodeDataPush, hash256 } from '@bitauth/libauth';

// Bind one compiled redeem to its exact successor without recompiling or
// rewriting the existing CashScript program. The terminal has no successor
// condition in the standalone vk_x graph.
export function bindSuccessor(redeem, nextLocking) {
  if (nextLocking === undefined) return Uint8Array.from(redeem);
  const successorHash = encodeDataPush(hash256(nextLocking));
  return Uint8Array.from([0x00, 0xcd, 0xaa, ...successorHash, 0x88, ...redeem]);
}

// Build a standalone successor graph from bare compiled redeem bytes. The
// returned bytes preserve each original redeem as an exact suffix and are
// suitable for both source generation and frozen-artifact repair.
export function buildSuccessorLockings(bareLockings) {
  if (!Array.isArray(bareLockings) || bareLockings.length === 0) throw new Error('successor graph requires at least one locking');
  const bound = new Array(bareLockings.length);
  let nextLocking;
  for (let i = bareLockings.length - 1; i >= 0; i--) {
    const bare = bareLockings[i];
    if (!(bare instanceof Uint8Array)) throw new TypeError(`locking ${i} is not a Uint8Array`);
    bound[i] = bindSuccessor(bare, nextLocking);
    nextLocking = bound[i];
  }
  return bound;
}

