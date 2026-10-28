/*
 * Reviewed auxiliary transport for the historical 51-slot minop witness ABI.
 * It is declaration-order data only: it is not a prover, producer, compiler,
 * or VM runner. The six upper Fp12 limbs of the embedded Fp6 witness are
 * removed only after their existing script-number values decode to zero.
 */
const removed = [40, 41, 42, 43, 44, 45];

const scriptNumber = bytes => {
  if (bytes.length === 0) return 0n;
  let magnitude = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    let byte = bytes[index];
    if (index === bytes.length - 1) byte &= 0x7f;
    magnitude = (magnitude << 8n) | BigInt(byte);
  }
  return (bytes[bytes.length - 1] & 0x80) === 0 ? magnitude : -magnitude;
};

/** Project declaration-order [proof, inputs, c, cInv, w0..w11, GLV, zInv]. */
export const project51To45 = args => {
  if (args.length !== 51) throw new Error(`expected 51 arguments, got ${args.length}`);
  const upperFp6 = removed.map(index => args[index]);
  if (upperFp6.some(bytes => scriptNumber(bytes) !== 0n)) {
    throw new Error('refusing to drop nonzero w6..w11');
  }
  return args.filter((_, index) => !removed.includes(index));
};

export const removedWitnessIndexes = removed;
