// One source owner for the immutable ordered P2SH32 worker-locking commitment.
export const workerBindingSource = (digest, totalInputs) => [
  ...Array.from({ length: totalInputs - 1 }, (_, index) =>
    `        require(tx.inputs[${index + 1}].lockingBytecode.length==35);`),
  `        bytes siblingLockings=${Array.from({ length: totalInputs - 1 },
    (_, index) => `tx.inputs[${index + 1}].lockingBytecode`).join('+')};`,
  `        require(sha256(siblingLockings)==0x${Buffer.from(digest).toString('hex')});`,
];
