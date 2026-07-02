// Shared emission post-pass: hoist duplicated big constants in a generated contract's
// spend() body into locals declared at the top of the body, so each repeated 18-49-byte
// literal is pushed once and stack-picked thereafter. Byte-saving and op-cost-neutral
// (picking an item costs about the same as re-pushing it — same reason the singleton
// libs bind their primes to a local, e.g. subFp's `int p = P;`).
//
// Only decimal literals of >= 18 digits are considered (below that the pick indirection
// stops paying for itself), and only when a literal occurs >= 2 times in the body.

/** Rewrite `src` (a full generated .cash source) hoisting duplicated spend-body constants. */
export function hoistSpendConstants(src) {
  const spendIdx = src.indexOf('function spend');
  if (spendIdx < 0) return src;
  let bodyStart = src.indexOf('\n', src.indexOf('{', spendIdx)) + 1;
  if (bodyStart <= 0) return src;
  // Covenant chunks: declare AFTER the covIn require — intratx/grouped's transformChunk
  // keeps only the lines between covIn and covOut, so a declaration above covIn would be
  // dropped by the transform and leave dangling references.
  const covInIdx = src.indexOf('activeInputIndex].nftCommitment', bodyStart);
  if (covInIdx >= 0) bodyStart = src.indexOf('\n', covInIdx) + 1;
  const head = src.slice(0, bodyStart);
  let body = src.slice(bodyStart);

  const counts = new Map();
  for (const m of body.matchAll(/\b\d{18,}\b/g)) counts.set(m[0], (counts.get(m[0]) || 0) + 1);
  const dups = [...counts.entries()].filter(([, count]) => count >= 2).map(([lit]) => lit);
  if (dups.length === 0) return src;

  const decls = dups.map((lit, n) => {
    body = body.replace(new RegExp(`\\b${lit}\\b`, 'g'), `hc${n}`);
    return `        int hc${n} = ${lit};`;
  });
  return head + decls.join('\n') + '\n' + body;
}
