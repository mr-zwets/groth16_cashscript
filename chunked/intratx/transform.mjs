// Transform a GENERIC covenant chunk (chunked/{pairing,bls12-381}/generated/*.cash)
// into an INTRA-TRANSACTION LINKED chunk for the new verification method.
//
// Old method (covenant, multi-tx): each chunk is its own transaction; the running
// state is hash256-committed into a token NFT commitment, re-provided and re-hashed
// every step, and handed to the next transaction's input.
//
// New method (this module, single-tx): the WHOLE chunked computation is the inputs
// of ONE transaction. A chunk takes its incoming state as a raw byte blob `inBlob`
// in its own witness, and binds the chain by FORWARD-checking its successor: it
// recomputes the outgoing state and `require`s that the NEXT input's `inBlob`
// (read via tx.inputs[idx+1].unlockingBytecode introspection) equals it — exactly
// Richard's `verify arg01 == arg10`, done by byte equality. No hashing, no NFT
// commitment, and intermediate values can be ANY size (no 128-byte token limit).
//
// The arithmetic body between the old covIn/covOut is reused VERBATIM — only the
// prologue (covIn -> split inBlob into int limbs) and the epilogue (covOut ->
// rebuild outBlob + forward-check) are rewritten. So all the validated field math
// is preserved bit-for-bit.

/** minimal push header size (bytes) for a data push of `len` bytes. */
export const headerSize = (len) => (len <= 75 ? 1 : len <= 255 ? 2 : 3);

// The current cashc fork (feat/multi-returns, rebased on upstream next) has no
// `internal` keyword — reusable functions are plain top-level `function`s. Chunks
// regenerated under it never contain `internal`, but normalize defensively so a
// stale generated chunk from the old fork still transforms; idempotent.
function normalizeInternal(src) {
  return src.replace(/\binternal function\b/g, 'function');
}

const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Collect every variable name ASSIGNED in a block of source: scalar / fresh-definition targets
 * (`x =`, `int x =`) and tuple-destructure targets (`(a, int b, ...) =`). Used by the carried-suffix
 * splice to tell a genuinely carried covOut limb from one that merely REUSES an input-param name after
 * being reassigned in the body (e.g. vk_x's `rX = dx`), which is not carried. `(?!=)` skips `==`. */
function collectAssignedNames(source) {
  const names = new Set();
  for (const [, name] of source.matchAll(/\b(\w+)\s*=(?!=)/g)) {
    names.add(name);
  }
  for (const [, targetList] of source.matchAll(/\(([^)]*)\)\s*=(?!=)/g)) {
    for (const target of targetList.split(',')) {
      names.add(target.trim().replace(/^int\s+/, ''));
    }
  }
  return names;
}

/** parse `int a,int b, bytes c` -> [{type,name,unused}] (single-line signature).
 * Handles the cashc fork's `type unused name` budget-pad modifier (a 3-token param the
 * compiler drops during stack cleanup); the transform strips it (we supply our own pad). */
function parseParams(sig) {
  const inner = sig.slice(sig.indexOf('(') + 1, sig.lastIndexOf(')'));
  return inner.split(',').map((p) => p.trim()).filter(Boolean).map((p) => {
    const m = p.match(/^(\w+)\s+(?:unused\s+)?(\w+)$/);
    return { type: m[1], name: m[2], unused: /^\w+\s+unused\s+\w+$/.test(p) };
  });
}

/**
 * Transform one covenant chunk source into a linked chunk.
 *   cfg.W            default serialized limb width in bytes
 *   cfg.widthsByName optional fixed-width overrides for bounded non-field state values
 *   cfg.prime        the field prime literal (string)
 *   cfg.forward      null  -> no forward check (stage-final / terminal); for a covOut
 *                            chunk we then emit a tautological length check so the
 *                            recomputed out-limbs are still consumed (no unused vars).
 *                    object-> { cmpExpr, nextFullInLen, skip, cmpLen }
 *                      cmpExpr      bytes expr to compare (default 'outBlob')
 *                      nextFullInLen byte length of the successor input's FULL inBlob
 *                      skip          byte offset of the bound region inside that inBlob
 *                      cmpLen        byte length of the compared region
 *   cfg.covInHash    (GROUPED only) when true, prepend a covenant-IN check binding the
 *                    incoming blob to the spent token: require(tx.inputs[0].nftCommitment
 *                    == hash256(inBlob)). Used on the FIRST chunk of a non-genesis group,
 *                    where the previous group handed state forward through an NFT commitment
 *                    (= hash256 of the same full state blob) instead of a sibling witness.
 *   cfg.epilogueMode (GROUPED only) 'covout' -> instead of a forward-check, commit the
 *                    recomputed outgoing blob to the created token: require(tx.outputs[0]
 *                    .nftCommitment == hash256(outBlob)) + category continuity. Used on the
 *                    LAST chunk of a non-terminal group (it has no in-tx successor to
 *                    forward-check; it hands state to the NEXT group's tx via a token).
 *                    Undefined => legacy behavior (forward-check / terminal).
 *   cfg.nextLockingHash optional 32-byte hex hash. With epilogueMode='covout', require
 *                    output[0]'s locking bytecode to hash to this value, binding a group
 *                    hand-off to the actual first locking of the successor group.
 *   cfg.externalBindings additional byte-slice bindings from this chunk's inBlob to another
 *                    input's inBlob: [{sourceOffset,targetInputIndex,targetFullInLen,
 *                    targetOffset,length}]. targetInputIndex is transaction-local.
 *   cfg.enforceExactInputLength when true, reject inBlob values with trailing/legacy
 *                    state limbs instead of parsing only the declared prefix.
 * Returns { src, inNames, outNames|null, extras, isTerminal, inLen, outLen }.
 */
export function transformChunk(src, cfg) {
  const W = cfg.W;
  const widthOf = (name) => cfg.widthsByName?.[name] ?? W;
  const lines = normalizeInternal(src).split('\n');
  const sigIdx = lines.findIndex((l) => /^\s*function spend\(/.test(l));
  if (sigIdx < 0) throw new Error('no spend()');
  const params = parseParams(lines[sigIdx]);

  // covIn: the single line binding incoming state to the spent NFT commitment.
  const ciIdx = lines.findIndex((l) => l.includes('activeInputIndex].nftCommitment'));
  if (ciIdx < 0) throw new Error('no covIn');
  const inNames = [...lines[ciIdx].matchAll(/toPaddedBytes\((\w+),\s*\d+\)/g)].map((m) => m[1]);
  const inWidths = inNames.map(widthOf);
  const inSet = new Set(inNames);
  const externalBindings = cfg.externalBindings ?? [];
  const externalChecks = externalBindings.map((binding) => {
    const { sourceOffset, targetInputIndex, targetFullInLen, targetOffset, length } = binding;
    const values = [sourceOffset, targetInputIndex, targetFullInLen, targetOffset, length];
    if (!values.every(Number.isSafeInteger) || values.some((value) => value < 0) || length === 0) {
      throw new Error(`invalid external binding: ${JSON.stringify(binding)}`);
    }
    if (sourceOffset + length > inWidths.reduce((sum, width) => sum + width, 0) || targetOffset + length > targetFullInLen) {
      throw new Error(`external binding outside input blob: ${JSON.stringify(binding)}`);
    }
    const source = sourceOffset === 0 ? 'inBlob' : `inBlob.split(${sourceOffset})[1]`;
    const targetStart = headerSize(targetFullInLen) + targetOffset;
    const target = `tx.inputs[${targetInputIndex}].unlockingBytecode.split(${targetStart})[1]`;
    return `        require(${source}.split(${length})[0] == ${target}.split(${length})[0]);`;
  });
  // extras = real spend params that are neither incoming-state limbs nor the dropped budget
  // pad (e.g. vk_x's zInv). The `unused` budget pad is stripped — we supply our own pad.
  const extras = params.filter((p) => !inSet.has(p.name) && !p.unused);

  // locate the spend function's closing brace (track depth from the signature line).
  let depth = 0, closeIdx = -1;
  for (let i = sigIdx; i < lines.length; i++) {
    depth += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
    if (i > sigIdx && depth === 0) { closeIdx = i; break; }
  }
  if (closeIdx < 0) throw new Error('no spend close');

  // covOut: the line committing outgoing state to output[0] (absent on terminal chunks).
  const coIdx = lines.findIndex((l, i) => i > ciIdx && i < closeIdx && l.includes('tx.outputs[0].nftCommitment'));
  const isTerminal = coIdx < 0;

  const header = lines.slice(0, sigIdx);
  const tail = lines.slice(closeIdx + 1); // contract closing brace etc.

  // new signature: extras first (pushed last), inBlob last (pushed FIRST -> front of
  // the unlocking bytecode, so a sibling's forward-check reads it at a fixed offset).
  const newSig = `    function spend(${[...extras.map((e) => `${e.type} ${e.name}`), 'bytes inBlob'].join(', ')}) {`;

  let outNames = null, outWidths = null, outLen = 0;
  let body, epilogue;
  if (isTerminal) {
    // keep the math + terminal asserts (e.g. finalExp result == ONE) verbatim.
    body = lines.slice(ciIdx + 1, closeIdx);
    epilogue = externalChecks;
  } else {
    // the reducing modulus is declared locally as `int P =` or (lazy-lib chunks) `int Pmod =`
    // on the line before covOut; either way drop that line and the covOut from the body.
    const hasIntP = /^int P(mod)? =/.test(lines[coIdx - 1].trim());
    body = lines.slice(ciIdx + 1, hasIntP ? coIdx - 1 : coIdx);
    const outMatches = [...lines[coIdx].matchAll(/toPaddedBytes\((\w+)(\s*%\s*P(?:mod)?)?,\s*\d+\)/g)];
    if (outMatches.length === 0) throw new Error('no covOut limbs');
    outNames = outMatches.map((match) => match[1]);
    const exactOutputs = outMatches.map((match) => match[2] === undefined);
    outWidths = outNames.map(widthOf);
    outLen = outWidths.reduce((sum, width) => sum + width, 0);
    // local name `Pmod` (not `P`): chunks that import the shared singleton library inherit a
    // global `constant P`, and `int P` would collide with it (same reason the lazy-lib covOut
    // uses Pmod). Non-importing chunks have no global P either way, so Pmod is always safe.
    //
    // CARRIED-SUFFIX SPLICE: a trailing run of output limbs that are the SAME variables at the SAME
    // offsets as the incoming limbs is, by definition, passed through unchanged — and already sits in
    // inBlob, byte-identical and reduced (the previous covOut wrote it with % Pmod; the genesis build
    // provides reduced state; arithmetic is mod P so a downstream consumer is value-invariant). Splice
    // that suffix straight from inBlob instead of re-serialising each limb with toPaddedBytes, and (via
    // the `used` scan below, which now no longer sees those names) skip materialising any of them the
    // body never reads. Requires equal in/out lengths so the inBlob byte offset lines up with outBlob.
    // A covOut limb whose name is also an input param but is ASSIGNED anywhere in the body is NOT
    // carried — its value changed, so it must be re-serialised, not spliced (e.g. vk_x's `rX = dx`).
    const assigned = collectAssignedNames(body.join('\n'));
    let carry = outNames.length;
    if (inNames.length === outNames.length) {
      while (carry > 0 && inNames[carry - 1] === outNames[carry - 1] &&
        inWidths[carry - 1] === outWidths[carry - 1] && !assigned.has(outNames[carry - 1])) carry -= 1;
    }
    const headExpr = outNames.slice(0, carry).map((n, i) =>
      `toPaddedBytes(${n}${exactOutputs[i] ? '' : ' % Pmod'}, ${outWidths[i]})`).join(' + ');
    const tailOffset = outWidths.slice(0, carry).reduce((sum, width) => sum + width, 0);
    const tailExpr = carry < outNames.length ? `inBlob.split(${tailOffset})[1]` : '';
    const outBlobExpr = [headExpr, tailExpr].filter(Boolean).join(' + ');
    epilogue = [
      // Pmod is only referenced when at least one recomputed head limb still needs reduction.
      ...(exactOutputs.slice(0, carry).some((exact) => !exact) ? [`        int Pmod = ${cfg.prime};`] : []),
      `        bytes outBlob = ${outBlobExpr};`,
    ];
    if (cfg.epilogueMode === 'covout') {
      // GROUPED: this is the LAST chunk of a non-terminal group. There is no in-tx
      // successor to forward-check; commit the outgoing state to the created token, which
      // the NEXT group's first chunk binds via covInHash. Category continuity keeps the
      // thread on the same token (the token rides input[0] of this group's tx).
      epilogue.push(
        `        require(tx.outputs[0].nftCommitment == hash256(outBlob));`,
        `        require(tx.outputs[0].tokenCategory == tx.inputs[0].tokenCategory);`,
      );
      if (cfg.nextLockingHash !== undefined) {
        if (!/^[0-9a-f]{64}$/i.test(cfg.nextLockingHash)) throw new Error('invalid nextLockingHash');
        epilogue.push(`        require(hash256(tx.outputs[0].lockingBytecode) == 0x${cfg.nextLockingHash});`);
      }
    } else if (cfg.forward) {
      const f = cfg.forward;
      const cmp = f.cmpExpr ?? 'outBlob';
      const off = headerSize(f.nextFullInLen) + f.skip;
      epilogue.push(
        `        require(${cmp} == tx.inputs[this.activeInputIndex + 1].unlockingBytecode.split(${off})[1].split(${f.cmpLen})[0]);`,
      );
    } else {
      // stage-final: no successor with a matching layout. Consume outBlob (the boundary
      // / vk_x result) with an always-true size check so the recomputation still runs.
      epilogue.push(`        require(outBlob.length == ${outLen});`);
    }
    epilogue.push(...externalChecks);
  }

  // prologue: peel the incoming limbs out of inBlob and cast to int. Only names
  // actually referenced downstream are bound (some chunks carry state they don't
  // read, e.g. g2check's A,C in the final chunk — declaring those would be an
  // unused-var error). The peel is SEQUENTIAL (one OP_SPLIT per limb on a shrinking
  // tail) rather than a fresh full-blob split per limb, which roughly thirds the
  // OP_SPLIT op-cost on the wide final-exponentiation chunks. Unread limbs before the
  // last read one are still split past (to advance the cursor); trailing unread limbs
  // are simply not peeled.
  const usedText = [...body, ...epilogue].join('\n');
  const used = inNames.map((nm) => new RegExp(`\\b${nm}\\b`).test(usedText));
  let maxUsed = -1;
  used.forEach((u, p) => { if (u) maxUsed = p; });
  const inLen = inWidths.reduce((sum, width) => sum + width, 0);
  const prologue = cfg.enforceExactInputLength ? [`        require(inBlob.length == ${inLen});`] : [];
  // GROUPED: a non-genesis group's first chunk binds its incoming blob to the spent token's
  // NFT commitment (= hash256 of the same full state the previous group committed via covout).
  if (cfg.covInHash) prologue.push(`        require(tx.inputs[0].nftCommitment == hash256(inBlob));`);
  let cur = 'inBlob';
  for (let p = 0; p <= maxUsed; p++) {
    const nm = inNames[p];
    const width = inWidths[p];
    if (p === maxUsed) {
      // last limb to read: if it's the very last in the blob, `cur` IS that limb.
      prologue.push(p === inNames.length - 1 ? `        int ${nm} = int(${cur});` : `        int ${nm} = int(${cur}.split(${width})[0]);`);
    } else if (used[p]) {
      prologue.push(`        bytes hh${p}, bytes rr${p} = ${cur}.split(${width}); int ${nm} = int(hh${p});`);
      cur = `rr${p}`;
    } else {
      prologue.push(`        bytes rr${p} = ${cur}.split(${width})[1];`);
      cur = `rr${p}`;
    }
  }

  const out = [...header, newSig, ...prologue, ...body, ...epilogue, '    }', ...tail].join('\n');
  return {
    src: out,
    inNames,
    outNames,
    extras: extras.map((e) => e.name),
    isTerminal,
    inLen,
    outLen,
  };
}
