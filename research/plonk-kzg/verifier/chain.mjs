// Today's standard rules: build the multi-input chain for a circuit, size each input's FILL from its measured
// op-cost, and spend the whole transaction on the libauth BCH 2026 VM (consensus and standard).
//   node chain.mjs <circuit> [proof index]
import {loadVectors, parseVK} from './plonk.mjs';
import {makePlan, buildMulti, multiWitness, planOpts} from './multi.mjs';
import {p2sh32, encodeUnlocking, spendTx} from './vm.mjs';
import {encodeTransaction} from '@bitauth/libauth';
export const txBytes = (tx) => encodeTransaction({version: 2, locktime: 0, inputs: tx.map((x, k) => ({outpointIndex: k, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: x.unlocking})), outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}).length;

export function chainTx(vk, plan, built, pushes, fills) {
  const locking = p2sh32(built.redeem);
  return pushes.map((ps, i) => ({locking, unlocking: encodeUnlocking([...ps, Buffer.alloc(fills?.[i] ?? 0), built.redeem])}));
}
// FILL per input: measured on the unbudgeted VM and iterated on the filled transaction (a remote read pushes the whole
// unlocking of the input it reads, so every FILL raises its readers' op-cost); 64 B slack per filled input, clamped so
// that the slack never takes an input over the 10,000 B standard unlocking limit (FILL's PUSHDATA2 header: 2 B more than
// the unfilled OP_0)
export const MAX_UNLOCKING = 10000, FILL_SLACK = 64, FILL_HDR = 2;
export const needOf = (opCost, built) => Math.ceil((opCost + built.defBytes) / 800) - 41; // BCHN-adjusted unlocking bytes the op-cost needs
export function sizeFills(vk, plan, built, pushes, {strict = true} = {}) {
  const base = chainTx(vk, plan, built, pushes, null).map((x) => x.unlocking.length); // unfilled sizes (FILL = OP_0)
  let fills = pushes.map(() => 0);
  for (let it = 0; it < 4; it++) {
    const tx = chainTx(vk, plan, built, pushes, fills); const free = spendTx('free', 'standard', tx); let changed = false;
    fills = free.map((x, i) => { if (strict && x.error && !/budget|density/.test(x.error)) throw new Error(`input ${i} (${plan.roles[i].kind}): ${x.error}`);
      const need = needOf(x.opCost, built) - base[i]; // beyond the unfilled size
      const room = MAX_UNLOCKING - base[i] - FILL_HDR;
      const f = need <= 0 ? 0 : need <= room ? Math.min(need + FILL_SLACK, room) : need + FILL_SLACK;
      if (f > fills[i]) { changed = true; return f; } return fills[i]; });
    if (!changed) break;
  }
  return fills;
}
// Liveness stress (liveness.mjs, chaintest.mjs): the chain of a valid proof with its quotient padded to nq words by
// pseudo-random nonzero high words (multiWitness nqPad), FILLs sized as for a real proof. ok: every input <= 10,000 B
// unlocking and within its BCHN-adjusted budget, the transaction <= 100,000 B, and the only failing check is the final
// identity of the last input: every other input passes, and the last one fails at its last check, i.e. in the role body
// itself (call depth 2: redeem -> C0 -> role body) with no check after the failing instruction (vm.mjs errorAt), not in a
// function or at an earlier check. nq <= the honest n_q (no padding): the honest proof, which must be accepted.
export function nqStress(vk, plan, built, proof, pub, nq) {
  const w = multiWitness(vk, plan, built, proof, pub, {nqPad: nq}); const fl = sizeFills(vk, plan, built, w.pushes, {strict: false});
  const tx = chainTx(vk, plan, built, w.pushes, fl); const res = spendTx('bch2026', 'standard', tx); const last = res.length - 1;
  const per = res.map((x, i) => ({i, role: plan.roles[i].kind, unlocking: x.unlockingLen, fill: fl[i], opBchn: x.opCost + built.defBytes, budget: x.budget, error: x.evalError}));
  const bad = per.filter((x) => x.unlocking > MAX_UNLOCKING || x.opBchn > x.budget || (x.i !== last && x.error));
  const at = res[last].errorAt;
  const finalOnly = w.S.stress ? !!res[last].evalError && /OP_VERIFY/.test(res[last].evalError) && at.depth === 2 && !at.checkAfter : res.every((x) => x.accepted);
  const tb = txBytes(tx); const worst = per.reduce((a, b) => (b.unlocking > a.unlocking ? b : a));
  return {nq, ok: !bad.length && tb <= 100000 && finalOnly, txBytes: tb, maxInput: {role: worst.role, i: worst.i, unlocking: worst.unlocking}, padded: !!w.S.stress, finalOnly, lastErrorAt: at,
    bad: bad.map((x) => `in${x.i} ${x.role} ${x.unlocking} B${x.error ? ' ' + x.error.slice(0, 60) : ''}`), lastError: res[last].evalError?.slice(0, 80), perInput: per.map(({i, error, ...x}) => x)};
}
// Digit stress (liveness.mjs, chaintest.mjs): the op-cost of an MSM input depends on its digits (zero digits are
// skipped). The stress publishes s'_q with every 5-bit chunk = 1 (digit -15: an addition and a negation in every window)
// for every base but Lambda', whose scalar 1 + t' < 2^129 has zero digits (chunk 16) in windows >= 26 and chunk 1 below;
// every MSM role's hand-over and slopes are rebuilt for these digits (multiWitness sPrime), so each MSM input runs to
// its end (ST and the first SI role then fail: G0 and P* are not the honest ones). FILLs are sized on the stressed
// transaction. ok: every MSM input passes, and its required unlocking (BCHN-adjusted op-cost / 800 - 41) plus the FILL
// header and slack is <= 10,000 B, i.e. any digit pattern fits. headroom = 10,000 - max(unfilled size, required).
export function digitStress(vk, plan, built, proof, pub, {chunk = 1} = {}) {
  const word = (q) => { let s = 0n; for (let i = 0; i < 51; i++) s += BigInt(plan.names[q] === 'Lam' && i >= 26 ? 16 : chunk) << BigInt(5 * i); return s; };
  const sPrime = Array.from({length: plan.nbm}, (_, q) => word(q));
  const w = multiWitness(vk, plan, built, proof, pub, {sPrime}); const fl = sizeFills(vk, plan, built, w.pushes, {strict: false});
  const base = chainTx(vk, plan, built, w.pushes, null).map((x) => x.unlocking.length);
  const tx = chainTx(vk, plan, built, w.pushes, fl); const free = spendTx('free', 'standard', tx); const res = spendTx('bch2026', 'standard', tx);
  const per = free.map((x, i) => { const need = needOf(x.opCost, built); const ro = plan.roles[i];
    return {i, role: ro.kind, windows: ro.hi !== undefined ? `${ro.hi}..${ro.lo}` : undefined, unfilled: base[i], need, fill: fl[i], unlocking: res[i].unlockingLen,
      headroom: MAX_UNLOCKING - Math.max(base[i], need), error: x.evalError ?? res[i].evalError}; }).filter((x) => x.role === 'MJ' || x.role === 'MA');
  const bad = per.filter((x) => x.error || x.unlocking > MAX_UNLOCKING || (x.need > x.unfilled && x.need + FILL_HDR + FILL_SLACK > MAX_UNLOCKING));
  const mj = per.filter((x) => x.role === 'MJ'); const worst = mj.reduce((a, b) => (b.headroom < a.headroom ? b : a));
  return {chunk, ok: !bad.length, worstMJ: {i: worst.i, need: worst.need, unfilled: worst.unfilled, headroom: worst.headroom},
    bad: bad.map((x) => `in${x.i} ${x.role} need ${x.need} unlocking ${x.unlocking}${x.error ? ' ' + x.error.slice(0, 60) : ''}`), perInput: per};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [c = 'mul2', pi = '0'] = process.argv.slice(2);
  const d = loadVectors(c); const vk = parseVK(d.vk.hex);
  const plan = makePlan(vk, planOpts(vk, c)); const built = buildMulti(vk, plan);
  console.log('code blob', built.code.length, 'redeem', built.redeem.length, 'roles', plan.roles.map((r) => r.kind).join(','), 'bodies', built.bodies.join(','));
  const w = multiWitness(vk, plan, built, d.valid[Number(pi)].proof, d.valid[Number(pi)].publicInputs);
  const fills = sizeFills(vk, plan, built, w.pushes);
  const tx = chainTx(vk, plan, built, w.pushes, fills);
  for (const mode of ['consensus', 'standard']) {
    const res = spendTx('bch2026', mode, tx);
    console.log(mode, res.every((x) => x.accepted) ? 'ACCEPTED' : 'REJECTED');
    res.forEach((x, i) => console.log(`  in${i} ${plan.roles[i].kind.padEnd(2)} unlocking ${x.unlockingLen} fill ${fills[i]} op ${x.opCost} / ${x.budget} ${x.accepted ? '' : x.error}`));
  }
  console.log('total unlocking', tx.reduce((s, x) => s + x.unlocking.length, 0), 'tx bytes', txBytes(tx));
}
