// Semantics-preserving size reductions on the merged program (ir.mjs form). Each one only
// changes where instructions live, never which instructions execute in which order:
//  - poolConstants: a data push repeated across the programs becomes a function that pushes
//    it (OP_INVOKE of a body consisting of that one push is that push);
//  - dedupe: functions whose fully inlined instruction streams are identical are merged
//    (e.g. the base-field constant and mulmod helpers each of the former programs defined);
//  - inlineCheap: a function whose definition costs more than it saves is inlined.
// The stack audit (stack-audit.mjs) runs on the result.
import {OpcodesBCH, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {isPush} from './ir.mjs';

const insHex = (x) => Buffer.from(encodeAuthenticationInstruction(x)).toString('hex');
const isDynamic = (body) => body !== undefined && body.length > 0 && body[0].opcode === OpcodesBCH.OP_INVOKE && body[0].call === undefined;

export function poolConstants(defs, main, minLength = 8) {
  const counts = new Map();
  const scan = (b) => b.forEach((x) => { if (isPush(x) && x.data && x.data.length >= minLength) { const h = Buffer.from(x.data).toString('hex'); counts.set(h, (counts.get(h) ?? 0) + 1); } });
  defs.forEach(scan); scan(main);
  const pooled = new Set([...counts].filter(([h, n]) => n * (h.length / 2 + 1) > (h.length / 2 + 1) + 4 + n * 2).map(([h]) => h));
  const rewrite = (b) => b.map((x) => (isPush(x) && x.data && pooled.has(Buffer.from(x.data).toString('hex')) ? {call: `k:${Buffer.from(x.data).toString('hex')}`} : x));
  for (const [k, b] of defs) defs.set(k, rewrite(b));
  const out = rewrite(main);
  for (const h of pooled) defs.set(`k:${h}`, [{opcode: h.length / 2 <= 75 ? h.length / 2 : h.length / 2 <= 255 ? 76 : 77, data: Uint8Array.from(Buffer.from(h, 'hex'))}]);
  return out;
}

// Flattened instruction stream of each function (calls expanded): a polynomial hash with its
// length, composed over calls; candidate groups are then compared token by token.
const MOD = (1n << 127n) - 1n, BASE = 1000003n;
const tokenHash = (s) => BigInt('0x' + Buffer.from(s).toString('hex').slice(0, 30).padEnd(30, '0')) ^ BigInt(s.length);
function streams(defs) {
  const memo = new Map(), pw = (n) => { let r = 1n, b = BASE, e = BigInt(n); while (e) { if (e & 1n) r = r * b % MOD; b = b * b % MOD; e >>= 1n; } return r; };
  const tok = (x) => {
    if (x.call !== undefined) return !defs.has(x.call) ? [`R:${x.call}`] : isDynamic(defs.get(x.call)) ? [`D:${sig(x.call).h}`] : null;
    if (x.fnref !== undefined) return [`F:${sig(x.fnref).h}`];
    return [insHex(x)];
  };
  const sig = (k) => {
    if (memo.has(k)) return memo.get(k);
    let h = 0n, len = 0;
    for (const x of defs.get(k)) {
      const t = tok(x);
      const part = t ? {h: tokenHash(t[0]) % MOD, len: 1} : sig(x.call);
      h = (h + part.h * pw(len)) % MOD; len += part.len;
    }
    memo.set(k, {h, len});
    return memo.get(k);
  };
  const flat = (k, out = [], cap = 20000) => {
    for (const x of defs.get(k)) {
      const t = tok(x);
      if (t) out.push(t[0]); else flat(x.call, out, cap);
      if (out.length > cap) throw new Error('stream too long to compare');
    }
    return out;
  };
  return {sig, flat};
}

const bodySize = (b) => b.reduce((a, x) => a + (x.call !== undefined ? 2 : x.fnref !== undefined ? 1 : encodeAuthenticationInstruction(x).length), 0);

export function dedupe(defs, main) {
  for (;;) {
    const {sig, flat} = streams(defs);
    const groups = new Map();
    for (const k of defs.keys()) {
      if (isDynamic(defs.get(k))) continue;
      const {h, len} = sig(k), key = `${h}:${len}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(k);
    }
    for (const ks of groups.values()) if (ks.length > 1) {
      const ref = flat(ks[0]).join(',');
      for (const k of ks.slice(1)) if (flat(k).join(',') !== ref) throw new Error(`hash collision ${ks[0]} ${k}`);
    }
    const rename = new Map();
    for (const ks of groups.values()) {
      if (ks.length < 2) continue;
      // keep a member that does not call another member (else renaming would make it recursive)
      const members = new Set(ks), reaches = (k, seen = new Set()) => defs.get(k).some((x) => x.call !== undefined && !seen.has(x.call) && (seen.add(x.call), members.has(x.call) || reaches(x.call, seen)));
      const keep = ks.filter((k) => !reaches(k)).sort((a, b) => bodySize(defs.get(a)) - bodySize(defs.get(b)) || (a < b ? -1 : 1))[0];
      for (const k of ks) if (k !== keep) rename.set(k, keep);
    }
    if (rename.size === 0) return main;
    const r = (b) => b.map((x) => (x.call !== undefined && rename.has(x.call) ? {call: rename.get(x.call)} : x.fnref !== undefined && rename.has(x.fnref) ? {fnref: rename.get(x.fnref)} : x));
    for (const k of rename.keys()) defs.delete(k);
    for (const [k, b] of defs) defs.set(k, r(b));
    main = r(main);
  }
}

export function inlineCheap(defs, main, idCost = 2) {
  for (;;) {
    const refs = new Map([...defs.keys()].map((k) => [k, 0]));
    const fnrefd = new Set();
    const count = (b) => b.forEach((x) => { if (x.call !== undefined && refs.has(x.call)) refs.set(x.call, refs.get(x.call) + 1); if (x.fnref !== undefined) fnrefd.add(x.fnref); });
    defs.forEach(count); count(main);
    let pick;
    for (const [k, n] of refs) {
      const b = defs.get(k);
      if (fnrefd.has(k) || isDynamic(b)) continue;
      if (b.some((x) => x.call === k)) continue;
      const size = bodySize(b);
      const keep = size + (size > 75 ? 2 : 1) + idCost + 1 + n * (idCost + 1);
      const inl = n * size;
      if (inl < keep && (!pick || keep - inl > pick[1])) pick = [k, keep - inl];
    }
    if (!pick) return main;
    const [k] = pick, body = defs.get(k);
    const r = (b) => b.flatMap((x) => (x.call === k ? body : [x]));
    defs.delete(k);
    for (const [kk, b] of defs) defs.set(kk, r(b));
    main = r(main);
  }
}

// Greedy inlining against the exact encoded size (`measure(defs, main)` returns bytes after
// identifier assignment): inline one function at a time while that shrinks the program.
export function inlineExact(defs, main, measure) {
  let best = measure(defs, main);
  for (let improved = true; improved;) {
    improved = false;
    const fnrefd = new Set();
    const scan = (b) => b.forEach((x) => { if (x.fnref !== undefined) fnrefd.add(x.fnref); });
    defs.forEach(scan); scan(main);
    for (const k of [...defs.keys()]) {
      const body = defs.get(k);
      if (fnrefd.has(k) || isDynamic(body) || body.some((x) => x.call === k)) continue;
      const r = (b) => b.flatMap((x) => (x.call === k ? body : [x]));
      const trial = new Map([...defs].filter(([kk]) => kk !== k).map(([kk, b]) => [kk, r(b)]));
      const trialMain = r(main);
      const size = measure(trial, trialMain);
      if (size < best) {
        best = size; improved = true;
        defs.clear(); trial.forEach((b, kk) => defs.set(kk, b)); main = trialMain;
      }
    }
  }
  return main;
}
