// Track 8 S8 unit check (SOUNDNESS-T8 sec. 9.1): residue safety of the on-chain constraint interpreter.
// Proof field lanes are parsed as 8-byte non-negative numbers, so a raw leaf lane lies in [0, 2^64), possibly >= p.
// Part A (history): the pre-fix subtraction form `a - b + p, MOD p` goes negative for b in [p + 1, 2^64), and the
//   extension product MULE is then not congruent; `a - b + 2p` is.
// Part B (the fix, S8b): the generated op bodies D_SUB, D_NEG, D_SUBL, D_RSUBL of both generators (gen.mjs, layout b
//   S4; genn.mjs, layouts b/b2/a') run in libauth on maximal non-negative lanes; every output lane must be canonical
//   (in [0, p)) and congruent, and MULE fed with those outputs must be congruent.
// Part C: MULE itself on maximal non-negative raw lanes (all six at 2^64 - 1, mixed p / 2^64 - 1 / 0).
const OC = new URL('.', import.meta.url).pathname.replace(/\/$/, '');
const {asm} = await import(OC + '/lib/asm.mjs');
const {evaluate} = await import(OC + '/vm.mjs');
const {vkxN} = await import(OC + '/modeln.mjs');
const {buildB} = await import(OC + '/genn.mjs');
const {loadVector, program} = await import(OC + '/layout-b.mjs');
const fs = await import('fs');
const P = 2n ** 64n - 2n ** 32n + 1n, M = 2n ** 64n - 1n;
const vpath = OC + '/../prover/vectors/S2/m1-0-Z128.json';
const v = JSON.parse(fs.readFileSync(vpath));
const gN = buildB(vkxN(v, {stmt: 'pool'}), {mode: 'pool', root: [0n, 0n, 0n, 0n], ctx: 'witness'});
const lv = loadVector(vpath);
const g4 = program(lv.vk, [0n, 0n, 0n, 0n], {ctx: 'witness'}).built;
const MULE = gN.fns.get('MULE').body;
const md = (x) => ((x % P) + P) % P;
const mulE = (a, b) => { // u^3 = u + 1
  const c = [0n, 0n, 0n, 0n, 0n];
  for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) c[i + j] += a[i] * b[j];
  return [md(c[0] + c[3]), md(c[1] + c[3] + c[4]), md(c[2] + c[4])];
};
const dec = (h) => { const b = Buffer.from(h, 'hex'); if (!b.length) return 0n; const neg = b[b.length - 1] & 0x80; b[b.length - 1] &= 0x7f; let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return neg ? -x : x; };
const top = (r, n, skip = 0) => r.stackTop.slice(r.stackTop.length - n - skip, r.stackTop.length - skip).map(dec);
const cases = [];
// the snippets leave their results on the stack, so libauth's final "exactly 1 item" check is the only error expected
const realError = (r) => (r.error && !String(r.error).includes('unexpected number of items on the stack') ? String(r.error) : null);
const record = (part, label, r, out, want, extra = {}) => {
  const congruent = !realError(r) && out.length === want.length && out.every((x, i) => md(x) === md(want[i]));
  cases.push({part, label, error: realError(r), out: out.map(String), want: want.map((x) => String(md(x))), congruent, nonNegative: out.every((x) => x >= 0n), ...extra});
};

// ---- Part A: the pre-fix form (raw opcodes, as the S4-S7 scripts had it) and the 2p form, then MULE ----
const bk = [0x1234567890abcdefn % P, 0x0fedcba987654321n % P, 0x13579bdf2468ace0n % P];
const runA = (label, unl, aRes) => {
  const r = evaluate('looseCons', asm(...unl, ...bk, {raw: MULE}), new Uint8Array(0));
  record('A', label, r, top(r, 3), mulE(aRes.map(md), bk));
};
runA('canonical inputs', [5n, 7n, 11n], [5n, 7n, 11n]);
runA('lane p+5 (non-negative, unreduced) straight into MULE', [P + 5n, 7n, 11n], [5n, 7n, 11n]);
runA('pre-fix: (2 - (p+5) + p) MOD p = -3, then MULE', [2n, P + 5n, 'SUB', P, 'ADD', P, 'MOD', 7n, 11n], [-3n, 7n, 11n]);
runA('pre-fix: two lanes negative', [2n, P + 5n, 'SUB', P, 'ADD', P, 'MOD', 1n, P + 9n, 'SUB', P, 'ADD', P, 'MOD', 11n], [-3n, -8n, 11n]);
runA('2p form: (a - b + 2p) MOD p, then MULE', [2n, P + 5n, 'SUB', 2n * P, 'ADD', P, 'MOD', 1n, P + 9n, 'SUB', 2n * P, 'ADD', P, 'MOD', 11n], [-3n, -8n, 11n]);

// ---- Part B: the generated op bodies (after the fix), both generators ----
// D_SUB / D_NEG run as TOALTSTACK body FROMALTSTACK with the program string on top; D_SUBL / D_RSUBL read a 2-byte
// absolute stack index operand from the program string (the loaded triple is the second operand, the top one first).
const LANES = [
  [[0n, 0n, 0n], [M, M, M]],
  [[M, M, M], [M, M, M]],
  [[1n, P, 0n], [M, P + 1n, M]],
  [[P - 1n, 0n, M], [M, P - 1n, 0n]],
  [[2n, 1n, 11n], [P + 5n, P + 9n, 3n]],
  [[0n, 0n, 0n], [P, P + 1n, 2n ** 63n]],
];
const PROG = Uint8Array.of(0x00, 0x00, 0x2a); // operand: index 0 (u16 LE), then one dummy byte left as the rest
for (const [gname, fns] of [['genn', gN.fns], ['gen', g4.fns]]) {
  const body = (n) => { const f = fns.get(n); if (!f) throw new Error(`${gname}: ${n} not defined`); return f.body; };
  for (const [a, b] of LANES) {
    const tag = `[${a.map((x) => (x === M ? '2^64-1' : String(x))).join(',')}] , [${b.map((x) => (x === M ? '2^64-1' : String(x))).join(',')}]`;
    let r = evaluate('looseCons', asm(...a, ...b, Uint8Array.of(0x2a), {raw: body('D_SUB')}), new Uint8Array(0));
    let out = top(r, 3, 1); record('B', `${gname} D_SUB a - b ${tag}`, r, out, a.map((x, i) => x - b[i]), {canonical: out.every((x) => x >= 0n && x < P)});
    const sub = out;
    r = evaluate('looseCons', asm(...b, Uint8Array.of(0x2a), {raw: body('D_NEG')}), new Uint8Array(0));
    out = top(r, 3, 1); record('B', `${gname} D_NEG -b ${tag}`, r, out, b.map((x) => -x), {canonical: out.every((x) => x >= 0n && x < P)});
    // loaded triple b at absolute index 0, top triple a: SUBL = a - b, RSUBL = b - a
    r = evaluate('looseCons', asm(...b, ...a, PROG, {raw: body('D_SUBL')}), new Uint8Array(0));
    out = top(r, 3, 1); record('B', `${gname} D_SUBL a - b ${tag}`, r, out, a.map((x, i) => x - b[i]), {canonical: out.every((x) => x >= 0n && x < P)});
    r = evaluate('looseCons', asm(...b, ...a, PROG, {raw: body('D_RSUBL')}), new Uint8Array(0));
    out = top(r, 3, 1); record('B', `${gname} D_RSUBL b - a ${tag}`, r, out, b.map((x, i) => x - a[i]), {canonical: out.every((x) => x >= 0n && x < P)});
    // the subtraction result straight into MULE (with the raw maximal lane b as the other factor)
    if (sub.length === 3) {
      r = evaluate('looseCons', asm(...sub, ...b, {raw: MULE}), new Uint8Array(0));
      record('B', `${gname} MULE(D_SUB(a, b), b) ${tag}`, r, top(r, 3), mulE(a.map((x, i) => md(x - b[i])), b.map(md)));
    }
  }
}

// ---- Part C: MULE on maximal non-negative raw lanes ----
const runC = (label, a, b) => { const r = evaluate('looseCons', asm(...a, ...b, {raw: MULE}), new Uint8Array(0)); record('C', label, r, top(r, 3), mulE(a.map(md), b.map(md))); };
runC('all six lanes 2^64-1', [M, M, M], [M, M, M]);
runC('a = 2^64-1 x3, b = p-1 x3', [M, M, M], [P - 1n, P - 1n, P - 1n]);
runC('a = (p, 2^64-1, 0), b = (2^64-1, 1, 2^64-1)', [P, M, 0n], [M, 1n, M]);
runC('a = (0, 0, 2^64-1), b = (0, 0, 2^64-1)', [0n, 0n, M], [0n, 0n, M]);

const outp = OC + '/results/s8-arith.json';
fs.writeFileSync(outp, JSON.stringify(cases.map(({error, ...c}) => (error ? {...c, error} : c)), null, 1) + '\n');
for (const c of cases) console.log(`${c.part} ${c.congruent ? 'congruent    ' : 'NOT congruent'}${c.canonical === false ? ' NON-CANONICAL' : ''}  ${c.label}${c.error ? ' err=' + c.error : ''}`);
const bad = cases.filter((c) => (c.part !== 'A' || c.label.startsWith('canonical') || c.label.startsWith('2p')) && (!c.congruent || c.canonical === false || !c.nonNegative));
const expectedBadA = cases.filter((c) => c.part === 'A' && c.label.startsWith('pre-fix') && !c.congruent).length;
console.log(`s8-arith: ${cases.length} cases; fixed ops and MULE: ${bad.length} wrong; pre-fix form wrong as expected: ${expectedBadA}/2`);
process.exit(bad.length === 0 && expectedBadA === 2 ? 0 : 1);
