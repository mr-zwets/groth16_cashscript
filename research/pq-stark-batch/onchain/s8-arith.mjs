// Track 8 S8 unit check (SOUNDNESS-T8 sec. 9.1): is the on-chain extension product (MULE) a ring homomorphism when one input lane is negative?
// A negative lane arises from D_SUB (a - b + p, then MOD p) when b is a proof-supplied lane in [p, 2^64).
const OC = new URL('.', import.meta.url).pathname.replace(/\/$/, '');
const {asm} = await import(OC + '/lib/asm.mjs');
const {evaluate} = await import(OC + '/vm.mjs');
const {vkxN} = await import(OC + '/modeln.mjs');
const {makeGenN} = await import(OC + '/genn.mjs');
const fs = await import('fs');
const P = 2n ** 64n - 2n ** 32n + 1n;
const v = JSON.parse(fs.readFileSync(OC + '/../prover/vectors/S2/m1-0-Z128.json'));
const vk = vkxN(v, {stmt: 'pool'});
const g = makeGenN(vk, {mode: 'pool', root: [0n, 0n, 0n, 0n], ctx: 'witness'});
const MULE = g.fns.get('MULE').body;
const md = (x) => ((x % P) + P) % P;
const mulE = (a, b) => { // u^3 = u + 1
  const c = [0n, 0n, 0n, 0n, 0n];
  for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) c[i + j] += a[i] * b[j];
  // u^3 = u + 1, u^4 = u^2 + u
  return [md(c[0] + c[3]), md(c[1] + c[3] + c[4]), md(c[2] + c[4])];
};
const dec = (h) => { const b = Buffer.from(h, 'hex'); if (!b.length) return 0n; const neg = b[b.length - 1] & 0x80; b[b.length - 1] &= 0x7f; let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return neg ? -x : x; };
const cases = [];
const run = (label, unl, aRes, b) => {
  const lock = asm(...unl, {raw: MULE});
  const r = evaluate('looseCons', lock, new Uint8Array(0));
  const out = r.stackTop.slice(-3).map(dec);
  const want = mulE(aRes.map(md), b);
  const ok = out.every((x, i) => md(x) === want[i]);
  cases.push({label, error: r.error ?? null, out: out.map(String), want: want.map(String), congruent: ok});
};
const b = [0x1234567890abcdefn % P, 0x0fedcba987654321n % P, 0x13579bdf2468ace0n % P];
// canonical control
run('canonical inputs', [5n, 7n, 11n, ...b], [5n, 7n, 11n], b);
// residue control: a lane = p + 5 (non-canonical, non-negative) fed straight in
run('lane p+5 (non-negative, unreduced)', [P + 5n, 7n, 11n, ...b], [5n, 7n, 11n], b);
// D_SUB(2, p + 5) = 2 - (p + 5) + p = -3, then MOD p (sign of the dividend) -> -3
run('lane D_SUB(2, p+5) then MOD p = -3', [2n, P + 5n, 'SUB', P, 'ADD', P, 'MOD', 7n, 11n, ...b], [2n - 5n, 7n, 11n], b);
run('two lanes negative', [2n, P + 5n, 'SUB', P, 'ADD', P, 'MOD', 1n, P + 9n, 'SUB', P, 'ADD', P, 'MOD', 11n, ...b], [-3n, -8n, 11n], b);
// candidate fix: subtract with a 2p offset (as SUBE already does): 2 - (p + 5) + 2p = p - 3 >= 0
run('fix candidate: a - b + 2p, then MOD p', [2n, P + 5n, 'SUB', 2n * P, 'ADD', P, 'MOD', 1n, P + 9n, 'SUB', 2n * P, 'ADD', P, 'MOD', 11n, ...b], [-3n, -8n, 11n], b);
const outp = OC + '/results/s8-arith.json';
fs.writeFileSync(outp, JSON.stringify(cases.map(({error, ...c}) => c), null, 1) + '\n');
for (const c of cases) console.log((c.congruent ? 'congruent    ' : 'NOT congruent') + '  ' + c.label);
