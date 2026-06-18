"""Generator for the BCH-limit-viable, multi-transaction vk_x checkpoint.

Runs the EXACT vkx.cash algorithm (bit-for-bit the py_ecc-validated reference),
snapshots the full Jacobian state at chunk boundaries, and emits:

  - chunked/chunkNN.cash  : one CashScript contract per chunk, self-verifying its
                            committed incoming/outgoing state via hash256.
  - chunked/manifest.json : ordered chunk metadata (iter range, term, the
                            INCOMING/OUTGOING hash256 commitments, the provided
                            incoming state coords for the unlocking vector), plus
                            input0/input1 and the final expected affine point.

State carried between chunks = the 9 Jacobian coords
(accX,accY,accZ, bX,bY,bZ, rX,rY,rZ). The loop index range, the active term
(0 = input0*IC1, 1 = input1*IC2), whether the chunk performs the term fold/reset,
and input0/input1 are baked per-chunk, so only the 9 coords vary and are the
thing committed.

Serialization (matches the .cash contract byte-for-byte):
  state = NUM2BIN_LE(accX,W) || NUM2BIN_LE(accY,W) || ... || NUM2BIN_LE(rZ,W)
  W = 40 (little-endian, OP_NUM2BIN). commitment = sha256(sha256(state)).
"""
import json, hashlib, sys, os

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

def addFp(x, y): return (x + y) % p
def subFp(x, y): return (x - y + p) % p
def mulFp(x, y): return (x * y) % p
def sqrFp(x): return (x * x) % p

def jac_double(X, Y, Z):
    a = sqrFp(X); b = sqrFp(Y); c = sqrFp(b)
    d = mulFp(2, subFp(subFp(sqrFp(addFp(X, b)), a), c))
    e = mulFp(3, a); f = sqrFp(e)
    nx = subFp(f, mulFp(2, d))
    ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c))
    nz = mulFp(2, mulFp(Y, Z))
    return nx, ny, nz

def jac_add(aX, aY, aZ, bX, bY, bZ):
    z1z1 = sqrFp(aZ); z2z2 = sqrFp(bZ)
    u1 = mulFp(aX, z2z2); u2 = mulFp(bX, z1z1)
    s1 = mulFp(mulFp(aY, bZ), z2z2); s2 = mulFp(mulFp(bY, aZ), z1z1)
    if u1 == u2 and s1 == s2:
        return jac_double(aX, aY, aZ)
    h = subFp(u2, u1); i2 = sqrFp(mulFp(2, h)); j = mulFp(h, i2)
    rr = mulFp(2, subFp(s2, s1)); v = mulFp(u1, i2)
    nx = subFp(subFp(sqrFp(rr), j), mulFp(2, v))
    ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2, mulFp(s1, j)))
    nz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h)
    return nx, ny, nz

W = 40
def serialize(state):
    return b''.join(int(c).to_bytes(W, 'little') for c in state)
def hash256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def commit(state):
    return hash256(serialize(state)).hex()

v = json.load(open('../vkx_vectors.json'))
ic0 = v['ic0']; ic1 = v['ic1']; ic2 = v['ic2']
input0 = v['input0']; input1 = v['input1']
expected = v['expected']

ITERS = 254
K = int(os.environ.get('K', '40'))  # iterations per chunk (tunable)

# ---- build chunk boundary plan ----
# A chunk is a contiguous range of double-and-add iterations within ONE term.
# The chunk whose range ends at iteration ITERS performs the term FOLD (acc+=R)
# at its tail; for term 0 it then RESETS R/base to IC2 for term 1. The final
# chunk (end of term 1) does the fold then the inverse -> affine -> assert.
chunks = []  # each: dict term, lo, hi, fold, reset_to_ic2, final
for term in (0, 1):
    lo = 0
    while lo < ITERS:
        hi = min(lo + K, ITERS)
        is_term_end = (hi == ITERS)
        chunks.append({
            'term': term, 'lo': lo, 'hi': hi,
            'fold': is_term_end,
            'reset_to_ic2': is_term_end and term == 0,
            'final': is_term_end and term == 1,
        })
        lo = hi

# ---- execute, capturing the state at every chunk boundary ----
def jac_dbl_base(bX, bY, bZ):
    if bZ != 0 and bY != 0:
        return jac_double(bX, bY, bZ)
    return bX, bY, bZ

def run_iter(k, i, rX, rY, rZ, bX, bY, bZ):
    if (k >> i) & 1 == 1:
        if rZ == 0:
            rX, rY, rZ = bX, bY, bZ
        else:
            rX, rY, rZ = jac_add(rX, rY, rZ, bX, bY, bZ)
    bX, bY, bZ = jac_dbl_base(bX, bY, bZ)
    return rX, rY, rZ, bX, bY, bZ

# initial state (entering chunk 0): acc=IC0, R=inf, base=IC1
state = (ic0[0], ic0[1], 1, ic1[0], ic1[1], 1, 0, 1, 0)
for ch in chunks:
    accX, accY, accZ, bX, bY, bZ, rX, rY, rZ = state
    ch['incoming'] = commit(state)
    ch['incoming_state'] = [str(x) for x in state]
    k = input0 if ch['term'] == 0 else input1
    for i in range(ch['lo'], ch['hi']):
        rX, rY, rZ, bX, bY, bZ = run_iter(k, i, rX, rY, rZ, bX, bY, bZ)
    if ch['fold']:
        if rZ != 0:
            accX, accY, accZ = jac_add(accX, accY, accZ, rX, rY, rZ)
    if ch['reset_to_ic2']:
        rX, rY, rZ = 0, 1, 0
        bX, bY, bZ = ic2[0], ic2[1], 1
    new_state = (accX, accY, accZ, bX, bY, bZ, rX, rY, rZ)
    if ch['final']:
        zInv = pow(accZ, p - 2, p)
        zInv2 = sqrFp(zInv); zInv3 = mulFp(zInv2, zInv)
        ch['affX'] = str(mulFp(accX, zInv2))
        ch['affY'] = str(mulFp(accY, zInv3))
        ch['outgoing'] = None
    else:
        ch['outgoing'] = commit(new_state)
    state = new_state

# sanity vs py_ecc
final = chunks[-1]
assert final['affX'] == str(expected[0]) and final['affY'] == str(expected[1]), \
    (final['affX'], final['affY'], expected)
# continuity: chunk i outgoing == chunk i+1 incoming
for a, b in zip(chunks, chunks[1:]):
    assert a['outgoing'] == b['incoming'], "continuity break"
print(f"py_ecc match OK, {len(chunks)} chunks, K={K}, continuity OK", file=sys.stderr)

# ---- emit .cash contracts ----
P = "21888242871839275222246405745257275088696311157297823662689037894645226208583"

FP_FUNCS = f"""    function addFp(int x, int y) returns (int) {{ return (x + y) % {P}; }}
    function subFp(int x, int y) returns (int) {{ return (x - y + {P}) % {P}; }}
    function mulFp(int x, int y) returns (int) {{ return (x * y) % {P}; }}
    function sqrFp(int x) returns (int) {{ return (x * x) % {P}; }}"""

INVERSE_FUNC = f"""    function inverseFp(int x) returns (int) {{
        int e = {P} - 2;
        int result = 1;
        int current = x % {P};
        for (int i = 0; i < 254; i++) {{
            if (((e >> i) % 2) == 1) {{ result = (result * current) % {P}; }}
            current = (current * current) % {P};
        }}
        return result;
    }}"""

def add_block(prefix, var_pfx, base_pfx):
    # Jacobian add of (var_pfx) += (base_pfx); inlined, mirrors the singleton.
    return f"""            int z1z1 = sqrFp({var_pfx}Z);
            int z2z2 = sqrFp({base_pfx}Z);
            int u1 = mulFp({var_pfx}X, z2z2);
            int u2 = mulFp({base_pfx}X, z1z1);
            int s1 = mulFp(mulFp({var_pfx}Y, {base_pfx}Z), z2z2);
            int s2 = mulFp(mulFp({base_pfx}Y, {var_pfx}Z), z1z1);
            if (u1 == u2 && s1 == s2) {{
                int a = sqrFp({var_pfx}X);
                int b = sqrFp({var_pfx}Y);
                int c = sqrFp(b);
                int d = mulFp(2, subFp(subFp(sqrFp(addFp({var_pfx}X, b)), a), c));
                int e = mulFp(3, a);
                int f = sqrFp(e);
                int nx = subFp(f, mulFp(2, d));
                int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
                int nz = mulFp(2, mulFp({var_pfx}Y, {var_pfx}Z));
                {var_pfx}X = nx; {var_pfx}Y = ny; {var_pfx}Z = nz;
            }} else {{
                int h = subFp(u2, u1);
                int i2 = sqrFp(mulFp(2, h));
                int j = mulFp(h, i2);
                int rr = mulFp(2, subFp(s2, s1));
                int vv = mulFp(u1, i2);
                int nx = subFp(subFp(sqrFp(rr), j), mulFp(2, vv));
                int ny = subFp(mulFp(rr, subFp(vv, nx)), mulFp(2, mulFp(s1, j)));
                int nz = mulFp(subFp(subFp(sqrFp(addFp({var_pfx}Z, {base_pfx}Z)), z1z1), z2z2), h);
                {var_pfx}X = nx; {var_pfx}Y = ny; {var_pfx}Z = nz;
            }}"""

def dbl_base():
    return f"""            int a = sqrFp(bX);
            int b = sqrFp(bY);
            int c = sqrFp(b);
            int d = mulFp(2, subFp(subFp(sqrFp(addFp(bX, b)), a), c));
            int e = mulFp(3, a);
            int f = sqrFp(e);
            int nx = subFp(f, mulFp(2, d));
            int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
            int nz = mulFp(2, mulFp(bY, bZ));
            bX = nx; bY = ny; bZ = nz;"""

SER = ("hash256(toPaddedBytes(accX, 40) + toPaddedBytes(accY, 40) + toPaddedBytes(accZ, 40)"
       " + toPaddedBytes(bX, 40) + toPaddedBytes(bY, 40) + toPaddedBytes(bZ, 40)"
       " + toPaddedBytes(rX, 40) + toPaddedBytes(rY, 40) + toPaddedBytes(rZ, 40))")

def gen_cash(idx, ch):
    k = input0 if ch['term'] == 0 else input1
    name = f"VkxChunk{idx:02d}"
    needs_inverse = ch['final']
    lines = []
    lines.append("pragma cashscript ^0.13.0;")
    lines.append(f"// vk_x chunk {idx}: term {ch['term']}, iterations [{ch['lo']},{ch['hi']}),"
                 f" fold={ch['fold']}, reset_to_ic2={ch['reset_to_ic2']}, final={ch['final']}.")
    lines.append(f"contract {name}() {{")
    lines.append(FP_FUNCS)
    if needs_inverse:
        lines.append(INVERSE_FUNC)
    lines.append("    function spend(int accX, int accY, int accZ, int bX, int bY, int bZ, int rX, int rY, int rZ) {")
    lines.append(f"        require({SER} == 0x{ch['incoming']});")
    # iteration loop: bake the bits of k for [lo,hi) as a constant scalar window.
    # We shift by the absolute index i, so reuse the singleton's per-bit test.
    lines.append(f"        int input = {k};")
    lines.append(f"        for (int i = {ch['lo']}; i < {ch['hi']}; i = i + 1) {{")
    lines.append("            if (((input >> i) % 2) == 1) {")
    lines.append("                if (rZ == 0) {")
    lines.append("                    rX = bX; rY = bY; rZ = bZ;")
    lines.append("                } else {")
    lines.append(add_block("", "r", "b"))
    lines.append("                }")
    lines.append("            }")
    lines.append("            if (bZ != 0 && bY != 0) {")
    lines.append(dbl_base())
    lines.append("            }")
    lines.append("        }")
    if ch['fold']:
        lines.append("        if (rZ != 0) {")
        lines.append(add_block("", "acc", "r"))
        lines.append("        }")
    if ch['reset_to_ic2']:
        lines.append(f"        rX = 0; rY = 1; rZ = 0;")
        lines.append(f"        bX = {ic2[0]}; bY = {ic2[1]}; bZ = 1;")
    if needs_inverse:
        lines.append("        int zInv = inverseFp(accZ);")
        lines.append("        int zInv2 = sqrFp(zInv);")
        lines.append("        int zInv3 = mulFp(zInv2, zInv);")
        lines.append(f"        require(mulFp(accX, zInv2) == {expected[0]});")
        lines.append(f"        require(mulFp(accY, zInv3) == {expected[1]});")
    else:
        lines.append(f"        require({SER} == 0x{ch['outgoing']});")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"

for idx, ch in enumerate(chunks):
    src = gen_cash(idx, ch)
    with open(f"chunk{idx:02d}.cash", "w") as f:
        f.write(src)

manifest = {
    'K': K,
    'numChunks': len(chunks),
    'input0': input0, 'input1': input1,
    'expected': [str(expected[0]), str(expected[1])],
    'serializeWidth': W,
    'chunks': [
        {
            'idx': i,
            'file': f"chunk{i:02d}.cash",
            'term': ch['term'], 'lo': ch['lo'], 'hi': ch['hi'],
            'fold': ch['fold'], 'reset_to_ic2': ch['reset_to_ic2'], 'final': ch['final'],
            'incoming': ch['incoming'],
            'outgoing': ch['outgoing'],
            'incoming_state': ch['incoming_state'],
        }
        for i, ch in enumerate(chunks)
    ],
}
with open('manifest.json', 'w') as f:
    json.dump(manifest, f, indent=2)
print(f"wrote {len(chunks)} chunk .cash files + manifest.json", file=sys.stderr)
