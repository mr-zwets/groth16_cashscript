"""Generator for the BCH-limit-viable, multi-transaction vk_x checkpoint.

Computes vk_x = IC0 + input0*IC1 + input1*IC2 (G1 on BN254/alt_bn128) with the
SHAMIR / STRAUS shared-doubling trick: a SINGLE 254-iteration MSB-first
double-and-add over one accumulator R, instead of two separate 254-iteration
double-and-add loops (508 doublings -> 254 doublings). Per bit position i it
doubles R then conditionally adds one of {none, IC1, IC2, T=IC1+IC2} according
to (bit_i(input0), bit_i(input1)). IC0 (the constant term) is folded in at the
very end, then a single Jacobian->affine conversion gives vk_x.

The public inputs input0/input1 are taken at RUNTIME: they are part of the
carried, hash256-committed state (rX, rY, rZ, input0, input1) and the per-bit
"add this point" decision is computed IN-SCRIPT from (input0>>i)&1, (input1>>i)&1
via a 2-bit Shamir select over the VK-derived constants {IC1, IC2, T=IC1+IC2}.
This keeps the verifier proof-AGNOSTIC: the .cash contracts bake only VK-derived
constants (IC0, IC1, IC2, T and the expected vk_x), never the proof's inputs.

REUSABLE-FUNCTION REFACTOR (the big win over the prior 43-chunk build):
The elliptic-curve operations are no longer INLINED in every iteration. The
local cashc (feat/reusable-functions) supports multi-value (tuple) returns
compiling to OP_DEFINE/OP_INVOKE, so the EC ops are defined ONCE per chunk and
INVOKEd per iteration:
  - jacDouble(x,y,z)               returns (int,int,int)  -- dbl-2009-l
  - jacAdd(aX,aY,aZ,bX,bY,bZ)      returns (int,int,int)  -- add-2007-bl,
        including the u1==u2&&s1==s2 doubling subcase AND the aZ==0 (R is
        infinity -> return b) case, all single-trailing-return.
  - selectPoint(b0,b1)             returns (int,int,int)  -- (aX,aY,doAdd),
        with the VK constants T=IC1+IC2 / IC1 / IC2 hardcoded INSIDE the body.
  - addFp/subFp/mulFp/sqrFp        single-return Fp ops (as before).
A whole iteration becomes a handful of OP_INVOKEs (tens of bytes) instead of
~1500 B of inlined formula. The fixed OP_DEFINE prologue (the function bodies)
is emitted once per chunk; with tiny per-iteration cost OP-COST binds again
(not size), so we pack many more iterations per chunk -> far fewer chunks.

Those bodies live ONCE in a shared lib/ tower (Fp -> G1 -> Vk, see emit_libs());
each chunk just `import "./lib/Vk.cash";`. Same deps-first order as the old inline
prologue + tree-shaking -> byte-identical compiled chunks, de-duplicated source.

The Jacobian->affine inverse is done with a VERIFIED inverse-on-stack: the final
chunk's witness supplies zInv = R.Z^(p-2) mod p; the contract require()s
mulFp(R.Z, zInv) == 1 (so a forged zInv is rejected) then x = X*zInv^2,
y = Y*zInv^3, asserting equality with the py_ecc vk_x. No Fermat loop in-script.

Emits:
  - chunked/lib/{Fp,G1,Vk}.cash : the shared field/curve/VK library tower the
                            chunks import (written once, before planning).
  - chunked/chunkNN.cash  : one CashScript contract per chunk, self-verifying its
                            committed incoming state via hash256, running its
                            window of MSB-first iterations (runtime bit tests),
                            committing outgoing state (final chunk folds IC0 +
                            verified inverse + asserts vk_x).
  - chunked/manifest.json : ordered chunk metadata (iter window, INCOMING/OUTGOING
                            hash256 commitments, the incoming state for the
                            unlocking vector, and for the final chunk the supplied
                            zInv), plus input0/input1 and the expected affine point.

State serialization (matches the .cash byte-for-byte):
  state = NUM2BIN_LE(rX,W)||NUM2BIN_LE(rY,W)||NUM2BIN_LE(rZ,W)
          ||NUM2BIN_LE(input0,W)||NUM2BIN_LE(input1,W),  W = 40.
  commitment = sha256(sha256(state)).
"""
import json, hashlib, sys, os, subprocess, glob

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
    # Mirrors the .cash jacAdd EXACTLY: aZ==0 -> return b; the u1==u2&&s1==s2
    # subcase -> jacDouble(a); otherwise add-2007-bl.
    if aZ == 0:
        return bX, bY, bZ
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

v = json.load(open('../../bn254-vkx/vkx_vectors.json'))
ic0 = v['ic0']; ic1 = v['ic1']; ic2 = v['ic2']
input0 = v['input0']; input1 = v['input1']
expected = v['expected']

# ---- precompute T = IC1 + IC2 (affine) via py_ecc, hardcode the result ----
from py_ecc.bn128 import add as ec_add, multiply as ec_mul, FQ
_ic0 = (FQ(ic0[0]), FQ(ic0[1]))
_ic1 = (FQ(ic1[0]), FQ(ic1[1]))
_ic2 = (FQ(ic2[0]), FQ(ic2[1]))
_T = ec_add(_ic1, _ic2)
T = [int(_T[0]), int(_T[1])]
# py_ecc reference vk_x (authoritative)
_vkx = ec_add(ec_add(_ic0, ec_mul(_ic1, input0)), ec_mul(_ic2, input1))
assert int(_vkx[0]) == int(expected[0]) and int(_vkx[1]) == int(expected[1]), "py_ecc vs vector mismatch"

ITERS = 254
P = "21888242871839275222246405745257275088696311157297823662689037894645226208583"

# ---------------------------------------------------------------------------
# The reusable EC/field functions. Previously emitted as `internal function`
# bodies INLINE in every chunk (replicated N times). They now live in a shared
# lib/ tower (Fp -> G1 -> Vk) that each chunk `import`s; the bodies below are
# emitted ONCE into the library files by emit_libs(). Import resolution merges
# the libraries deps-first (Fp, then G1, then Vk), which is the SAME order the
# old inline prologue used, and tree-shaking keeps exactly the reachable set --
# so each chunk's compiled bytecode is unchanged, just de-duplicated in source.
# ---------------------------------------------------------------------------
def fp_lib_funcs():
    # Library form of the base-field ops: `function` (implicitly internal in a
    # library) and `% P` referencing the global constant, which inlines to the
    # same literal the old `% <prime>` bodies used.
    return ("    function addFp(int x, int y) returns (int) { return (x + y) % P; }\n"
            "    function subFp(int x, int y) returns (int) { return (x - y + P) % P; }\n"
            "    function mulFp(int x, int y) returns (int) { return (x * y) % P; }\n"
            "    function sqrFp(int x) returns (int) { return (x * x) % P; }")

def jac_double_fn():
    # dbl-2009-l. When z==0 the formula yields nz = 2*Y*Z = 0, so an infinity
    # point stays infinity (nx,ny are garbage but Z=0 marks infinity). The call
    # site only invokes jacDouble when rZ != 0, matching the Python reference.
    return """    internal function jacDouble(int x, int y, int z) returns (int, int, int) {
        int a = sqrFp(x);
        int b = sqrFp(y);
        int c = sqrFp(b);
        int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
        int e = mulFp(3, a);
        int f = sqrFp(e);
        int nx = subFp(f, mulFp(2, d));
        int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
        int nz = mulFp(2, mulFp(y, z));
        return nx, ny, nz;
    }"""

def jac_add_fn():
    # add-2007-bl with the u1==u2&&s1==s2 doubling subcase and the aZ==0 (R is
    # infinity -> return b) case, ALL in single-trailing-return style: result
    # vars rx/ry/rz are assigned in branches and returned once at the end.
    return """    internal function jacAdd(int aX, int aY, int aZ, int bX, int bY, int bZ) returns (int, int, int) {
        int rx = bX;
        int ry = bY;
        int rz = bZ;
        if (aZ != 0) {
            int z1z1 = sqrFp(aZ);
            int z2z2 = sqrFp(bZ);
            int u1 = mulFp(aX, z2z2);
            int u2 = mulFp(bX, z1z1);
            int s1 = mulFp(mulFp(aY, bZ), z2z2);
            int s2 = mulFp(mulFp(bY, aZ), z1z1);
            if (u1 == u2 && s1 == s2) {
                int da = sqrFp(aX);
                int db = sqrFp(aY);
                int dc = sqrFp(db);
                int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
                int de = mulFp(3, da);
                int df = sqrFp(de);
                int dnx = subFp(df, mulFp(2, dd));
                int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
                int dnz = mulFp(2, mulFp(aY, aZ));
                rx = dnx; ry = dny; rz = dnz;
            } else {
                int h = subFp(u2, u1);
                int i2 = sqrFp(mulFp(2, h));
                int jj = mulFp(h, i2);
                int rr = mulFp(2, subFp(s2, s1));
                int vv = mulFp(u1, i2);
                int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
                int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(s1, jj)));
                int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h);
                rx = anx; ry = any; rz = anz;
            }
        }
        return rx, ry, rz;
    }"""

def select_point_fn():
    # 2-bit Shamir select over the hardcoded VK constants {IC1, IC2, T=IC1+IC2}.
    # Returns (aX, aY, doAdd); single trailing return.
    return f"""    internal function selectPoint(int b0, int b1) returns (int, int, int) {{
        int aX = 0;
        int aY = 0;
        int doAdd = 0;
        if (b0 == 1 && b1 == 1) {{ aX = {T[0]}; aY = {T[1]}; doAdd = 1; }}
        else {{ if (b0 == 1) {{ aX = {ic1[0]}; aY = {ic1[1]}; doAdd = 1; }}
               else {{ if (b1 == 1) {{ aX = {ic2[0]}; aY = {ic2[1]}; doAdd = 1; }} }} }}
        return aX, aY, doAdd;
    }}"""

def _to_lib_fn(s):
    # The jac_*/select_point bodies are written as `    internal function ...`;
    # inside a `library` they are plain `function` (implicitly internal).
    return s.replace("internal function", "function")

def emit_libs():
    """Write the shared lib/ tower (Fp -> G1 -> Vk) imported by every chunk.

    Must run BEFORE the planner: the op-cost oracle compiles candidate chunks
    that `import "./lib/Vk.cash"`, so the library files have to exist on disk.
    """
    libdir = os.path.abspath('lib')
    os.makedirs(libdir, exist_ok=True)

    fp = "\n".join([
        "pragma cashscript ^0.13.0;",
        "",
        "// BN254 base field Fp. Shared by every shamir vk_x chunk (these ops used to",
        "// be replicated as `internal function`s inside each chunk). `P` is a global",
        "// constant, inlined at each use site -> single source of truth for the prime.",
        "library Fp {",
        f"    int constant P = {P};",
        "",
        fp_lib_funcs(),
        "}",
        "",
    ])
    g1 = "\n".join([
        "pragma cashscript ^0.13.0;",
        "",
        "// BN254 G1 Jacobian group law (double / add) over Fp, used by the Shamir",
        "// double-and-add loop. Builds on the base field library.",
        'import "./Fp.cash";',
        "",
        "library G1 {",
        _to_lib_fn(jac_double_fn()),
        _to_lib_fn(jac_add_fn()),
        "}",
        "",
    ])
    vk = "\n".join([
        "pragma cashscript ^0.13.0;",
        "",
        "// VK-specific layer: the 2-bit Shamir point select over the verifying-key",
        "// constants {IC1, IC2, T=IC1+IC2}. GENERATED from the VK vectors. A chunk that",
        "// imports this transitively pulls in the whole tower (Vk -> G1 -> Fp).",
        'import "./G1.cash";',
        "",
        "library Vk {",
        _to_lib_fn(select_point_fn()),
        "}",
        "",
    ])
    with open(os.path.join(libdir, 'Fp.cash'), 'w') as f: f.write(fp)
    with open(os.path.join(libdir, 'G1.cash'), 'w') as f: f.write(g1)
    with open(os.path.join(libdir, 'Vk.cash'), 'w') as f: f.write(vk)
    print("wrote lib/Fp.cash, lib/G1.cash, lib/Vk.cash", file=sys.stderr)

# SER includes the carried public inputs.
SER = ("hash256(toPaddedBytes(rX, 40) + toPaddedBytes(rY, 40) + toPaddedBytes(rZ, 40)"
       " + toPaddedBytes(input0, 40) + toPaddedBytes(input1, 40))")

def loop_lines(lo, hi):
    # BOUNDED LOOP over this chunk's MSB-first bit window [lo,hi). The loop body
    # is emitted into bytecode exactly ONCE (cashc compiles `for` to a runtime
    # loop), so the per-chunk locking size is independent of how many iterations
    # the chunk runs -> chunks become OP-COST-bound, not size-bound.
    #
    # Bit-position mapping (matches the run_window reference exactly): reference
    # iterates j in [lo,hi) with bit i = 253 - j, i.e. MSB-first positions
    # 253-lo, 253-lo-1, ..., 253-(hi-1). Here we run an ASCENDING index
    # k = 0..count-1 and compute i = hiBit - k with hiBit = 253 - lo, so
    # k=0 -> i=253-lo and k=count-1 -> i=253-(hi-1). Identical sequence.
    #
    # Bit extraction is at RUNTIME: input0/input1 are loop-invariant carried
    # state and the per-iteration add is chosen in-script from (input>>i)%2.
    # CashScript's `>>` works on int (only `&` is bytes-only), so we use
    # `(input0 >> i) % 2` -- NO 2^i literals, NO `&`.
    count = hi - lo
    hiBit = 253 - lo
    return f"""        // bounded MSB-first loop over bit window [{lo},{hi}) -> bit positions
        // {hiBit} down to {253 - (hi - 1)} (count {count}); body compiled ONCE.
        for (int k = 0; k < {count}; k = k + 1) {{
            int i = {hiBit} - k;
            // double R (guarded rZ != 0, matching the py_ecc reference)
            if (rZ != 0) {{
                (int dx, int dy, int dz) = jacDouble(rX, rY, rZ);
                rX = dx; rY = dy; rZ = dz;
            }}
            // runtime 2-bit Shamir select over VK consts {{IC1,IC2,T}}, then add
            int b0 = (input0 >> i) % 2;
            int b1 = (input1 >> i) % 2;
            (int aX, int aY, int doAdd) = selectPoint(b0, b1);
            if (doAdd == 1) {{
                (int ax, int ay, int az) = jacAdd(rX, rY, rZ, aX, aY, 1);
                rX = ax; rY = ay; rZ = az;
            }}
        }}"""

def gen_cash(idx, ch, nchunks):
    name = f"VkxChunk{idx:02d}"
    lines = []
    lines.append("pragma cashscript ^0.13.0;")
    lines.append(f"// vk_x chunk {idx}: Shamir window [{ch['lo']},{ch['hi']}) (MSB-first bit"
                 f" positions {253 - ch['lo']}..{253 - (ch['hi'] - 1)}), final={ch['final']}.")
    lines.append("// Public inputs taken at RUNTIME: carried state = (rX,rY,rZ,input0,input1);")
    lines.append("// per-bit add chosen in-script via 2-bit Shamir select over VK consts.")
    lines.append("// EC/field ops come from the shared lib/ tower (Fp -> G1 -> Vk).")
    lines.append('import "./lib/Vk.cash";')
    lines.append(f"contract {name}() {{")
    if ch['final']:
        lines.append("    function spend(int rX, int rY, int rZ, int input0, int input1, int zInv, bytes unused zeroPadding) {")
    else:
        lines.append("    function spend(int rX, int rY, int rZ, int input0, int input1, bytes unused zeroPadding) {")
    lines.append(f"        require({SER} == 0x{ch['incoming']});")
    lines.append(loop_lines(ch['lo'], ch['hi']))
    if ch['final']:
        # fold IC0 (constant term) UNCONDITIONALLY (no bit test) via jacAdd, then
        # verified inverse-on-stack -> affine -> assert.
        lines.append("        // fold IC0 (constant term) -- unconditional add of hardcoded VK const")
        lines.append(f"        (int icx, int icy, int icz) = jacAdd(rX, rY, rZ, {ic0[0]}, {ic0[1]}, 1);")
        lines.append("        rX = icx; rY = icy; rZ = icz;")
        lines.append("        // verified inverse-on-stack: zInv supplied, require rZ*zInv == 1")
        lines.append("        require(mulFp(rZ, zInv) == 1);")
        lines.append("        int zInv2 = sqrFp(zInv);")
        lines.append("        int zInv3 = mulFp(zInv2, zInv);")
        lines.append(f"        require(mulFp(rX, zInv2) == {expected[0]});")
        lines.append(f"        require(mulFp(rY, zInv3) == {expected[1]});")
    else:
        lines.append(f"        require({SER} == 0x{ch['outgoing']});")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"

# ---------------------------------------------------------------------------
# Reference execution (the .cash CONTRACT stays runtime; the trace MAY use the
# known inputs to compute the reference R).
# ---------------------------------------------------------------------------
def added_point(i):
    b0 = (input0 >> i) & 1
    b1 = (input1 >> i) & 1
    if b0 and b1: return (T[0], T[1])
    if b0:        return (ic1[0], ic1[1])
    if b1:        return (ic2[0], ic2[1])
    return None

def run_window(lo, hi, rX, rY, rZ):
    for j in range(lo, hi):
        i = 253 - j
        if rZ != 0:
            rX, rY, rZ = jac_double(rX, rY, rZ)
        ap = added_point(i)
        if ap is not None:
            aX, aY = ap
            rX, rY, rZ = jac_add(rX, rY, rZ, aX, aY, 1)
    return rX, rY, rZ

# ---------------------------------------------------------------------------
# Chunk planner. Per-iteration bytecode is now tiny, so OP-COST binds (not size).
# We measure the COMPILED locking bytecode + real-VM op-cost of a candidate
# chunk and grow the window until adding one more iteration would push op-cost
# over OP_COST_TARGET or locking over BYTE_BUDGET. The fixed OP_DEFINE prologue
# (function bodies) is included in every measurement.
# ---------------------------------------------------------------------------
CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js'
# Real-VM per-input op-cost budget at the 10,000-byte standard unlocking cap:
#   (41 + 10000) * 800 = 8,032,800. Keep a margin under it.
OP_BUDGET = (41 + 10000) * 800
OP_COST_TARGET = int(os.environ.get('OP_COST_TARGET', '7300000'))  # ~7.3M / chunk
BYTE_BUDGET = int(os.environ.get('BYTE_BUDGET', '9700'))
# Final chunk needs head-room for the IC0 fold + verified-inverse/assert tail.
# Those run once and cost ~ one jacAdd + a few mulFp/sqrFp/require; reserve op
# budget so the final window doesn't overflow once the tail is added.
FINAL_TAIL_OP = int(os.environ.get('FINAL_TAIL_OP', '900000'))

# --- compiled-cost oracle: compile a synthetic chunk for window [lo,hi) and
#     measure its real-VM op-cost + locking length via the build helper. We
#     reuse libauth through a tiny node one-shot so the planner sees the SAME
#     numbers the final vectors will. ---
_NODE_ORACLE = r'''
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
(async () => {
  const la = await import(LIBAUTH);
  const { hexToBin, bigIntToVmNumber, createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = la;
  const realVm = createVirtualMachineBch2026(false);
  const TARGET_UNLOCK = 10000, OP_PUSHDATA2 = 0x4d;
  const pushInt = (n) => {
    const d = bigIntToVmNumber(n);
    if (d.length === 0) return Uint8Array.from([0x00]);
    if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
    if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
    if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
    if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
    return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
  };
  const padPush = (argLen) => { const N = TARGET_UNLOCK - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]); };
  const argv = process.argv.slice(2);
  const cashFile = argv[0];
  const isFinal = argv[1] === '1';
  const coords = argv.slice(2).map((s) => BigInt(s)); // declaration order incl zInv for final
  const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
  const lockHex = execFileSync('node', [CASHC, cashFile, '-h'], { encoding: 'utf8', maxBuffer: 64*1024*1024 }).trim();
  const locking = Uint8Array.from([...hexToBin(lockHex)]); // no OP_DROP: trailing unused pad param
  const reversed = [...coords].reverse();
  const argBytes = Uint8Array.from(reversed.flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length), ...argBytes]); // pad first (pushed first)
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = realVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  process.stdout.write(JSON.stringify({ lockingBytes: locking.length, operationCost: state.metrics.operationCost, accepted, error: state.error ?? null }));
})();
'''
_oracle_path = os.path.abspath('._oracle.cjs')
with open(_oracle_path, 'w') as f:
    f.write(_NODE_ORACLE)

def measure(lo, hi, is_final, incoming, outgoing, incoming_state, zInv=None):
    """Compile a candidate chunk and return (lockingBytes, operationCost, accepted)."""
    ch = {'lo': lo, 'hi': hi, 'final': is_final, 'incoming': incoming, 'outgoing': outgoing}
    src = gen_cash(0, ch, 1)
    tmp = os.path.abspath('._probe.cash')
    with open(tmp, 'w') as f:
        f.write(src)
    coords = [str(x) for x in incoming_state]
    if is_final:
        coords = coords + [str(zInv)]
    args = ['node', _oracle_path, tmp, '1' if is_final else '0'] + coords
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"oracle failed lo={lo} hi={hi}: {res.stderr}")
    j = json.loads(res.stdout)
    return j['lockingBytes'], j['operationCost'], j['accepted']

# ---------------------------------------------------------------------------
# Greedy plan with measured op-cost. We must compute the incoming state of each
# chunk to compile it (the hash commitment is baked), so plan + execute in one
# forward pass: start from R=infinity, grow the current window one iter at a
# time, re-measuring, until op-cost would exceed target or bytes exceed budget.
# ---------------------------------------------------------------------------
def main():
    chunks = []
    state = (0, 1, 0, input0, input1)  # R = infinity; inputs carried
    lo = 0
    print("planning chunks (measuring compiled op-cost per candidate window)...", file=sys.stderr)
    while lo < ITERS:
        rX0, rY0, rZ0, i0, i1 = state
        incoming = commit(state)
        incoming_state = [rX0, rY0, rZ0, i0, i1]
        # Binary-search the largest hi in (lo, ITERS] whose window fits the op-cost
        # target. op-cost is monotonic increasing in hi (each extra iteration only
        # adds work), so the fitting windows form a prefix -> binary search finds the
        # SAME optimum as a linear scan, in ~log2(n) measurements instead of n.
        # The final window (hi==ITERS) carries the IC0-fold + inverse tail.
        def measure_candidate(hi):
            is_final = (hi == ITERS)
            rX, rY, rZ = run_window(lo, hi, rX0, rY0, rZ0)
            if is_final:
                rXf, rYf, rZf = jac_add(rX, rY, rZ, ic0[0], ic0[1], 1)
                zc = pow(rZf, p - 2, p)
                outgoing = None
                lb, oc, acc = measure(lo, hi, True, incoming, None, incoming_state, zc)
            else:
                outgoing = commit((rX, rY, rZ, input0, input1))
                zc = None
                lb, oc, acc = measure(lo, hi, False, incoming, outgoing, incoming_state)
            tail = FINAL_TAIL_OP if is_final else 0
            fits = acc and lb <= BYTE_BUDGET and (oc + tail) <= OP_COST_TARGET
            return fits, (hi, is_final, outgoing, lb, oc, acc, zc)

        best = None
        loB, hiB = lo + 1, ITERS
        while loB <= hiB:
            mid = (loB + hiB) // 2
            fits, rec = measure_candidate(mid)
            if fits:
                best = rec
                loB = mid + 1
            else:
                hiB = mid - 1
        if best is None:
            # one iteration overflows the target (shouldn't happen at 7.3M); take it.
            _, best = measure_candidate(lo + 1)
        bhi, b_is_final, b_outgoing, b_lb, b_oc, b_acc, b_zInv = best
        ch = {
            'lo': lo, 'hi': bhi, 'final': b_is_final,
            'incoming': incoming, 'incoming_state': [str(x) for x in incoming_state],
            'lockingBytes': b_lb, 'operationCost': b_oc, 'accepted': b_acc,
        }
        # advance state
        rX, rY, rZ = run_window(lo, bhi, rX0, rY0, rZ0)
        if b_is_final:
            rXf, rYf, rZf = jac_add(rX, rY, rZ, ic0[0], ic0[1], 1)
            zInv = pow(rZf, p - 2, p)
            zInv2 = sqrFp(zInv); zInv3 = mulFp(zInv2, zInv)
            ch['affX'] = str(mulFp(rXf, zInv2))
            ch['affY'] = str(mulFp(rYf, zInv3))
            ch['zInv'] = str(zInv)
            ch['outgoing'] = None
            state = (rXf, rYf, rZf, input0, input1)
        else:
            ch['outgoing'] = b_outgoing
            state = (rX, rY, rZ, input0, input1)
        chunks.append(ch)
        print(f"  chunk {len(chunks)-1}: [{lo},{bhi}) iters={bhi-lo} lock={b_lb}B "
              f"op-cost={b_oc:,} final={b_is_final}", file=sys.stderr)
        lo = bhi
    chunks[-1]['final'] = True
    return chunks

def build_all():
    # Emit the shared lib/ tower FIRST: the planner's op-cost oracle compiles
    # candidate chunks that import lib/Vk.cash, so it must already exist.
    emit_libs()
    chunks = main()

    # sanity vs py_ecc
    final = chunks[-1]
    assert final['affX'] == str(expected[0]) and final['affY'] == str(expected[1]), \
        (final['affX'], final['affY'], expected)
    for a, b in zip(chunks, chunks[1:]):
        assert a['outgoing'] == b['incoming'], "continuity break"
    print(f"py_ecc match (Shamir==py_ecc) OK, {len(chunks)} chunks, OP_COST_TARGET={OP_COST_TARGET:,}, "
          f"BYTE_BUDGET={BYTE_BUDGET}, continuity OK", file=sys.stderr)

    # ---- emit .cash contracts ----
    for idx, ch in enumerate(chunks):
        src = gen_cash(idx, ch, len(chunks))
        with open(f"chunk{idx:02d}.cash", "w") as f:
            f.write(src)

    # remove any orphan chunk files from a previous (different) chunk count
    for fn in glob.glob("chunk*.cash"):
        n = int(fn[len("chunk"):-len(".cash")])
        if n >= len(chunks):
            os.remove(fn)
            print(f"removed orphan {fn}", file=sys.stderr)

    # clean up planner scratch files
    for fn in ('._probe.cash', '._oracle.cjs'):
        try: os.remove(os.path.abspath(fn))
        except OSError: pass

    manifest = {
        'K': BYTE_BUDGET,
        'byteBudget': BYTE_BUDGET,
        'opCostTarget': OP_COST_TARGET,
        'numChunks': len(chunks),
        'algorithm': 'shamir-straus-runtime-inputs-reusable-fns',
        'input0': input0, 'input1': input1,
        'T': [str(T[0]), str(T[1])],
        'expected': [str(expected[0]), str(expected[1])],
        'serializeWidth': W,
        'chunks': [
            {
                'idx': i,
                'file': f"chunk{i:02d}.cash",
                'lo': ch['lo'], 'hi': ch['hi'],
                'final': ch['final'],
                'incoming': ch['incoming'],
                'outgoing': ch['outgoing'],
                'incoming_state': ch['incoming_state'],
                'zInv': ch.get('zInv'),
                'plannedLockingBytes': ch.get('lockingBytes'),
                'plannedOperationCost': ch.get('operationCost'),
            }
            for i, ch in enumerate(chunks)
        ],
    }
    with open('manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(chunks)} chunk .cash files + manifest.json", file=sys.stderr)

if __name__ == '__main__':
    build_all()
