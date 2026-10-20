// CashScript sources of the vk_x MSM stages carried by the executors (inputs 0, 1, 2) and the
// terminal (input 4). Genesis (input 3) carries MSM part A (positions 63..MSM_SPLIT, see
// ../pairfold5-msm/vkx-msm.mjs) and pins the first 198 bytes of input 0's state push.
//
// State push (224 bytes, the last push before the redeem): X, Y, Z (Jacobian accumulator),
// n0, n1 (32 bytes each, little endian) and the 64 witness bytes w (one per Straus position,
// MSB-first). Each executor runs witness bytes [from, to) of its OP_INPUTINDEX range and
// requires the next stage's state push (input 1, 2, then 4) to equal its result with n0, n1 and w
// copied through, so every stage sees the same claimed inputs and witness. The terminal stage
// runs the last positions, adds the constant IC0 - [2^64]G, converts to affine with the witnessed
// Z inverse, requires the result to equal the vk_x in genesis push 0 (the block the Miller loop
// consumes) and checks the GLV decomposition of w against n0, n1 by Horner.
//
// The pinned push is located from the end of the receiver's unlocking: its redeem push has a fixed
// length (the locking pins its hash) and it checks its own state push is exactly 224 bytes, so
// the pinned bytes are its state push.
import { helpers, P, R, LAM, FINAL } from '../pairfold5-msm/vkx-msm.mjs';

export const STATE_BYTES = 160;
// slim layout: executor state = X, Y, Z (96); terminal state = w, X, Y, Z (160). The claimed
// public inputs n0, n1 are the terminal's own number pushes (range-checked and GLV-checked there),
// and the witness bytes w live only in the terminal's state push: genesis reads its wa from there,
// and every executor reads its witness bytes from there.
export const EXEC_STATE_BYTES = 96;

// Read original witness bytes as an unsigned little-endian integer; no encoding changes.
const straus = (from, to, packedDigits = false) => `${packedDigits ? '        int digitWord=int(w+0x00);\n' : ''}        for (int t = ${from}; t < ${to}; t = t + 1) {
            int b = ${packedDigits ? '(digitWord>>(t*8))%256' : 'int(w.split(t + 1)[0].split(t)[1] + 0x00)'};
            (rX, rY, rZ) = dbl(rX, rY, rZ);
            if (b % 16 != 0) { (int x0, int y0) = tab0(b % 16); (rX, rY, rZ) = madd(rX, rY, rZ, x0, y0); }
            if (b / 16 != 0) { (int x1, int y1) = tab64(b / 16); (rX, rY, rZ) = madd(rX, rY, rZ, x1, y1); }
        }`;

const unpack = (size) => `        require(st.length == ${size});
        bytes s = st.split(${size - EXEC_STATE_BYTES})[1];
        int rX = int(s.split(32)[0]);
        int rY = int(s.split(64)[0].split(32)[1]);
        int rZ = int(s.split(64)[1]);`;

// cuts: [c0, c1, c2, c3]; executor k (input k) runs witness bytes [cuts[k], cuts[k + 1]).
// backExec / backTerminal: length of the executor / terminal redeem push (header included).
export const sourceExec = ({ cuts, backExec, backTerminal, packedDigits = false }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmStage() {
    function spend(bytes st) {
${unpack(EXEC_STATE_BYTES)}
        bytes v = tx.inputs[4].unlockingBytecode;
        bytes w = v.split(v.length - ${backTerminal + 160})[1].split(64)[0];
        int k = this.activeInputIndex;
        int from = ${cuts[0]}; int to = ${cuts[1]}; int next = 1; int back = ${backExec};
        if (k == 1) { from = ${cuts[1]}; to = ${cuts[2]}; next = 2; }
        if (k == 2) { from = ${cuts[2]}; to = ${cuts[3]}; next = 4; back = ${backTerminal}; }
${straus('from', 'to', packedDigits)}
        bytes u = tx.inputs[next].unlockingBytecode;
        require(u.split(u.length - back - ${EXEC_STATE_BYTES})[1].split(${EXEC_STATE_BYTES})[0] ==
            toPaddedBytes(rX, 32) + toPaddedBytes(rY, 32) + toPaddedBytes(rZ, 32));
    }
}
`;

// Carried pushes (bottom to top): n1, n0, zInv, st.
export const sourceFinal = ({ from, genIdx = 3, packedDigits = false, glvComponents = false, glvPairs = false }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmFinal() {
    function spend(bytes st, int zInv, int n0, int n1) {
${unpack(STATE_BYTES)}
        require(within(n0, 0, ${R})); require(within(n1, 0, ${R}));
        bytes w = st.split(64)[0];
${straus(from, 64, packedDigits)}
        (rX, rY, rZ) = madd(rX, rY, rZ, ${FINAL.x}, ${FINAL.y});
        require((rZ * zInv) % ${P} == 1);
        int zi2 = (zInv * zInv) % ${P};
        bytes g = tx.inputs[${genIdx}].unlockingBytecode;
        require(g.split(3)[0] == 0x4dc001);
        require((rX * zi2) % ${P} == int(g.split(163)[0].split(131)[1]));
        require((rY * (zi2 * zInv % ${P})) % ${P} == int(g.split(195)[0].split(163)[1]));
${glvComponents ? glvPairs ? `        // Each accumulator packs two unsigned 128-bit components.
        // After t<=64 steps each low/high half has at most t bits; no carry crosses a lane.
        int k01=0; int k23=0;
        for (int t=0; t<64; t=t+1) {
            int b=(digitWord>>(t*8))%256;
            int lo=b%16; int hi=b/16;
            k01=2*k01+lo%2+((hi%2)<<64)+((lo/2%2+((hi/2%2)<<64))<<128);
            k23=2*k23+lo/4%2+((hi/4%2)<<64)+((lo/8+((hi/8)<<64))<<128);
        }
        require((k01+${BigInt(LAM)-(1n<<128n)}*(k01>>128))%${R}==n0);
        require((k23+${BigInt(LAM)-(1n<<128n)}*(k23>>128))%${R}==n1);` : `        // Four packed components keep low/high binary halves at offsets 0 and 64.
        // The low half has at most t bits after t<=64 iterations, so no carry crosses bit64.
        int k0=0; int k1=0; int k2=0; int k3=0;
        for (int t=0; t<64; t=t+1) {
            int b=(digitWord>>(t*8))%256;
            int lo=b%16; int hi=b/16;
            k0=2*k0+lo%2+((hi%2)<<64);
            k1=2*k1+lo/2%2+((hi/2%2)<<64);
            k2=2*k2+lo/4%2+((hi/4%2)<<64);
            k3=2*k3+lo/8+((hi/8)<<64);
        }
        require((k0+${LAM}*k1)%${R}==n0);
        require((k2+${LAM}*k3)%${R}==n1);` : `        int s0lo = 0; int s1lo = 0; int s0hi = 0; int s1hi = 0;
        for (int t = 0; t < 64; t = t + 1) {
            int b = ${packedDigits ? '(digitWord>>(t*8))%256' : 'int(w.split(t + 1)[0].split(t)[1] + 0x00)'};
            int lo = b % 16; int hi = b / 16;
            s0lo = 2 * s0lo + lo % 2 + lo / 2 % 2 * ${LAM};
            s1lo = 2 * s1lo + lo / 4 % 2 + lo / 8 * ${LAM};
            s0hi = 2 * s0hi + hi % 2 + hi / 2 % 2 * ${LAM};
            s1hi = 2 * s1hi + hi / 4 % 2 + hi / 8 * ${LAM};
        }
        require((s0hi * ${1n << 64n} + s0lo) % ${R} == n0);
        require((s1hi * ${1n << 64n} + s1lo) % ${R} == n1);`}
    }
}
`;
