// Grade singleton/bls12-381/vkx.cash: the standalone vk_x checkpoint (G1 only).
// vkx.cash has a constructor VkX(expectedX,expectedY); cashc -h emits the template
// and constructor args bind by PREPENDING their pushes (reverse decl order) plus an
// OP_DROP. Valid input -> ACCEPT; tampered input -> recomputed vk_x != expected ->
// REJECT. Run: node singleton/bls12-381/vkx.mjs
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { vkx as vkxPoint, PUBLIC_INPUTS } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, bigIntToVmNumber, encodeDataPush, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';

const HUGE = Number.MAX_SAFE_INTEGER;
const loose = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loose, ripemd160, secp256k1, sha1, sha256 }));

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));

const template = hexToBin(execFileSync('node', [CASHC, join(here, 'vkx.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
const va = vkxPoint.toAffine();
// locking = push(expectedY) || push(expectedX) || template  (reverse decl order; no
// OP_DROP since the unlocking carries no zero-pad here)
const locking = (eX, eY) => Uint8Array.from([...pushInt(eY), ...pushInt(eX), ...template]);
// unlocking = push(input1) || push(input0)  (cashc reverses spend args)
const unlocking = (i0, i1) => Uint8Array.from([...pushInt(i1), ...pushInt(i0)]);

const run = (lock, unlock) => {
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: unlock, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  return st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
};

const good = run(locking(va.x, va.y), unlocking(PUBLIC_INPUTS[0], PUBLIC_INPUTS[1]));
const badInput = run(locking(va.x, va.y), unlocking(PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]));
const badExpect = run(locking(va.x, va.y + 1n), unlocking(PUBLIC_INPUTS[0], PUBLIC_INPUTS[1]));
console.log(`VkX (BLS12-381) contract ${template.length}B`);
console.log(`valid=${good}  reject-bad-input=${!badInput}  reject-bad-expected=${!badExpect}`);
const ok = good && !badInput && !badExpect;
console.log(`${ok ? 'PASS' : 'FAIL'}  vkx checkpoint`);
process.exit(ok ? 0 : 1);
