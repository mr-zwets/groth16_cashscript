// Whole-transaction verification for layout b2 (Track 8 S6), on top of vm.mjs (S4, unchanged):
//   r100   per-input unlocking, bytecode and stack-item limits raised to 100,000 B; transaction limit 100,000 B
//   r100t  r100 with the standard transaction size limit raised to 200,000 B (two 100 KB inputs in one transaction)
//   spec   libauth bch-spec;  bch  today's rules
// Relay/standardness limits raised, not a new transaction version.
import {createInstructionSetBch2026, createVirtualMachine, ripemd160, secp256k1, sha1, sha256} from '@bitauth/libauth';
import {VMS, consensusR100} from './vm.mjs';

const crypto = {ripemd160, secp256k1, sha1, sha256};
const consensusR100t = {...consensusR100, maximumStandardTransactionSize: 200_000};
const TX = {
  r100Std: VMS.r100Std, r100Cons: VMS.r100Cons, specStd: VMS.specStd, specCons: VMS.specCons, bchStd: VMS.bchStd, bchCons: VMS.bchCons,
  r100tStd: createVirtualMachine(createInstructionSetBch2026(true, {consensus: consensusR100t, ...crypto})),
  r100tCons: createVirtualMachine(createInstructionSetBch2026(false, {consensus: consensusR100t, ...crypto})),
};
// true or an error string
export function verifyTxN(vmName, sourceOutputs, transaction) { return TX[vmName].verify({sourceOutputs, transaction}); }
