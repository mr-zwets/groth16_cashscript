// Track 12 public-values layout (must match ../../pv.mjs and the covenant's on-chain rebuild, template.mjs):
//   PV = "BCHPAYv1" ‖ instance (32 B) ‖ n (1 B, 1..=127) ‖ Σ_k value_k (u64 LE) ‖ len_k (u16 LE) ‖ locking_k
// Included verbatim (include!) by both guests; no_std-friendly (alloc only).
pub const PV_TAG: &[u8; 8] = b"BCHPAYv1";

pub fn encode_pv(instance: &[u8; 32], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    assert!(!outputs.is_empty() && outputs.len() <= 127, "1..=127 outputs");
    let mut pv = Vec::with_capacity(41 + outputs.iter().map(|(_, l)| 10 + l.len()).sum::<usize>());
    pv.extend_from_slice(PV_TAG);
    pv.extend_from_slice(instance);
    pv.push(outputs.len() as u8);
    for (value, locking) in outputs {
        assert!(*value < (1u64 << 63), "value fits a VM number");
        assert!(locking.len() <= 10_000, "locking bytecode <= 10,000 B");
        pv.extend_from_slice(&value.to_le_bytes());
        pv.extend_from_slice(&(locking.len() as u16).to_le_bytes());
        pv.extend_from_slice(locking);
    }
    pv
}

// The example application: a ZK hash-lock vault. Knowing a preimage of LOCK_HASH authorizes ANY outputs, and the proof
// commits exactly those outputs, so the proof cannot be redirected (Groth16 re-randomization does not change PV).
// LOCK_HASH is compiled into the program, so it is part of the programVKey / image id that the covenant pins.
// REPLACE it (and the secret) before any real use: the example secret below is public, and the preimage must carry
// >= 128 bits of entropy, because LOCK_HASH can be read from the published program.
// LOCK_HASH = sha256("verifier.cash track12 example secret: REPLACE with >=128 random bits")
pub const LOCK_HASH: [u8; 32] = [
    0x99, 0xa3, 0x64, 0xf6, 0x6b, 0x31, 0xc6, 0x3e, 0x9f, 0x74, 0x13, 0xd8, 0x4a, 0x75, 0x2e, 0x06,
    0x58, 0x25, 0xa6, 0xbe, 0xfa, 0x6d, 0x02, 0x6e, 0xed, 0x90, 0x07, 0x0c, 0x8e, 0x78, 0x36, 0xbf,
];
