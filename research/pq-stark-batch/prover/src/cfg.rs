//! Plonky3 configurations for p3-batch-stark: Goldilocks, SHA-256 everywhere (Merkle leaves, Merkle
//! nodes, Fiat-Shamir, grinding), FRI over Plonky3's cubic trinomial extension (x^3 = x + 1), with
//! and without the hiding (ZK) PCS. Adapted from Track 5 `research/pq-stark/prover/src/cfg.rs`; the
//! changes are: `cap_height` is a parameter (it was fixed at 0), the OOD and lookup grinding sites of
//! the batch STARK are parameters, and only the cubic extension is built.
//!
//! - Leaf hash:    SerializingHasher<Sha256>        = SHA256(canonical u64 LE bytes of the row(s) [+ salt])
//! - Node hash:    CompressionFunctionFromHasher<Sha256, 2, 32> = SHA256(left || right)
//!                 (NOT p3_sha256::Sha256Compress: that is the raw, unpadded SHA-256 compression
//!                 function, which CashVM's OP_SHA256 cannot compute.)
//! - Challenger:   SerializingChallenger64<Goldilocks, HashChallenger<u8, TapSha256, 32>>
//!                 (TapSha256 = SHA-256 that records its inputs, for the transcript logs)

use std::cell::RefCell;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_fri::{HidingFriPcs, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

pub type Val = Goldilocks;
pub type EF = CubicTrinomialExtensionField<Val>;
pub const D: usize = 3;

thread_local! {
    pub static TAP: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
}

pub fn tap_start() {
    TAP.with(|t| *t.borrow_mut() = Some(Vec::new()));
}
pub fn tap_take() -> Vec<Vec<u8>> {
    TAP.with(|t| t.borrow_mut().take().unwrap_or_default())
}

/// SHA-256 that records every input it hashes on this thread while a tap is active.
#[derive(Copy, Clone, Debug, Default)]
pub struct TapSha256;

impl CryptographicHasher<u8, [u8; 32]> for TapSha256 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let bytes: Vec<u8> = input.into_iter().collect();
        TAP.with(|t| {
            if let Some(v) = t.borrow_mut().as_mut() {
                v.push(bytes.clone());
            }
        });
        Sha256.hash_iter(bytes)
    }
}

pub type FieldHash = SerializingHasher<Sha256>;
pub type Compress = CompressionFunctionFromHasher<Sha256, 2, 32>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, TapSha256, 32>>;
pub type Dft = Radix2DitParallel<Val>;

pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ExtensionMmcs<Val, EF, ValMmcs>>;
pub type Cfg = StarkConfig<Pcs, EF, Challenger>;

/// Hiding MMCS: every leaf gets S random base elements (the salt) appended before hashing.
pub type HValMmcs<const S: usize> = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, S>;
pub type HPcs<const S: usize> =
    HidingFriPcs<Val, Dft, HValMmcs<S>, ExtensionMmcs<Val, EF, HValMmcs<S>>, StdRng>;
pub type HCfg<const S: usize> = StarkConfig<HPcs<S>, EF, Challenger>;

/// One parameter set. Everything here is verifying-key data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Params {
    pub name: String,
    pub ext: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub batch_pow_bits: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
    pub ood_pow_bits: usize,
    pub lookup_pow_bits: usize,
    pub zk: bool,
    /// hiding PCS: random codewords per committed matrix (zk only)
    pub num_random_codewords: usize,
    /// hiding MMCS: salt elements per leaf (zk only)
    pub salt: usize,
    /// Merkle cap height requested from the MMCS (the effective height can be lower, see FORMAT.md)
    pub cap_height: usize,
    /// Merkle digest bytes (always 32 here)
    pub digest: usize,
}

pub fn challenger() -> Challenger {
    Challenger::from_hasher(vec![], TapSha256)
}

fn fri_params<M>(s: &Params, mmcs: M) -> p3_fri::FriParameters<M> {
    p3_fri::FriParameters {
        log_blowup: s.log_blowup,
        log_final_poly_len: s.log_final_poly_len,
        max_log_arity: s.max_log_arity,
        num_queries: s.num_queries,
        batch_proof_of_work_bits: s.batch_pow_bits,
        commit_proof_of_work_bits: s.commit_pow_bits,
        query_proof_of_work_bits: s.query_pow_bits,
        mmcs,
    }
}

pub fn make_cfg(s: &Params) -> Cfg {
    assert!(!s.zk && s.ext == D && s.digest == 32);
    let val_mmcs = ValMmcs::new(FieldHash::new(Sha256), Compress::new(Sha256), s.cap_height);
    let ch_mmcs = ExtensionMmcs::<Val, EF, ValMmcs>::new(val_mmcs.clone());
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params(s, ch_mmcs));
    Cfg::new(pcs, challenger())
        .with_ood_proof_of_work_bits(s.ood_pow_bits)
        .with_lookup_proof_of_work_bits(s.lookup_pow_bits)
}

/// `seed` drives the salts and the random codewords. Production proving must use OS randomness;
/// the vectors use fixed seeds so that they are reproducible (see README).
pub fn make_hcfg<const S: usize>(s: &Params, seed: u64) -> HCfg<S> {
    use rand::SeedableRng;
    assert!(s.zk && s.ext == D && s.digest == 32);
    assert_eq!(s.salt, S);
    let val_mmcs = HValMmcs::<S>::new(
        FieldHash::new(Sha256),
        Compress::new(Sha256),
        s.cap_height,
        StdRng::seed_from_u64(seed ^ 0x5a5a_0001),
    );
    let ch_mmcs = ExtensionMmcs::<Val, EF, HValMmcs<S>>::new(val_mmcs.clone());
    let pcs = HPcs::<S>::new(
        Dft::default(),
        val_mmcs,
        fri_params(s, ch_mmcs),
        s.num_random_codewords,
        StdRng::seed_from_u64(seed ^ 0x5a5a_0002),
    );
    HCfg::<S>::new(pcs, challenger())
        .with_ood_proof_of_work_bits(s.ood_pow_bits)
        .with_lookup_proof_of_work_bits(s.lookup_pow_bits)
}

fn mk(name: &str) -> Params {
    Params {
        name: name.into(),
        ext: D,
        log_blowup: 2,
        log_final_poly_len: 2,
        max_log_arity: 1,
        num_queries: 2,
        batch_pow_bits: 0,
        commit_pow_bits: 1,
        query_pow_bits: 1,
        ood_pow_bits: 0,
        lookup_pow_bits: 0,
        zk: false,
        num_random_codewords: 4,
        salt: 4,
        cap_height: 0,
        digest: 32,
    }
}

/// Named parameter sets.
/// - PT / PTZ: Plonky3's own batch-test FRI shapes (`FriParameters::new_testing(_, 2)`; ZK: 4 random
///   codewords, 4-element salts, cap height 2 as in `make_config_zk`). Not secure: test vectors only.
/// - Z128 / Z128g: DESIGN-T8 section 0.5 (D = 3, log_blowup 9, one arity-8 fold, final length 256 /
///   32, Q = 24, PoW query 24 / commit 2 / batch 20, rc = 3, salt 2, cap 0).
pub fn all_sets() -> Vec<Params> {
    let pt = mk("PT");
    let mut ptz = mk("PTZ");
    ptz.zk = true;
    ptz.cap_height = 2;
    let z = |name: &str, lf: usize| Params {
        name: name.into(),
        ext: D,
        log_blowup: 9,
        log_final_poly_len: lf,
        max_log_arity: 3,
        num_queries: 24,
        batch_pow_bits: 20,
        commit_pow_bits: 2,
        query_pow_bits: 24,
        ood_pow_bits: 0,
        lookup_pow_bits: 0,
        zk: true,
        num_random_codewords: 3,
        salt: 2,
        cap_height: 0,
        digest: 32,
    };
    vec![pt, ptz, z("Z128", 8), z("Z128g", 5)]
}

/// `NAME[+k=v...]`, e.g. `Z128+cap=5`, `Z128+zk=0`, `PT+q=4`.
pub fn get_set(name: &str) -> Params {
    let base = name.split('+').next().unwrap();
    let mut s = all_sets()
        .into_iter()
        .find(|s| s.name == base)
        .unwrap_or_else(|| panic!("unknown set {base}"));
    for kv in name.split('+').skip(1) {
        let (k, v) = kv.split_once('=').expect("k=v");
        let v: usize = v.parse().expect("number");
        match k {
            "lb" => s.log_blowup = v,
            "lf" => s.log_final_poly_len = v,
            "arity" => s.max_log_arity = v,
            "q" => s.num_queries = v,
            "qpow" => s.query_pow_bits = v,
            "cpow" => s.commit_pow_bits = v,
            "bpow" => s.batch_pow_bits = v,
            "oodpow" => s.ood_pow_bits = v,
            "lpow" => s.lookup_pow_bits = v,
            "zk" => s.zk = v != 0,
            "rc" => s.num_random_codewords = v,
            "salt" => s.salt = v,
            "cap" => s.cap_height = v,
            _ => panic!("unknown override {k}"),
        }
    }
    s.name = name.to_string();
    s
}
