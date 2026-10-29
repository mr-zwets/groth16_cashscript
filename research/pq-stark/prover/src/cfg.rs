//! Plonky3 configurations: Goldilocks, SHA-256 everywhere (Merkle leaves, Merkle nodes, Fiat-Shamir,
//! grinding), FRI over a degree-2 or degree-3 extension, with and without the hiding (ZK) PCS.
//!
//! - Leaf hash:    SerializingHasher<Sha256>        = SHA256(canonical u64 LE bytes of the row(s))
//! - Node hash:    CompressionFunctionFromHasher<Sha256, 2, 32> = SHA256(left || right)
//!                 (NOT p3_sha256::Sha256Compress: that is the raw, unpadded SHA-256 compression
//!                 function, which CashVM's OP_SHA256 cannot compute.)
//! - Challenger:   SerializingChallenger64<Goldilocks, HashChallenger<u8, TapSha256, 32>>
//!                 (TapSha256 = SHA-256 that can record its inputs, for transcript debugging)

use std::cell::RefCell;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::{BinomialExtensionField, CubicTrinomialExtensionField};
use p3_fri::{HidingFriPcs, TwoAdicFriPcs};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;

use crate::airs::Val;

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

/// SHA-256 truncated to its first N bytes (Merkle digests of N bytes; collision security 4N bits).
#[derive(Copy, Clone, Debug, Default)]
pub struct TruncSha256<const N: usize>;

impl<const N: usize> CryptographicHasher<u8, [u8; N]> for TruncSha256<N> {
    fn hash_iter<I>(&self, input: I) -> [u8; N]
    where
        I: IntoIterator<Item = u8>,
    {
        let d = Sha256.hash_iter(input);
        core::array::from_fn(|i| d[i])
    }
}

pub type FieldHash = SerializingHasher<Sha256>;
pub type Compress = CompressionFunctionFromHasher<Sha256, 2, 32>;
pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, TapSha256, 32>>;
pub type Dft = Radix2DitParallel<Val>;

pub type TValMmcs<const H: usize> = MerkleTreeMmcs<
    Val,
    u8,
    SerializingHasher<TruncSha256<H>>,
    CompressionFunctionFromHasher<TruncSha256<H>, 2, H>,
    2,
    H,
>;
pub type TPcs<EF, const H: usize> =
    TwoAdicFriPcs<Val, Dft, TValMmcs<H>, ExtensionMmcs<Val, EF, TValMmcs<H>>>;
pub type TCfg<EF, const H: usize> = StarkConfig<TPcs<EF, H>, EF, Challenger>;

pub fn make_tcfg<EF, const H: usize>(s: &FriSet) -> TCfg<EF, H>
where
    EF: p3_field::ExtensionField<Val>,
{
    assert_eq!(s.digest, H);
    let val_mmcs = TValMmcs::<H>::new(
        SerializingHasher::new(TruncSha256::<H>),
        CompressionFunctionFromHasher::new(TruncSha256::<H>),
        0,
    );
    let ch_mmcs = ExtensionMmcs::<Val, EF, TValMmcs<H>>::new(val_mmcs.clone());
    let pcs = TPcs::<EF, H>::new(Dft::default(), val_mmcs, fri_params(s, ch_mmcs));
    TCfg::<EF, H>::new(pcs, challenger())
}

pub type EF2 = BinomialExtensionField<Val, 2>;
pub type EF3 = CubicTrinomialExtensionField<Val>;

pub type Pcs<EF> = TwoAdicFriPcs<Val, Dft, ValMmcs, ExtensionMmcs<Val, EF, ValMmcs>>;
pub type Cfg<EF> = StarkConfig<Pcs<EF>, EF, Challenger>;

/// Hiding MMCS: every leaf gets S random base elements (the salt) appended before hashing.
pub type HValMmcs<const S: usize> = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, S>;
pub type HPcs<EF, const S: usize> =
    HidingFriPcs<Val, Dft, HValMmcs<S>, ExtensionMmcs<Val, EF, HValMmcs<S>>, StdRng>;
pub type HCfg<EF, const S: usize> = StarkConfig<HPcs<EF, S>, EF, Challenger>;

#[derive(Clone, Debug, serde::Serialize)]
pub struct FriSet {
    pub name: String,
    pub ext: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub batch_pow_bits: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
    pub zk: bool,
    pub num_random_codewords: usize,
    pub salt: usize,
    /// Merkle digest bytes (32 = full SHA-256; 25 = truncated, non-ZK only)
    pub digest: usize,
}

pub fn challenger() -> Challenger {
    Challenger::from_hasher(vec![], TapSha256)
}

fn fri_params<M>(s: &FriSet, mmcs: M) -> p3_fri::FriParameters<M> {
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

pub fn make_cfg<EF>(s: &FriSet) -> Cfg<EF>
where
    EF: p3_field::ExtensionField<Val>,
{
    let val_mmcs = ValMmcs::new(FieldHash::new(Sha256), Compress::new(Sha256), 0);
    let ch_mmcs = ExtensionMmcs::<Val, EF, ValMmcs>::new(val_mmcs.clone());
    let pcs = Pcs::<EF>::new(Dft::default(), val_mmcs, fri_params(s, ch_mmcs));
    Cfg::<EF>::new(pcs, challenger())
}

pub fn make_hcfg<EF, const S: usize>(s: &FriSet, seed: u64) -> HCfg<EF, S>
where
    EF: p3_field::ExtensionField<Val>,
{
    use rand::SeedableRng;
    assert_eq!(s.salt, S);
    let val_mmcs = HValMmcs::<S>::new(
        FieldHash::new(Sha256),
        Compress::new(Sha256),
        0,
        StdRng::seed_from_u64(seed ^ 0x5a5a_0001),
    );
    let ch_mmcs = ExtensionMmcs::<Val, EF, HValMmcs<S>>::new(val_mmcs.clone());
    let pcs = HPcs::<EF, S>::new(
        Dft::default(),
        val_mmcs,
        fri_params(s, ch_mmcs),
        s.num_random_codewords,
        StdRng::seed_from_u64(seed ^ 0x5a5a_0002),
    );
    HCfg::<EF, S>::new(pcs, challenger())
}
