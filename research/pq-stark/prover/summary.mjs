#!/usr/bin/env node
// vectors/summary.json: per vector, set, sizes (by section), Plonky3 estimates, prover time, case counts
import { readFileSync, readdirSync } from 'node:fs';
const rows = [];
for (const f of readdirSync('vectors').filter((x) => /^(fib|mimc)-.*\.json$/.test(x)).sort()) {
  const v = JSON.parse(readFileSync(`vectors/${f}`, 'utf8'));
  rows.push({ file: f, air: v.air, log_n: v.log_n, k: v.k, set: v.set.name, ext: v.set.ext, log_blowup: v.set.log_blowup,
    queries: v.set.num_queries, query_pow_bits: v.set.query_pow_bits, max_log_arity: v.set.max_log_arity,
    final_poly_len: 1 << v.set.log_final_poly_len, digest_bytes: v.set.digest, zk: v.set.zk,
    random_codewords: v.set.zk ? v.set.num_random_codewords : 0, salt: v.set.zk ? v.set.salt : 0,
    quotient_chunks: v.shape.num_chunks, fri_log_arities: v.shape.log_arities, proof_bytes: v.sizes.total, sizes: v.sizes,
    estimates: v.plonky3_security_estimates, prove_ms: v.prove_ms, tampered_cases: (v.tampered ?? []).length,
    transcript_hashes: v.transcript_hash_inputs.length });
}
console.log(JSON.stringify(rows, null, 1));
