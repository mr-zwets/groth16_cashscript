# Track 12: a program-pinned covenant template for SP1 v5 and RISC Zero proofs on the reviewed BN254 verifier

Branch `wip/pinned-template`, 2026-11-03. This is research, not a leaderboard entry, and it has **not been independently
reviewed**.

**What this adds.** Track 11 (`../real-keys`) showed that the reviewed verifier `../bn-native-sound` accepts real SP1
v5 and RISC Zero Groth16 proofs. Its plain builds take the public inputs `n0, n1` from the spender, so they accept a
valid proof of *any* program. This directory turns the verifier into a covenant that releases value only to the
transaction outputs that a **pinned program** authorized:

- the program identity (SP1 `programVKey`, RISC Zero image id) is a constant in the covenant code;
- the public values (PV) are **rebuilt on chain from the spending transaction's own outputs** (introspection). Their
  digest is **computed with OP_SHA256**, never taken as a pushed number;
- binding never depends on proof bytes, so a re-randomized Groth16 proof cannot change what is authorized (tested);
- no output may pay back to the covenant's own locking (on-chain guard), so "change" cannot re-arm a used proof.

**Before you fund one, read "What the statement does not bind".** Fund each address once, with exactly 3 UTXOs. A
proof does not choose which UTXOs it spends, so any later deposit to the same address can be taken by replaying a
used proof.

**What is real and what is not (read this first).**

| item | status |
|---|---|
| Template, library, transaction builder | done: `pv.mjs`, `template.mjs`, `pinned.mjs`, `example.mjs` |
| Proofs of the exact template statement | **test key only.** These are valid Groth16 proofs minted under the reviewed build's fixture VK, whose trapdoor is published in zk-verifier-bench (`../sound-si-gls/mint.mjs`). They exercise the full verifier and the template, but they are not SP1 or RISC Zero proofs |
| Real SP1 v5 / RISC Zero proofs of the template statement | **none.** The zkVM toolchains (`sp1up`, `rzup`) could not be installed in this session: the permission system denied installing external toolchains. Guest and host sources are in `guest/`. They are written against sp1-sdk 5.2.4 and risc0-zkvm 3.0.x but **were never compiled or run**. "Producing real proofs" below gives the exact steps |
| Real-key tests | rejection runs only, using Track 11's published real proofs: other programs, and each real proof under a template pinned to its own program (its PV is not in the template layout). Re-randomized real proofs are accepted by the plain core (positive control) and rejected by the template. No Track 11 fixture can be validly re-encoded into the template layout, because its PV lacks the `BCHPAYv1` tag, so none is used as a "valid" template spend |

## The statement

`pv.mjs` defines the PV layout. The guest commits these bytes raw (SP1 `io::commit_slice`, RISC Zero
`env::commit_slice`):

```
PV = "BCHPAYv1" (8 B) ‖ INSTANCE (32 B, covenant constant) ‖ n (1 B = output count; 1..127 on chain, 1..96 spendable)
     ‖ for k = 0..n-1:  value_k (u64 LE) ‖ len_k (u16 LE) ‖ lockingBytecode_k
```

The statement is: "program `PROGRAM_VKEY` (image `IMAGE_ID`) authorized exactly these outputs, in this order, for
deployment `INSTANCE`". The public inputs are derived the way the EVM verifiers derive them (Track 11 `claims.mjs`):

- **SP1 v5:** `n0 = programVKey`, `n1 = sha256(PV) & (2^253 − 1)`.
- **RISC Zero:** `(n0, n1) = splitDigest(ReceiptClaimLib.ok(IMAGE_ID, sha256(PV)).digest())`, where the journal is PV.

## The covenant (template.mjs)

The template uses Track 11's `setCovenant` hook. The hook code runs in role 2 (input 2, which owns `STMT` and runs the
vk_x binding). It sits right after `STMT` is decoded and range-checked (`n0, n1 < r`), before every
challenge-dependent step, and `K_code` pins it like the rest of the code:

```
PV  <- TAG ‖ INSTANCE ‖ NUM2BIN(TXOUTPUTCOUNT, 1)
for k in 0 .. TXOUTPUTCOUNT-1:                         (OP_BEGIN … OP_UNTIL)
    OUTPUTTOKENCATEGORY k == <empty>                    (no token on any output)
    OUTPUTBYTECODE k != UTXOBYTECODE(INPUTINDEX)        (no output pays back to this covenant's own locking)
    PV <- PV ‖ NUM2BIN(OUTPUTVALUE k, 8) ‖ NUM2BIN(SIZE(OUTPUTBYTECODE k), 2) ‖ OUTPUTBYTECODE k
SP1:   n0 == PROGRAM_VKEY;  n1 == BIN2NUM(REVERSEBYTES(SHA256(PV)) with top byte & 0x1f ‖ 0x00)
RISC0: od = SHA256(sha256("risc0.Output") ‖ SHA256(PV) ‖ 0^32 ‖ 0x0200)
       cd = SHA256(sha256("risc0.ReceiptClaim") ‖ 0^32 ‖ IMAGE_ID ‖ SYSTEM_STATE_ZERO ‖ od ‖ 0^8 ‖ 0x0400)
       n1 == BIN2NUM(cd[16:32] ‖ 0x00);  n0 == BIN2NUM(cd[0:16] ‖ 0x00)
```

After the hook, the reviewed verifier runs unchanged. `n0, n1` enter the GT-GLS fold of `e(vk_x, γ)` with
`vk_x = IC0 + n0·IC1 + n1·IC2`, so a proof of any other statement fails there. No reviewed file changed: the template
only imports `../bn-native-sound` (script, protocol, transaction, vm) and `../real-keys/claims.mjs`.

**Why every accept-relevant value has an owner** (the soundness-reset review question):

| value | owner |
|---|---|
| program id | constant in the code (pinned by `K_code`, hence by the P2SH32 locking) |
| INSTANCE, PV tag | constants in the code |
| PV | rebuilt from introspection of this transaction (count, then every output's value and locking in order) |
| "no self-payment" | every output's locking is compared with the spent UTXO's own locking (`OP_UTXOBYTECODE` of `OP_INPUTINDEX`), and an equal one fails `OP_VERIFY` |
| `n0, n1` | must equal values computed from the constants and PV (NUMEQUALVERIFY). The spender's `STMT` copy is only compared, never trusted |
| vk_x | the reviewed GT-GLS binding over exactly `n0, n1` (bn-native-sound) |
| A, B, C | the reviewed verifier. Re-randomization changes them but not the statement, which is all the covenant uses |
| which inputs run which role | bn-native-sound `GRAPH`: exactly 3 inputs, all spending this locking, each role chosen by `OP_INPUTINDEX` |

**What the statement does not bind (read before funding):**

- **Inputs: the proof does not choose which UTXOs it spends.** PV covers outputs, not outpoints or input values.
  Whoever builds the transaction (the prover, anyone who saw the proof, or a miner) picks any 3 UTXOs at the
  covenant address. If the address holds more than one set of 3 (two fundings, a top-up, a stray deposit), a used or
  seen proof can be replayed: it pays the **same** outputs again, and everything above them goes to the miner as fee.
  So value is conserved only while the address holds exactly the one funding the proof was made for. Rules:
  - fund each INSTANCE **once**, with exactly 3 UTXOs, and use a fresh random INSTANCE for every funding;
  - treat any later deposit to the address as lost to a replay.
  (Binding an outpoint is possible with `OP_OUTPOINTTXHASH`, but then the prover must know the funding txid before
  proving. It is not implemented here; the BCHN harness funds random outpoints.)
- **Change must go to a covenant with a fresh INSTANCE.** Change sent back to the same covenant would be a second
  funding of the same INSTANCE, and the already-public proof could be replayed against it. The covenant therefore
  rejects any output whose locking equals its own P2SH32 locking (tested: `self-payment`). The guard does **not**
  cover the covenant's two other lockings of the same redeem script `R`, and `GRAPH` would accept either: **P2SH20**
  (`OP_HASH160 <HASH160(R)> OP_EQUAL`), and **bare `R`** as the locking itself (non-standard to create, so it does not
  relay, but consensus-valid if mined). Never pay either. A P2SH20 guard is **not implemented**: the code cannot
  contain `HASH160(R)` as a constant (`R` commits to the code), but it could likely be closed by computing
  `HASH160(R)` at runtime from the input's redeem script; that would change the covenant script and is left open.
- **Fee.** fee = (sum of the 3 UTXOs actually spent) − (sum of the outputs). The proof fixes the outputs, not the
  inputs, so it fixes the fee only together with the funding. The transaction cannot get a fee input later (`GRAPH`
  admits exactly 3 inputs), and the only fee-bump path is a child spending one of the outputs (CPFP). The outputs
  the guest commits must therefore leave at least the relay fee: about 1 sat/B × up to 30.2 kB. `cov.preflight`
  checks this before proving, along with dust, output standardness (libauth bch-2026: OP_RETURN + pushes, or a
  locking ≤ 201 B), the 223-B OP_RETURN data-carrier cap (sum of locking length + 1) and the shape caps below.
- **The txid is not final until confirmation.** Nothing signs the transaction. Any relay can re-randomize A, B, C
  (still valid), or change version, locktime or sequence numbers. The outputs and fee stay the same, but the txid
  changes, so do not chain unconfirmed child transactions on the txid that `buildSpend` printed.
- **Version and locktime.** Not bound; they do not move value.
- **Tokens.** Every output must carry no CashTokens. Token data is not in PV, and introspection cannot tell every token
  encoding apart exactly (for example, a fungible-only output and the same output plus an immutable NFT with an empty
  commitment look alike to `OUTPUTTOKENCATEGORY` and `OUTPUTTOKENCOMMITMENT`). A token-carrying application needs its
  own encoding and a separate argument. **Tokens sent to the covenant address are destroyed** when it is spent
  (implicit burn: no output may carry them).
- **Spendable shape: at most 96 outputs, |PV| ≤ 9,900 B and outputs × |PV| ≤ 300,000.** On chain, `NUM2BIN(n, 1)`
  fails above 127 outputs and a PV over 10,000 B fails the stack-item limit. The rebuild also costs about
  n × |PV| op, because each `OP_CAT` is charged for the PV built so far, and all of it lands in role 2. Measured with
  test-key spends and prover-sized fillers on both systems: 112 × 25 B, 40 × 223 B and 1 × 9,949 B spend, but
  127 × 25 B, 96 × 60 B and 64 × 140 B exceed role 2's op budget even at the 10,000 B unlocking cap. Every measured
  point inside the caps spent with at least 5.6% role-2 margin. `pv.mjs` and the guests' `encode_pv` refuse to
  encode a PV outside the caps, so a proof that could never be spent is not produced. This is liveness only, never
  acceptance.
- **The program's own logic.** The covenant enforces "the program authorized these outputs". Whether that
  authorization is meaningful depends on the guest.

## The example application and guest

`guest/shared/pv.rs` holds the same encoder in Rust, plus the example: a **ZK hash-lock vault**. The guest reads
`(secret, INSTANCE, outputs)`, asserts `sha256(secret) == LOCK_HASH` (a constant compiled into the program, so it is
part of the programVKey / image id), and commits `PV = encode_pv(INSTANCE, outputs)`. Knowing the secret authorizes
any outputs. Because the proof commits those outputs, a third party who sees the proof in the mempool cannot redirect
it, and the secret is never revealed on chain. The example statement (`example-params.mjs`) pays 200,000 sat to a
P2PKH plus a 0-sat `OP_RETURN "track12 pay"` memo, so PV is 99 B. **The example is for regtest or chipnet only:** its
payout hash160 (`0x11` × 20) has no known key, so the 200,000 sat are burned, and its INSTANCE and secret are public.
`example.mjs` refuses these values unless `--regtest` is given.

- `guest/sp1/program` (SP1 v5 guest, sp1-zkvm 5.2.4) and `guest/sp1/script` (host: `vkey`, `prove request.json proof.json`).
- `guest/risc0/methods/guest` (risc0-zkvm 3.0.x guest) and `guest/risc0/host` (host: `imageid`, `prove …`;
  `risc0-ethereum-contracts::encode_seal` for the selector ‖ proof encoding).
- The example `LOCK_HASH` is the hash of a **public** string, so anyone can prove for any outputs of a covenant that
  pins the unmodified example guest. Replace it and the secret (≥ 128 bits of entropy) before any real use:
  `LOCK_HASH` can be read from the published program, so a guessable secret can be brute-forced. `example.mjs request`
  refuses the example secret without `--regtest`, and the guest hosts (`vkey`, `imageid`, `prove`) refuse a build
  whose `guest/shared/pv.rs` still has the example `LOCK_HASH` (`99a364f6…36bf`) unless `--regtest` is passed.

## Results (libauth BCH 2026 with the bench's OP_DEFINE patch, i.e. BCHN accounting)

Shape: 1 standard transaction, 3 inputs, all `P2SH32(R)` (35-byte locking, 65-byte redeem `R`), every unlocking
≤ 10,000 B. Fillers are prover-sized to a 6% standard op-cost margin, as in the reviewed build.

| build (key) | code | template block (role 2) | unlocking per input (B) | op cost per input, standard / budget (margin) | consensus op | tx B (BCHN) |
|---|--:|---|---|---|---|--:|
| plain verifier core (reviewed bn-native-sound, test key, bench reference) | 7,310 B | none | 9,316 / 9,262 / 8,792 | 7,050,949 / 7,485,600 (5.81%); 7,010,150 / 7,442,400 (5.81%); 6,656,840 / 7,066,400 (5.80%) | 7,016,645 / 6,975,846 / 6,623,944 | 27,519 |
| SP1 template (test key), 2 outputs | 7,456 B | +146 B, +12,673 op (consensus +12,417) | 9,342 / 9,294 / 8,773 | 7,055,570 / 7,506,400 (6.01%); 6,976,887 / 7,468,000 (6.58%); 6,626,248 / 7,051,200 (6.03%) | 7,021,138 / 6,942,455 / 6,592,968 | 27,604 |
| SP1 template (test key), 1 output | 7,456 B | | 9,327 / 9,294 / 8,840 | 7,044,708 / 6,998,883 / 6,677,843 (6.00 / 6.28 / 6.01%) | 7,010,148 / 6,964,323 / 6,644,435 | 27,634 |
| RISC Zero template (test key), 2 outputs | 7,638 B | +328 B, +15,267 op (consensus +14,371) | 9,383 / 9,385 / 8,775 | 7,071,778 / 7,539,200 (6.20%); 7,025,322 / 7,540,800 (6.84%); 6,628,918 / 7,052,800 (6.01%) | 7,036,962 / 6,990,506 / 6,594,614 | 27,738 |
| SP1 template (real SP1 v5 key) | 7,455 B | as above | no accepting spend exists (no real proof of the statement) | | | |
| RISC Zero template (real key, Track 11 root `b1f64013…` / released root `a54dc85a…`) | 7,638 B / 7,638 B | as above | no accepting spend exists | | | |

- Op costs come from libauth (`test.pinned.report.json`, standard) and from the node-check export of the same
  transactions (consensus; BCHN `t12c` perInput). The bench reference row is the builtin bn-native-sound fixture with
  its own fillers (5.8% margin).
- The "template block" column is measured by `covenant-cost.mjs` as template minus plain over role 2's
  `statement..slices` range, with the same proof. It includes the self-payment guard (+13 B of code, about 2.5k op
  for 2 outputs). The block grows roughly with n × |PV|, not linearly: each of the loop's three `OP_CAT`s per output
  is charged for the whole PV built so far. See "Spendable shape" above for the measured limits.
- **Real-key liveness is argued, not measured.** The real-key template code differs from the test-key code only in
  32-byte VK constants (7,455 vs 7,456 B), and op cost depends on the witness (GT-GLS digits, `n_q`), not on the VK.
  Track 11 measured the real fixtures within 0.1% of the test-key fixture with the same `n_q`. With 2 outputs, the
  template block adds 0.18% (SP1) or 0.22% (RISC Zero) of role 2's budget.
- The template code is deterministic: each test-key build is built twice and compared byte for byte.

## Tests (`pinned-test.mjs`; plain rejection tests, no exploit construction)

**Test key: 92 runs, 6 accepted controls, 86 rejections, consensus = standard on every run.** Each "valid proof of …"
rejection carries a valid Groth16 proof of exactly the statement in `STMT` (minted). The verifier would accept it, so
only the template can reject it. Every such run fails at role 2's `covenant` section. **The suite asserts, per run,
which inputs fail, in which section and on which opcode** (`NUMEQUALVERIFY` 0x9d for the statement checks, `OP_VERIFY`
0x69 for the range checks and the self-payment guard, `EQUALVERIFY` 0x88 for the transcript, and the recorded opcode
for the permuted-input and token runs), and it asserts that no
rejection comes from a resource limit (op cost or stack-item size). A rejection for the wrong reason fails the
suite.

| category | runs (sp1 + risc0) | first failing guard |
|---|--:|---|
| controls: exact statement (2 outputs), a 1-output statement, the **re-randomized** proof (A, B, C all differ) with the same outputs; the 2-output control also passes libauth `verify()` of the full transaction (consensus and standard, 3 × 100,000-sat inputs) | 3 + 3 accept | – |
| wrong program / image: valid proof of another programVKey / image id with the same PV; covenant pinned to another program (last byte xor 1) spent with the application's proof | 2 + 2 | `r2:covenant` |
| wrong public values: valid proofs whose PV pays 200,001 sat, pays another locking, names another INSTANCE, uses tag `BCHPAYv2`, or has one byte appended | 5 + 5 | `r2:covenant` |
| pushed-digest / carrier substitution: SP1 `n1 = sha256(PV) mod r` (wrong reduction); RISC Zero claim halves big-endian, and `splitDigest(sha256(PV))` instead of the claim digest; the application proof with `OP_RETURN <PV>` or `OP_RETURN <sha256(PV)>` in the outputs while paying elsewhere | 3 + 4 | `r2:covenant` |
| re-randomized application proof with the payout redirected / reduced | 2 + 2 | `r2:covenant` |
| changed outputs: payout value −1, +1, another P2PKH, memo byte changed, memo value 546 | 5 + 5 | `r2:covenant` |
| extra / missing outputs: extra P2PKH, extra empty OP_RETURN, memo missing, payout missing, payout duplicated | 5 + 5 | `r2:covenant` |
| index games: outputs swapped, payout split in two; inputs 0↔2 and 0↔1 permuted; a 4th input; 2 inputs; a token on the payout output | 7 + 7 | `r2:covenant` (outputs, token); `unlocking/redeem` (permuted inputs: code-piece split or K_code); `graph` (input count) |
| self-payment: valid proofs of statements whose outputs pay change back to this covenant's own locking (output 0; output 1) | 2 + 2 | `r2:covenant`, failing opcode `OP_VERIFY` (0x69) of the guard, not a statement `NUMEQUALVERIFY` (0x9d) |
| mixing two valid spends of this covenant: A0 A1 B2 with A's or B's outputs, B0 B1 A2, A0 B1 A2, and the same statement with a re-randomized proof (A0 A1 A'2, A'0 A1 A2) | 6 + 6 | the reviewed core's transcript checks (`r0:transcript`, `r1:transcript`, `r0:post`; `r2:covenant` where B's statement meets A's outputs), all `EQUALVERIFY` / `NUMEQUALVERIFY`, never a budget limit |
| public input ≥ r (`STMT` patched, DG and handovers recommitted): `n0 + r`, `n1 + r`, `2^256 − 1`; SP1 also the unmasked sha256 (≥ r) | 4 + 3 | `statement` (every role) |
| swapped inputs: valid proof of `(n1, n0)`; the application proof with `STMT` swapped (recommitted) | 2 + 2 | `r2:covenant` |

**Real keys** (Track 11's published proofs; none is of the template statement):

| key | runs | result |
|---|--:|---|
| `sp1-v5` | 10 | for each of the 3 real SP1 v5 proofs: under the template pinned to the placeholder application program → reject; under a template pinned to **its own** programVKey → reject (its PV is not of the template layout); the same proof re-randomized, own program → reject. Control: silvana-add re-randomized is **accepted by the plain core** |
| `risc0` (root b1f64013) | 4 | the same three for TestReceiptV5_0, plus its re-randomized plain-core control (accepted) |
| `risc0-v3` (released root a54dc85a) | 4 | the same for TestReceiptV3_0 (the receipt that verifies under the released root), control accepted |

All real-key rejections fail at `r2:covenant`, and inputs 0 and 1 accept. So the real proofs pass the verifier
itself; only the template rejects.

## Stock BCHN (node-check harness)

zk-verifier-bench `research/node-check` on branch `wip/pinned-template` (`export-pinned.mjs`, `run-t12.sh`). Stock
BCHN 29.1.0, regtest, fresh localhost-only nodes, each stopped afterwards. The timing node uses block validation;
the policy node runs `POLICY=1`, i.e. `testmempoolaccept` with `acceptnonstdtxn=0`. Run `t12c`
(groth16_cashscript a7edd02, the fix-round build with the self-payment guard; load average 0.6–2.0): **108 Track 12
workloads, all as expected, BCHN = libauth on every one.** Both nodes were stopped afterwards.

| workload | n | BCHN block | testmempoolaccept (POLICY=1) | Verify ms/tx (median of 11, K = 10) | worst input std + DEFINE |
|---|--:|---|---|--:|--:|
| SP1 template controls (test key): exact, 1-output, re-randomized | 3 | accept | 3/3 allowed (14.5 sat/B) | 3.487–3.503 | 93.99–94.00% |
| RISC Zero template controls (test key) | 3 | accept | 3/3 allowed (14.4 sat/B) | 3.471–3.479 | 93.97–94.00% |
| real-key re-randomized proofs, plain core (sp1-v5, risc0, risc0-v3) | 3 | accept | 3/3 allowed | 3.470–3.475 | 94.00% |
| test-key rejections | 84 | 84/84 rejected (`blk-bad-inputs`) | timing node: `mandatory-script-verify-flag-failed`: 57 × NUMEQUALVERIFY (covenant, and the input count in GRAPH); 7 × OP_VERIFY (statement range); 4 × OP_VERIFY (self-payment guard); 12 × EQUALVERIFY (mixed spends: transcript); 2 × EQUALVERIFY and 2 × OP_SPLIT range (permuted inputs) | – | – |
| real-key rejections | 15 | 15/15 rejected (`blk-bad-inputs`, NUMEQUALVERIFY) | – | – | – |
| reference: bn-native-sound (builtin, densless fixture) | 1 | accept | fee only (1,000-sat inputs); allowed at 2 sat/B | 3.481 | 94.20% |

- Rejection runs go to the timing node only. They are consensus script failures, so policy cannot change them.
- Not exported: the 2 token-output runs (libauth-only). On BCHN, an output token with an unknown category fails the
  token rules before the script verdict matters.
- All controls were funded at 200,000 sat per input (about 14.5 sat/B), so nothing near the 1 sat/B relay floor was
  exercised on BCHN. `cov.preflight` / `buildSpend` enforce that floor in the library instead.
- Earlier runs, on the build before the fix round (no self-payment guard, no mixing runs): `t12a` (funded at
  100,000 sat per input) and `t12b` (92 workloads, 200,000 sat per input) agreed on every verdict. Two `t12a`
  rejections (duplicated 200,000-sat payout) were rejected for `bad-txns-in-belowout` before the script ran.

## Producing real proofs (not done here)

```sh
# SP1 v5 (CPU): sp1up && sp1up --version v5.2.4; docker for the gnark wrap (or sp1-sdk feature native-gnark)
# 0. replace LOCK_HASH in guest/shared/pv.rs with sha256 of YOUR secret (>= 128 random bits); pick a fresh INSTANCE
#    (32 random bytes) and write statement.json = {"instanceId": "<INSTANCE>", "outputs": [{"lockingHex", "valueSatoshis"}]}
#    (on regtest you may instead use: node example.mjs example-statement statement.json, and pass --regtest below)
#    (the hosts refuse the example LOCK_HASH unless --regtest is appended to their commands)
cd guest/sp1/script && SP1_PROVER=cpu cargo run --release -- vkey            # YOUR programVKey: pin this value
# RISC Zero 3.0.x: rzup install (cargo-risczero, r0vm 3.0.x, risc0-groth16); the covenant key is 'risc0-v3'
cd guest/risc0 && cargo run --release -p host -- imageid                       # YOUR image id: pin this value
# 1. the covenant, from YOUR program id (never from a proof file); bchtest prefix (--mainnet is refused until a real-key accept exists)
node example.mjs pin sp1-v5 <programVKey> <INSTANCE>        # (or risc0-v3 <imageId>) locking + address
#    check the outputs against the amount you WILL fund (pinned.mjs cov.preflight: caps, standard outputs, 223-B
#    OP_RETURN cap, dust, self-payment, fee >= 1 sat/B at worst-case size). Do not fund yet.
# 2. prove: the proof depends only on the outputs and INSTANCE (not on the funding), so prove BEFORE funding; if
#    proving fails, nothing is locked
node example.mjs request <secretHex> statement.json request.json
cd guest/sp1/script && SP1_PROVER=cpu cargo run --release -- prove ../../../request.json ../../../proof.json
cd guest/risc0 && cargo run --release -p host -- prove ../../request.json ../../proof.json
# 3. fund the address ONCE with exactly 3 UTXOs totalling the amount preflight was run with; write utxos.json
# 4. spend: refuses a proof.json that names another program, a PV for another INSTANCE, and a proof that does not
#    verify for the statement derived from YOUR program id and the outputs; runs libauth verify() and prints the txid
node example.mjs spend sp1-v5 <programVKey> <INSTANCE> proof.json utxos.json tx.json
```

- Expected resources (unverified here): SP1's CPU Groth16 pipeline (core, compress, shrink, wrap, gnark) is
  memory-heavy. Run it niced on 4 threads and check that it fits in 24 GB before relying on it. RISC Zero's
  `ProverOpts::groth16()` on x86-64 Linux CPU needs docker (risc0-groth16 3.0.x runs the `risczero/risc0-groth16-prover` image; the rzup component is used only with the `cuda` feature).
- `pinned.mjs` checks the SP1 selector `a4594c59` (SP1 v5.0.0 circuits). The proof must also verify (noble pairing)
  for the statement derived from the pinned program id, INSTANCE and outputs, or the builder refuses it.
- `openPinned` refuses key `risc0` (Track 11's unreleased root `b1f64013…`) without `allowUnreleasedRisc0`, and key
  `test` without `allowTestKey`.
- **RISC Zero version pin.** The released risc0-zkvm 3.0.x proves under control root `a54dc85a…` (key `risc0-v3`,
  `fold-risc0.mjs`, sources in `upstream/SOURCES.md`). Track 11's `risc0` key pins risc0-ethereum main's `b1f64013…`
  (risc0 main @ fc0222ab, unreleased). A receipt for one root is rejected by a build for the other. A RISC Zero
  upgrade means a new covenant.
- The RISC Zero guest `include!`s `../../../../shared/pv.rs`. A docker (reproducible) guest build that mounts only
  the risc0 workspace would not see it; copy the file in for that case.

## Verify an SP1 proof in your covenant (library use)

```js
import {openPinned} from './pinned.mjs';
const cov = await openPinned('sp1-v5', {system: 'sp1', programVKey: '0x00…' /* your guest's vk.bytes32() */,
                                        instanceId: '…' /* 32 random bytes, one per deployment */});
cov.address;                                  // bchtest: by default; mainnet only after a real-key accept (see the status table)
const outputs = [{lockingBytecode: payoutLocking, valueSatoshis: 200000n}];
cov.preflight({outputs, utxoTotal: 240000n}); // BEFORE proving: caps, standard outputs, 223-B OP_RETURN cap, dust,
                                              // no self-payment, fee >= 1 sat/B
cov.publicValuesFor(outputs);                 // what your guest must commit_slice: PV bytes; prove now
// THEN fund cov.address ONCE with exactly 3 UTXOs totalling utxoTotal (the verifier is a 3-input transaction)
const {hex} = cov.buildSpend({proof: proofHex /* proof.bytes() */, outputs, utxos});  // broadcast hex
```

- **CashScript.** The verifier is generated by this repository's assembler (OP_DEFINE function tables, loops,
  3-input roles). It is not written in CashScript, and a CashScript contract cannot co-spend it: `GRAPH` admits
  exactly 3 inputs, all of this locking. The composition point is the outputs. Any output can be a CashScript
  contract's locking bytecode (e.g. its P2SH32), so the proof can hand value to a CashScript contract that holds the
  application state. Build the spend with `buildSpend` (CashScript's `TransactionBuilder` cannot produce these
  unlockings) and broadcast the hex with any provider, e.g. CashScript's `ElectrumNetworkProvider.sendRawTransaction`.
- Your guest must commit **exactly** the `pv.mjs` / `guest/shared/pv.rs` bytes, raw (`commit_slice`, not `commit`,
  which bincode-frames the value).
- Pin your own program. Never deploy with key `test`: its trapdoor is public, so anyone can mint proofs under it.

## Security notes (honest scope)

- **End-to-end security is capped by the zkVM.** It is the minimum of: BN254 pairing security (about 100–110 bits
  classical, not post-quantum); the trusted setups behind the SP1 and RISC Zero Groth16 keys; the inner STARKs; and
  the pinned program's own correctness. **RISC Zero:** succinct receipts are 97 bits *conjectured* and about
  **48 bits provable** in the Johnson-bound regime (EF soundcalc @ b325e30 `reports/risc0.md`; recomputed in Track 10
  G0 as 48.22). **SP1 v5:** unassessed. soundcalc's summary lists SP1 6.1.0 at 100 bits (unique-decoding regime), not
  v5. Any text that presents RISC Zero receipts should carry the 48-bit provable figure.
- The verifier carries bn-native-sound's open risks unchanged. The new code is `template.mjs` (about 30 lines of
  script generation in the hook), `pv.mjs`, `pinned.mjs`, `fold-risc0.mjs` and the guests. **None of it has been
  reviewed independently.** The tests are necessary evidence, not a proof.
- No real proof of the template statement exists yet. The accept path is shown with test-key proofs (exact statement)
  and with real proofs on the plain core. Real-key liveness is argued from Track 11.
- A proof does not choose which UTXOs it spends. Any second funding of an INSTANCE (a top-up, a stray deposit, change
  sent to its P2SH20 or bare-`R` alias) can be taken by replaying a used proof: the same outputs are paid again and any surplus
  goes to fees (see "What the statement does not bind"). Change back to the covenant's own P2SH32 locking is rejected
  on chain.

## Reproduce

```sh
# groth16_cashscript, this directory (node_modules: zk-verifier-bench's, with the libauth OP_DEFINE patch)
node fold-risc0.mjs                                   # risc0-v3.fixtures.json (noble checks, released control root)
node pinned-test.mjs test test.pinned.report.json     # ~26 s; also: sp1-v5, risc0, risc0-v3
node covenant-cost.mjs                                # template block bytes / op cost
node example.mjs test-proof sp1 pf.json               # prints the spend command (test key, --regtest)
node example.mjs spend test <printed programVKey> <printed INSTANCE> pf.json utxos.json --regtest   # builder, test key
# zk-verifier-bench research/node-check (BCHN):
G16=<this checkout> node export-pinned.mjs <data-dir> test   (and sp1-v5, risc0, risc0-v3);  run-t12.sh NAME 9 7 11
```
