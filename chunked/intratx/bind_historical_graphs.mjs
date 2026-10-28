// Freeze graph-rooted variants from the already-qualified positive packet.
// This module is data-only: it does not import a producer, compiler, builder,
// planner, prover, or negative-case runner.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  bigIntToVmNumber, decodeAuthenticationInstructions, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256,
} from '@bitauth/libauth';

const frameManifestUrl = new URL('./historical-frame-repairs.json', import.meta.url);
const frameManifestBytes = readFileSync(frameManifestUrl);
const frameManifest = JSON.parse(frameManifestBytes);
const CORRECTED_PACKET_SHA256 =
  'f88d2274794b0e38c5254187c04d97033080b7fa84fafbccd982f99e5b4f19b1';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = bytes => Buffer.from(bytes).toString('hex');
const bytes = value => Buffer.from(value, 'hex');
const pushNumber = value => Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(value))));
const locking = code => Buffer.from(encodeLockingBytecodeP2sh32(hash256(code)));

function decodeStep(step) {
  const unlocking = bytes(step.unlocking);
  const instructions = decodeAuthenticationInstructions(unlocking);
  assert(instructions.every(i => !('error' in i) &&
    (i.data !== undefined || i.opcode === 0 || i.opcode === 0x4f ||
      i.opcode >= 0x51 && i.opcode <= 0x60)), 'push-only archived unlocking required');
  const code = Buffer.from(instructions.at(-1)?.data ?? []);
  assert(code.length > 0, 'missing final redeem code');
  const codePush = Buffer.from(encodeDataPush(code));
  assert(unlocking.subarray(-codePush.length).equals(codePush), 'canonical final code push required');
  assert.equal(hex(locking(code)), step.locking, 'source corrected P2SH32 owner');
  return {code, prefix: unlocking.subarray(0, -codePush.length)};
}

function profileFor(id) {
  const profile = frameManifest.profiles.find(candidate => candidate.id === id);
  assert(profile, `unknown historical frame profile: ${id}`);
  assert.equal(profile.layout, 'intratx', 'grouped graph is outside this helper');
  return profile;
}

function sourceProfile(packet, id) {
  assert.equal(packet.schema, 'historical-frame-corrected-positive-set/v1');
  const profile = packet.profiles.find(candidate => candidate.id === id);
  assert(profile, `missing corrected positive profile: ${id}`);
  return profile;
}

function assertCommonProfile(profile, source) {
  assert.equal(source.layout, 'intratx');
  assert.equal(source.cases.length, profile.caseCount);
  assert.equal(source.originalFixtureSha256, profile.originalFixture.sha256);
  assert.equal(source.cases[0].steps.length, profile.programCount);
  assert.equal(profile.originalProgramSha256.length, profile.programCount);
  assert.equal(profile.repairedProgramSha256.length, profile.programCount);
  for (const run of source.cases) {
    assert.equal(run.steps.length, profile.programCount);
    run.steps.forEach((step, index) => {
      const decoded = decodeStep(step);
      assert.equal(sha256(decoded.code), profile.repairedProgramSha256[index],
        `corrected source program ${index}`);
    });
  }
}

function assertCrossCaseSourceIdentity(source) {
  const first = source.cases[0].steps.map(decodeStep);
  for (const run of source.cases.slice(1)) {
    run.steps.forEach((step, index) => {
      const current = decodeStep(step);
      assert(current.code.equals(first[index].code), `case code differs at input ${index}`);
      assert.equal(step.locking, source.cases[0].steps[index].locking,
        `case locking differs at input ${index}`);
    });
  }
  return first;
}

function rootIndexGuard() {
  // INPUTINDEX == 0; this makes the designated root-position premise explicit.
  return Buffer.from([0xc0, 0x00, 0x9d]);
}

function countGuard(count) {
  return Buffer.concat([Buffer.from([0xc3]), pushNumber(count), Buffer.from([0x9d])]);
}

function successorGuard(nextLocking) {
  // P2SH32 locking bytecode is 35 bytes and is embedded by a separate 0x23 push.
  assert.equal(nextLocking.length, 35);
  return Buffer.concat([Buffer.from([0xc0, 0x8b, 0xc7, 0x23]), nextLocking,
    Buffer.from([0x88])]);
}

function directInputPin(index, expectedLocking) {
  assert(index > 0);
  assert.equal(expectedLocking.length, 35);
  return Buffer.concat([pushNumber(index), Buffer.from([0xc7, 0x23]), expectedLocking,
    Buffer.from([0x88])]);
}

function buildCodes(profile, sourceSteps) {
  const oldCodes = sourceSteps.map(step => step.code);
  const oldLockings = sourceSteps.map(step => locking(step.code));
  const count = profile.programCount;
  const mode = profile.id === 'bch-groth16-historical-bn13-frame-corrected'
    ? 'root-absolute-pins' : 'successor-chain';
  const rootedCodes = Array.from({length: count});

  if (mode === 'root-absolute-pins') {
    // Keep inputs 1..12 and the terminal byte-identical. Root input 0 pins
    // every absolute successor locking owner, avoiding BN13's existing
    // SHA256(input-3-locking) dependency cycle.
    const pins = oldLockings.slice(1).map((owner, offset) => directInputPin(offset + 1, owner));
    rootedCodes[0] = Buffer.concat([rootIndexGuard(), countGuard(count), ...pins, oldCodes[0]]);
    for (let i = 1; i < count; i++) rootedCodes[i] = oldCodes[i];
  } else {
    let nextLocking = null;
    for (let i = count - 1; i >= 0; i--) {
      const binding = i === count - 1 ? Buffer.alloc(0) : successorGuard(nextLocking);
      const root = i === 0 ? Buffer.concat([rootIndexGuard(), countGuard(count)]) : Buffer.alloc(0);
      rootedCodes[i] = Buffer.concat([root, binding, oldCodes[i]]);
      nextLocking = locking(rootedCodes[i]);
    }
  }
  return {mode, oldCodes, oldLockings, rootedCodes,
    rootedLockings: rootedCodes.map(code => locking(code))};
}

function qualifiedProfile(packet, profileId) {
  const profile = profileFor(profileId);
  const source = sourceProfile(packet, profileId);
  assertCommonProfile(profile, source);
  const sourceSteps = assertCrossCaseSourceIdentity(source);
  const graph = buildCodes(profile, sourceSteps);
  const rootedCodeSha256 = graph.rootedCodes.map(sha256);
  const rootedLockingHex = graph.rootedLockings.map(hex);

  const cases = source.cases.map(run => ({
    name: run.name,
    steps: run.steps.map((step, index) => {
      const decoded = decodeStep(step);
      const unlocking = Buffer.concat([decoded.prefix, encodeDataPush(graph.rootedCodes[index])]);
      assert(unlocking.subarray(0, decoded.prefix.length).equals(decoded.prefix));
      assert.equal(hex(locking(graph.rootedCodes[index])), rootedLockingHex[index]);
      return {label: step.label, locking: rootedLockingHex[index], unlocking: hex(unlocking)};
    }),
  }));

  const rootPrefix = graph.mode === 'successor-chain'
    ? Buffer.concat([rootIndexGuard(), countGuard(profile.programCount),
      successorGuard(graph.rootedLockings[1])])
    : Buffer.concat([rootIndexGuard(), countGuard(profile.programCount),
      ...graph.oldLockings.slice(1).map((owner, offset) => directInputPin(offset + 1, owner))]);
  assert(graph.rootedCodes[0].subarray(0, rootPrefix.length).equals(rootPrefix));
  if (graph.mode === 'root-absolute-pins') {
    for (let i = 1; i < profile.programCount; i++) {
      assert(graph.rootedCodes[i].equals(graph.oldCodes[i]), `BN13 input ${i} must remain unchanged`);
    }
  } else {
    assert(graph.rootedCodes[profile.programCount - 1].equals(graph.oldCodes[profile.programCount - 1]),
      'successor-chain terminal must remain unchanged');
  }

  return {
    schema: 'historical-rooted-positive-profile/v1',
    id: `${profile.id}-rooted`, sourceProfileId: profile.id,
    originalFixtureSha256: profile.originalFixture.sha256,
    layout: profile.layout, curve: profile.curve, declaredVm: profile.declaredVm,
    programCount: profile.programCount, caseCount: profile.caseCount,
    standardDensityHoldsMayOccur: profile.standardDensityHoldsMayOccur === true,
    graphBinding: {
      mode: graph.mode, rootIndex: 0, inputCount: profile.programCount,
      rootIndexGuardHex: hex(rootIndexGuard()), countGuardHex: hex(countGuard(profile.programCount)),
      successorGuardPrefixHex: graph.mode === 'successor-chain' ? 'c08bc723' : null,
      absolutePins: graph.mode === 'root-absolute-pins' ? graph.rootedLockings.slice(1).map((owner, i) => ({
        input: i + 1, locking: hex(graph.oldLockings[i + 1]),
      })) : [],
      rootPremise: 'The designated root UTXO is spent at transaction input 0.',
    },
    sourceCorrectedProgramSha256: graph.oldCodes.map(sha256),
    rootedProgramSha256: rootedCodeSha256,
    rootedLockingHex,
    cases,
    qualification: {
      claim: 'The exact ordered intratx graph is bound by root position/count and fixed successor locking owners; the original arithmetic body and positive payload prefixes are preserved.',
      theoremTransfer: 'The prior finite-domain arithmetic theorem transfers because each new gate is stack-neutral and the original body is byte-identical after the gate prefix.',
      preservedPayload: 'Proof/public/state/table/padding unlocking instructions are byte-identical; only redeem code and coherent P2SH32 locking owners change.',
      externalPremises: [
        'The designated root UTXO is the transaction input 0 spend.',
        'The five successor-chain profiles use the reverse-constructed fixed owner chain.',
        'The absolute-pin BN13 root preserves inputs 1..12 and pins their exact locking owners.',
        'The declared VM implements the reviewed introspection opcodes with the pinned semantics.',
      ],
      claimsNotEstablished: ['exact historical outpoint identity', 'whole-transaction admission', 'relay/mainnet admission', 'neutral-domain completeness', 'grouped token ancestry'],
    },
  };
}

export function bindHistoricalProfile(correctedPacketBytes, profileId) {
  assert.equal(sha256(correctedPacketBytes), CORRECTED_PACKET_SHA256,
    'exact frozen corrected-positive packet required');
  const packet = JSON.parse(correctedPacketBytes);
  return qualifiedProfile(packet, profileId);
}

export function bindHistoricalProfiles(correctedPacketBytes) {
  assert.equal(sha256(correctedPacketBytes), CORRECTED_PACKET_SHA256,
    'exact frozen corrected-positive packet required');
  const packet = JSON.parse(correctedPacketBytes);
  const ids = [
    'bch-groth16-historical-bn27-intratx-frame-corrected',
    'bch-groth16-historical-bls26-frame-corrected',
    'bch-groth16-historical-bls24-frame-corrected',
    'bch-groth16-historical-bn13-frame-corrected',
    'bch-groth16-historical-bls34-frame-corrected',
    'bch-groth16-historical-bn-large4-frame-corrected',
  ];
  return {schema: 'historical-rooted-positive-set/v1', correctedPacketSha256: sha256(correctedPacketBytes),
    profiles: ids.map(id => qualifiedProfile(packet, id))};
}

export function rootedManifest(rootedSet, correctedPacketBytes) {
  return {
    schema: 'historical-rooted-graph-manifest/v1',
    sourceHelper: 'chunked/intratx/bind_historical_graphs.mjs',
    sourceHelperSha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
    sourceFrameManifest: 'chunked/intratx/historical-frame-repairs.json',
    sourceFrameManifestSha256: sha256(frameManifestBytes),
    sourceRootedManifest: 'chunked/intratx/historical-rooted-graphs.json',
    correctedPositivePacketSha256: sha256(correctedPacketBytes),
    profiles: rootedSet.profiles.map(profile => ({
      id: profile.id, sourceProfileId: profile.sourceProfileId, curve: profile.curve,
      declaredVm: profile.declaredVm, programCount: profile.programCount,
      caseCount: profile.caseCount, originalFixtureSha256: profile.originalFixtureSha256,
      standardDensityHoldsMayOccur: profile.standardDensityHoldsMayOccur,
      graphBinding: profile.graphBinding, sourceCorrectedProgramSha256: profile.sourceCorrectedProgramSha256,
      rootedProgramSha256: profile.rootedProgramSha256, rootedLockingHex: profile.rootedLockingHex,
      qualification: profile.qualification,
    })),
    scope: 'Existing positive packet only; no proof generation, negative cases, compiler/producer invocation, grouped graph, or cybersecurity testing.',
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [input, profileOrAll, output, manifestOutput, ...extra] = process.argv.slice(2);
  assert(input && profileOrAll && output && extra.length === 0,
    'usage: node bind_historical_graphs.mjs corrected-positives.json profile-id rooted-profile.json\n' +
    '   or: node bind_historical_graphs.mjs corrected-positives.json --all rooted-positives.json rooted-manifest.json');
  const packetBytes = readFileSync(input);
  assert.notEqual(resolve(input), resolve(output));
  if (profileOrAll === '--all') {
    assert(manifestOutput, 'all-profile mode requires a manifest output');
    assert.notEqual(resolve(output), resolve(manifestOutput));
    const rootedSet = bindHistoricalProfiles(packetBytes);
    writeFileSync(output, JSON.stringify(rootedSet, null, 2) + '\n', {flag: 'wx'});
    writeFileSync(manifestOutput, JSON.stringify(rootedManifest(rootedSet, packetBytes), null, 2) + '\n', {flag: 'wx'});
    console.log(JSON.stringify({profiles: rootedSet.profiles.length, output, manifestOutput}));
  } else {
    const profile = bindHistoricalProfile(packetBytes, profileOrAll);
    writeFileSync(output, JSON.stringify(profile, null, 2) + '\n', {flag: 'wx'});
    console.log(JSON.stringify({id: profile.id, cases: profile.cases.length, output}));
  }
}
