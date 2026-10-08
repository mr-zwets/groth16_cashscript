import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { produceTransaction } from './transaction.mjs';

assert.equal(process.argv.length, 3, 'usage: node export.mjs output.json');
const fixtures = JSON.parse(readFileSync(new URL('public-fixtures.json', import.meta.url)));
const generated = fixtures.fixtures.map(({ fixture, proof, publicInputs }) => ({
  fixture,
  steps: produceTransaction(fixtures.vk, proof, publicInputs),
}));
writeFileSync(process.argv[2], JSON.stringify(generated, null, 2) + '\n');
