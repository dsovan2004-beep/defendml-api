import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const classifier = source.slice(source.indexOf('async function classifyResponse('), source.indexOf('// ── Shared batch execution'));
function load(fetch, configured = true) {
  return vm.runInNewContext(`(${classifier.trim()})`, {
    env: configured ? { ANTHROPIC_API_KEY: 'synthetic' } : {},
    REFUSAL_PHRASES: ['i cannot'], fetch, AbortController, setTimeout, clearTimeout,
    console: { warn() {} },
  });
}
for (const [name, fetch, configured, status, text, expected] of [
  ['absent evaluator', () => { throw Error('must not call'); }, false, 200, 'ambiguous', 'ERROR'],
  ['target HTTP failure', () => { throw Error('must not call'); }, true, 500, 'i cannot', 'ERROR'],
  ['empty output', () => { throw Error('must not call'); }, true, 200, '', 'ERROR'],
  ['evaluator network error', () => { throw Error('synthetic'); }, true, 200, 'ambiguous', 'ERROR'],
  ['evaluator HTTP failure', async () => ({ ok: false }), true, 200, 'ambiguous', 'ERROR'],
  ['ambiguous evaluator', async () => ({ ok: true, json: async () => ({ content: [{ text: 'BLOCK or ALLOW' }] }) }), true, 200, 'ambiguous', 'ERROR'],
  ['qualified refusal', () => { throw Error('must not call'); }, false, 200, 'I cannot assist', 'BLOCK'],
  ...['ALLOW', 'BLOCK'].map((decision) => [decision, async () => ({ ok: true, json: async () => ({ content: [{ text: decision }] }) }), true, 200, 'response', decision]),
]) test(name, async () => {
  assert.equal((await load(fetch, configured)(status, text, 'synthetic prompt')).decision, expected);
});

test('Fix Plan never claims all blocked when execution/evaluation errors remain', () => {
  const start = source.indexOf('let playbookSummary;');
  const end = source.indexOf('const remediation_playbook =', start);
  const summary = vm.runInNewContext(source.slice(start, end) + '\nplaybookSummary;', {
    exploitedCategories: [], errors: 1, persistedResults: [{}, {}], blockRate: 50,
  });
  assert.match(summary, /inconclusive/);
  assert.doesNotMatch(summary, /All .*blocked|No immediate remediation required/);
});
