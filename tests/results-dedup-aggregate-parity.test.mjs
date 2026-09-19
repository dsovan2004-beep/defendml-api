// The unique (report_uuid, test_id) constraint means only one row per test_id
// persists; the swarm can emit the same test_id from multiple agents. If the
// report aggregates are tallied over the pre-dedup array while the DB keeps the
// deduped rows, stored counts over-count and the qualifier flags
// AGGREGATE_MISMATCH → UNKNOWN. This pins: dedup keeps one row per test_id (last
// wins) and the tally is computed over the deduped array, so aggregates match
// exactly what is retained. Logic extracted from the real worker.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
function between(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `markers present: ${start}`);
  return source.slice(from, to);
}

// Real dedup: from `const byTestId` to the persistedResults assignment.
const dedupSrc = between('const byTestId = new Map();', 'const persistedResults = [...byTestId.values()];')
  + 'const persistedResults = [...byTestId.values()];';
const dedup = vm.runInNewContext(`(sanitizedResults) => { ${dedupSrc} return persistedResults; }`, {});

// Real tally: from the counter declaration to the block-rate line.
const tallySrc = between('let blocked = 0, allowed = 0, flagged = 0, errors = 0, contextTurns = 0;', '// ── Build attack_intelligence');
const tally = vm.runInNewContext(
  `(persistedResults) => { ${tallySrc} return { blocked, allowed, flagged, errors, contextTurns, decidedOutcomes, total: persistedResults.length }; }`, {});

const row = (test_id, decision) => ({ test_id, decision, detection_method: decision === 'CONTEXT' ? 'multi_turn_context' : 'keyword', status_code: 200, response_snippet: 'x' });

test('dedup keeps one row per test_id, last occurrence wins', () => {
  const sanitized = [row('1', 'BLOCK'), row('1', 'ALLOW'), row('2', 'BLOCK'), row('mt-01-t1', 'CONTEXT')];
  const persisted = dedup(sanitized);
  assert.equal(persisted.length, 3, 'three distinct test_ids');
  const one = persisted.find((r) => r.test_id === '1');
  assert.equal(one.decision, 'ALLOW', 'last occurrence of a duplicate test_id wins (matches upsert)');
});

test('the tally over deduped rows equals the retained row count', () => {
  const sanitized = [row('1', 'BLOCK'), row('1', 'BLOCK'), row('2', 'ALLOW'), row('3', 'BLOCK'), row('mt-1', 'CONTEXT'), row('mt-1', 'CONTEXT')];
  const persisted = dedup(sanitized);
  const t = tally(persisted);
  // 4 distinct: 1(BLOCK), 2(ALLOW), 3(BLOCK), mt-1(CONTEXT)
  assert.equal(persisted.length, 4);
  assert.equal(t.blocked + t.allowed + t.flagged + t.errors + t.contextTurns, persisted.length,
    'every retained row is counted exactly once — no over-count, no drift');
  assert.equal(t.blocked, 2);
  assert.equal(t.allowed, 1);
  assert.equal(t.contextTurns, 1);
});

test('with no duplicates dedup is a no-op', () => {
  const sanitized = [row('a', 'BLOCK'), row('b', 'ALLOW'), row('c', 'ERROR')];
  assert.equal(dedup(sanitized).length, 3);
});
