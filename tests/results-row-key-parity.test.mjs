// Every persisted red_team_results row must carry the SAME set of top-level keys.
// The bulk insert uses PostgREST, which rejects a mixed-key array with PGRST102
// "All object keys must match" — failing the ENTIRE batch and losing all results
// while the report still shows aggregates. Phase 1 stage 2 added case_observation
// to the executeBatch row but not the multi-turn row; no multi-turn scan ran
// until 2026-09-19, so it was silent. This pins key parity to the real source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');

function slice(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `markers present: ${start}`);
  return source.slice(from, to + end.length);
}

// Direct-child keys = identifier:-lines at the shallowest indentation in the block.
// Nested object/array contents sit deeper and are excluded; template-literal lines
// (`Step 1: …`) start with a backtick, not an identifier, so they never match.
function topLevelKeys(block) {
  const keyLines = [];
  for (const line of block.split('\n')) {
    const m = line.match(/^(\s+)([A-Za-z_]\w*)\s*[:,]/); // key: value  OR  shorthand key,
    if (m) keyLines.push([m[1].length, m[2]]);
  }
  const minIndent = Math.min(...keyLines.map(([i]) => i));
  return [...new Set(keyLines.filter(([i]) => i === minIndent).map(([, k]) => k))].sort();
}

const executeBatchRow = slice('const isAllow = decision === "ALLOW";', 'latency_ms: Date.now() - testStart,');
const multiTurnRow = slice('agentResults.push({', 'latency_ms: 0,');

const httpKeys = topLevelKeys(executeBatchRow);
const mtKeys = topLevelKeys(multiTurnRow);

test('executeBatch and multi-turn result rows share an identical key set', () => {
  assert.deepEqual(mtKeys, httpKeys,
    `result-row key sets differ — bulk insert would fail PGRST102.\n` +
    `executeBatch: ${httpKeys.join(',')}\nmulti-turn:  ${mtKeys.join(',')}`);
});

test('both result rows include case_observation', () => {
  assert.ok(httpKeys.includes('case_observation'), 'executeBatch row missing case_observation');
  assert.ok(mtKeys.includes('case_observation'), 'multi-turn row missing case_observation');
});

test('the canonical key set is exactly the persisted columns', () => {
  assert.deepEqual(httpKeys, [
    'case_observation', 'category', 'decision', 'detection_method', 'latency_ms',
    'layer_stopped', 'prompt_text', 'report_uuid', 'reproduction_steps',
    'response_snippet', 'response_text', 'status_code', 'test_id',
  ]);
});
