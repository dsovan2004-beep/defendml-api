import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { isQualifiedMemory, qualifiesMemoryOutcome, MEMORY_QUALIFICATION_VERSION } from '../memory-qualification.mjs';

test('historical memory without execution provenance is quarantined', () => {
  const historical = Array.from({ length: 54 }, () => ({ response_patterns: {}, failed_prompts: ['synthetic'], successful_prompts: [] }));
  const before = JSON.stringify(historical);
  assert.equal(historical.filter(isQualifiedMemory).length, 0);
  assert.equal(JSON.stringify(historical), before);
});
test('future memory requires successful qualified attack execution', () => {
  const row = { decision: 'BLOCK', detection_method: 'keyword', status_code: 200, response_snippet: 'Synthetic refusal' };
  assert.equal(qualifiesMemoryOutcome(row), true);
  for (const patch of [{ decision: 'ERROR' }, { detection_method: 'multi_turn_context' }, { detection_method: 'llm_fallback_block' }, { status_code: 403 }, { status_code: 0 }, { response_snippet: '  ' }, { status_code: null }]) {
    assert.equal(qualifiesMemoryOutcome({ ...row, ...patch }), false);
  }
  for (const decision of ['ALLOW', 'FLAG']) assert.equal(qualifiesMemoryOutcome({ ...row, decision, detection_method: 'llm_judge' }), true);
});
test('qualified memory needs versioned source linkage and positive evidence count', () => {
  const qualification = { version: MEMORY_QUALIFICATION_VERSION, state: 'QUALIFIED', qualified_outcomes: 1, source_report_ids: ['synthetic-report'] };
  assert.equal(isQualifiedMemory({ response_patterns: { qualification } }), true);
  for (const patch of [{ state: 'UNKNOWN' }, { version: 'old' }, { qualified_outcomes: 0 }, { source_report_ids: [] }, { source_report_ids: [null] }]) {
    assert.equal(isQualifiedMemory({ response_patterns: { qualification: { ...qualification, ...patch } } }), false);
  }
});
test('consumer and writer do not launder existing unqualified rows', () => {
  const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
  assert.match(source, /swarmMemory.filter\(isQualifiedMemory\)/);
  assert.match(source, /persistedResults.filter\(qualifiesMemoryOutcome\)/);
  assert.match(source, /if \(existing && !isQualifiedMemory\(existing\)\) continue/);
  assert.match(source, /memory_history_incomplete/);
  assert.match(source, /memory_history_conflicting/);
});
