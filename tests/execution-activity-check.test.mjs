// R006-1 (Codex CLI review, 2026-10-07): deactivating a Target is the documented
// containment action, so a job queued BEFORE deactivation must not execute.
// worker.js is too large to drive end to end here; like the authorization-boundary
// test, this locks the source contract: the execute path refuses an inactive
// Target before any interface runner, and the queue consumer records it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const worker = await readFile(new URL('../worker.js', import.meta.url), 'utf8');

test('execute refuses an inactive Target before any interface runner runs', () => {
  const execStart = worker.indexOf('RED TEAM EXECUTE');
  assert.ok(execStart > 0, 'execute section present');
  const exec = worker.slice(execStart);
  const check = exec.indexOf('if (target.is_active !== true) {');
  assert.ok(check > 0, 'activity check present in the execute path');
  assert.match(exec.slice(check, check + 300), /error: "target_inactive" \}, 409/);
  for (const runner of ['runToolActionCallbackScan(', 'runMemorySessionScan(', 'runToolActionScan(']) {
    const at = exec.indexOf(runner);
    assert.ok(at > check, `${runner} runs only after the activity check`);
  }
});

test('the queue consumer records a refused inactive Target as TARGET_INACTIVE', () => {
  assert.match(worker, /response\.status === 409 \? "TARGET_INACTIVE"/);
});
